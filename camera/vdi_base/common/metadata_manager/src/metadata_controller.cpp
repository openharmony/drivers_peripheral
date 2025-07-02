/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "metadata_controller.h"
#include "camera_dump.h"

namespace OHOS {
namespace Camera {
const std::vector<int32_t> DATA_BASE = {
    OHOS_CAMERA_STREAM_ID,
    OHOS_SENSOR_COLOR_CORRECTION_GAINS,
    OHOS_SENSOR_EXPOSURE_TIME,
    OHOS_CONTROL_EXPOSURE_MODE,
    OHOS_CONTROL_AE_EXPOSURE_COMPENSATION,
    OHOS_CONTROL_AE_LOCK,
    OHOS_CONTROL_FOCUS_MODE,
    OHOS_CONTROL_METER_MODE,
    OHOS_CONTROL_FLASH_MODE,
    OHOS_CONTROL_FPS_RANGES,
    OHOS_CONTROL_AWB_MODE,
    OHOS_CONTROL_AWB_LOCK,
    OHOS_CONTROL_AF_REGIONS,
    OHOS_CONTROL_METER_POINT,
    OHOS_CONTROL_VIDEO_STABILIZATION_MODE,
    OHOS_CONTROL_FOCUS_STATE,
    OHOS_CONTROL_EXPOSURE_STATE,
};

MetadataController::MetadataController() {}

MetadataController::~MetadataController()
{
    {
        std::unique_lock<std::mutex> lock(queueLock_);
        if (isRunning_.load()) {
            isRunning_.store(false);
        }
        cv_.notify_all();
    }

    StopThread();
}

MetadataController &MetadataController::GetInstance()
{
    static MetadataController controller;
    return controller;
}

void MetadataController::SetUpdateSettingCallback(const MetaDataCb &cb)
{
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    if (!isInit_) {
        CAMERA_LOGE("already set update setting callback.");
        return;
    }
    updateSettingFunc_ = cb;
}

void MetadataController::UnSetUpdateSettingCallback()
{
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    if (!isInit_) {
        CAMERA_LOGE("already set update setting callback.");
        return;
    }
    updateSettingFunc_ = nullptr;
}

void MetadataController::AddNodeCallback(const MetaDataCb &cb)
{
    std::unique_lock<std::mutex> lock(queueLock_);
    if (cb != nullptr) {
        nodeFunc_.push_back(cb);
    }
}

void MetadataController::ClearNodeCallback()
{
    if (nodeFunc_.empty()) {
        CAMERA_LOGE("nodeFunc_ empty");
        return;
    }
    std::unique_lock<std::mutex> lock(queueLock_);
    nodeFunc_.clear();
}

void MetadataController::SetPeerFrameFlag(bool flag)
{
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    peerFrame_ = flag;
}

void MetadataController::AddEnabledAbility(const std::vector<int32_t> &abilityMetaDataTag)
{
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    std::vector<int32_t>().swap(abilityMetaData_);
    for (auto it = abilityMetaDataTag.cbegin(); it != abilityMetaDataTag.cend(); it++) {
        switch (*it) {
            case OHOS_CAMERA_STREAM_ID:                 // fallthrough
            case OHOS_SENSOR_COLOR_CORRECTION_GAINS:    // fallthrough
            case OHOS_SENSOR_EXPOSURE_TIME:             // fallthrough
            case OHOS_CONTROL_EXPOSURE_MODE:            // fallthrough
            case OHOS_CONTROL_AE_EXPOSURE_COMPENSATION: // fallthrough
            case OHOS_CONTROL_AE_LOCK:                  // fallthrough
            case OHOS_CONTROL_FOCUS_MODE:               // fallthrough
            case OHOS_CONTROL_METER_MODE:               // fallthrough
            case OHOS_CONTROL_FLASH_MODE:               // fallthrough
            case OHOS_CONTROL_FPS_RANGES:               // fallthrough
            case OHOS_CONTROL_AWB_MODE:                 // fallthrough
            case OHOS_CONTROL_AWB_LOCK:                 // fallthrough
            case OHOS_CONTROL_AF_REGIONS:               // fallthrough
            case OHOS_CONTROL_METER_POINT:              // fallthrough
            case OHOS_CONTROL_VIDEO_STABILIZATION_MODE: // fallthrough
            case OHOS_CONTROL_FOCUS_STATE:              // fallthrough
            case OHOS_CONTROL_EXPOSURE_STATE: {
                abilityMetaData_.push_back((*it));
                break;
            }
            default:
                break;
        }
    }
}

int32_t MetadataController::GetEnabledAbility(std::vector<int32_t> &results)
{
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    results = abilityMetaData_;
    return RC_OK;
}

int32_t MetadataController::DelEnabledAbility(const std::vector<int32_t> &results)
{
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    for (auto &metaType : results) {
        auto itr = std::find(abilityMetaData_.begin(), abilityMetaData_.end(), metaType);
        if (itr != abilityMetaData_.end()) {
            abilityMetaData_.erase(itr);
        } else {
            CAMERA_LOGW("enabled result is not found. [metaType = %{public}d]", metaType);
            return RC_ERROR;
        }
    }
    return RC_OK;
}

static bool UpdateMuteMode(const std::shared_ptr<CameraMetadata>& metadata, bool oldMode)
{
    bool newMode = oldMode;
    common_metadata_header_t *data = metadata->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_MUTE_MODE, &entry);
    if (ret == 0) {
        if (entry.count == 1) {
            newMode = (entry.data.u8[0] > 0 ? true : false);
            CAMERA_LOGI("update mute mode, %{public}d -> %{public}d", oldMode, newMode);
        } else {
            CAMERA_LOGE("OHOS_CONTROL_MUTE_MODE tag, size error %{public}d", entry.count);
        }
    }
    return newMode;
}

bool MetadataController::IsMute()
{
    return isMute_;
}

bool MetadataController::UpdateSettingsConfig(const std::shared_ptr<CameraMetadata> &meta)
{
    bool result = false;
    isMute_ = UpdateMuteMode(meta, isMute_);
    int32_t streamId = GetStreamId(meta);
    if (streamId < 0) {
        CAMERA_LOGE("streamId is invalid %{public}d", streamId);
        return false;
    }
    result = FilterUpdateKeys(streamId, meta);
    if (!result) {
        CAMERA_LOGE("filter update keys fail and streamId = %{public}d", streamId);
        return false;
    }
    return DealMetadata(streamId, meta);
}

void MetadataController::GetSettingsConfig(std::shared_ptr<CameraMetadata> &meta)
{
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    metaDataConfig_->GetMetadata(DEVICE_STREAM_ID, meta);
}

int32_t MetadataController::GetStreamId(const std::shared_ptr<CameraMetadata> &meta)
{
    common_metadata_header_t *data = meta->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is nullptr");
        return RC_ERROR;
    }
    camera_metadata_item_t entry;
    int32_t streamId = -1;
    int rc = FindCameraMetadataItem(data, OHOS_CAMERA_STREAM_ID, &entry);
    if (rc == 0) {
        streamId = *entry.data.i32;
    }
    return streamId;
}

bool MetadataController::FilterUpdateKeys(int32_t streamId, const std::shared_ptr<CameraMetadata> &meta)
{
    common_metadata_header_t *data = meta->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is nullptr");
        return false;
    }

    std::vector<int32_t> metaKeys;
    for (auto &metaKey : DATA_BASE) {
        camera_metadata_item_t entry;
        int rc = FindCameraMetadataItem(data, metaKey, &entry);
        if (rc != 0) {
            continue;
        }
        metaKeys.push_back(metaKey);
    }

    if (metaKeys.size() == 0) {
        return false;
    }
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    updateMetaDataKeys_[streamId] = metaKeys;
    return true;
}

bool MetadataController::DealMetadata(int32_t streamId, const std::shared_ptr<CameraMetadata> &meta)
{
    bool result = false;
    if (firstNotifyNodes_.count(streamId) == 0 && streamId != DEVICE_STREAM_ID) {
        {
            std::unique_lock<std::mutex> lock(dataConfigLock_);
            changeDataKeys_[streamId] = updateMetaDataKeys_[streamId];
            result = metaDataConfig_->UpdateSettingsConfig(streamId, true, updateMetaDataKeys_[streamId], meta);
            if (!result) {
                CAMERA_LOGE("set metadata config fail and streamId = %{public}d", streamId);
                return false;
            }
        }
        firstNotifyNodes_.insert(streamId);
        {
            std::unique_lock<std::mutex> lock(queueLock_);
            queue_.push(meta);
            cv_.notify_all();
        }
        return true;
    }
    std::shared_ptr<CameraMetadata> metaTemp = nullptr;
    {
        std::unique_lock<std::mutex> lock(dataConfigLock_);
        if (!metaDataConfig_->GetMetadata(streamId, metaTemp)) {
            CAMERA_LOGE("get metadata fail and streamId = %{public}d", streamId);
            return false;
        }
    }

    std::shared_ptr<CameraMetadata> changeMetadata = std::make_shared<CameraMetadata>(ENTRY_CAPACITY, DATA_CAPACITY);
    result = CompareMetadata(streamId, metaTemp, meta, changeMetadata);
    if (!result) {
        CAMERA_LOGE("compare metadata fail and streamId = %{public}d", streamId);
        return false;
    }
    std::unique_lock<std::mutex> lock(queueLock_);
    queue_.push(changeMetadata);

    CameraDumper& dumper = CameraDumper::GetInstance();
    dumper.DumpMetadata("MetadataController", ENABLE_METADATA, changeMetadata);

    cv_.notify_all();
    return true;
}

bool MetadataController::CompareMetadata(int32_t streamId, const std::shared_ptr<CameraMetadata> &oldMeta,
    const std::shared_ptr<CameraMetadata> &newMeta, std::shared_ptr<CameraMetadata> &outMetadata)
{
    std::vector<int32_t> updateKeys;
    std::vector<int32_t> newKeys;
    common_metadata_header_t *metadataOld = oldMeta->get();
    common_metadata_header_t *metadataNew = newMeta->get();
    if (metadataOld == nullptr || metadataNew == nullptr) {
        CAMERA_LOGE("get metadata failed.");
        return false;
    }
    bool result = false;
    for (auto &metaType : updateMetaDataKeys_[streamId]) {
        camera_metadata_item_t baseEntry;
        int ret = FindCameraMetadataItem(metadataOld, metaType, &baseEntry);
        if (ret != 0) {
            CAMERA_LOGE("metadata base not found tag.[metaType = %{public}d]", metaType);
            newKeys.push_back(metaType);
            continue;
        }
        camera_metadata_item_t newEntry;
        ret = FindCameraMetadataItem(metadataNew, metaType, &newEntry);
        if (ret != 0) {
            CAMERA_LOGE("metadata result not found tag.[metaType = %{public}d]", metaType);
            continue;
        }
        bool isChange = IsChangeTagData(metaType, baseEntry, newEntry);
        if (isChange) {
            updateKeys.push_back(OHOS_CAMERA_STREAM_ID);
            updateKeys.push_back(metaType);
            result = UpdateNewTagData(updateKeys, newMeta, outMetadata);
            if (!result) {
                CAMERA_LOGE("compare update change meta failed.");
                return false;
            }
        }
    }

    if (updateKeys.size() == 0 && newKeys.size() == 0) {
        CAMERA_LOGW("ignore meta data");
        return false;
    }
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    if (newKeys.size() > 0) {
        newKeys.push_back(OHOS_CAMERA_STREAM_ID);
    }

    if (updateKeys.size() > 0) {
        updateKeys.push_back(OHOS_CAMERA_STREAM_ID);
    }
    return UpdateChangeMetadata(streamId, updateKeys, newKeys, newMeta, outMetadata);
}

bool MetadataController::UpdateChangeMetadata(int32_t streamId, const std::vector<int32_t> &updateKeys,
    const std::vector<int32_t> &newKeys, const std::shared_ptr<CameraMetadata> &newMeta,
    std::shared_ptr<CameraMetadata> &outMetadata)
{
    bool result = false;
    if (updateKeys.size() == 0 && newKeys.size() > 1) {
        changeDataKeys_[streamId] = newKeys;
        result = metaDataConfig_->UpdateSettingsConfig(streamId, true, newKeys, newMeta);
        if (!result) {
            CAMERA_LOGE("set meta config new keys failed.");
            return false;
        }
        result = UpdateNewTagData(newKeys, newMeta, outMetadata);
    } else {
        changeDataKeys_[streamId] = updateKeys;
        if (newKeys.size() > 1) {
            result = UpdateNewTagData(newKeys, newMeta, outMetadata);
            if (!result) {
                CAMERA_LOGE("update keys metadata failed.");
                return false;
            }
            changeDataKeys_[streamId].insert(changeDataKeys_[streamId].end(), newKeys.begin(), newKeys.end());
            result = metaDataConfig_->UpdateSettingsConfig(streamId, true, newKeys, newMeta);
            if (!result) {
                CAMERA_LOGE("set metadta config keys failed.");
                return false;
            }
        }
        result = metaDataConfig_->UpdateSettingsConfig(streamId, false, updateKeys, newMeta);
    }
    if (!result) {
        CAMERA_LOGE("update change metadata failed.");
        return false;
    }
    return true;
}

bool MetadataController::IsChangeTagData(
    int32_t key, const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry)
{
    bool result = false;
    switch (key) {
        case OHOS_CONTROL_AWB_MODE:       // fallthrough
        case OHOS_CONTROL_AWB_LOCK:       // fallthrough
        case OHOS_CONTROL_FOCUS_MODE:     // fallthrough
        case OHOS_CONTROL_FOCUS_STATE:    // fallthrough
        case OHOS_CONTROL_EXPOSURE_MODE:  // fallthrough
        case OHOS_CONTROL_EXPOSURE_STATE: // fallthrough
        case OHOS_CONTROL_AE_LOCK:        // fallthrough
        case OHOS_CONTROL_FLASH_MODE:     // fallthrough
        case OHOS_CONTROL_METER_MODE:     // fallthrough
        case OHOS_CONTROL_VIDEO_STABILIZATION_MODE: {
            result = IsChangeU8Metadata(baseEntry, newEntry);
            break;
        }
        case OHOS_CONTROL_AE_EXPOSURE_COMPENSATION: {
            result = IsChangeI32Metadata(baseEntry, newEntry);
            break;
        }
        case OHOS_SENSOR_EXPOSURE_TIME: {
            result = IsChangeI64Metadata(baseEntry, newEntry);
            break;
        }
        case OHOS_SENSOR_COLOR_CORRECTION_GAINS: {
            result = IsChangeFloatMetadata(baseEntry, newEntry);
            break;
        }
        case OHOS_CONTROL_FPS_RANGES: // fallthrough
        case OHOS_CONTROL_AF_REGIONS: // fallthrough
        case OHOS_CONTROL_METER_POINT: {
            result = IsChangeI32ArrayMetadata(baseEntry, newEntry);
            break;
        }
        default: {
            CAMERA_LOGW("invalid key %{public}d", key);
            break;
        }
    }
    return result;
}

bool MetadataController::IsChangeU8Metadata(
    const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry)
{
    if (*(baseEntry.data.u8) == *(newEntry.data.u8)) {
        return false;
    }
    return true;
}

bool MetadataController::IsChangeI32Metadata(
    const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry)
{
    if (*(baseEntry.data.i32) == *(newEntry.data.i32)) {
        return false;
    }
    return true;
}

bool MetadataController::IsChangeI64Metadata(
    const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry)
{
    if (*(baseEntry.data.i64) == *(newEntry.data.i64)) {
        return false;
    }
    return true;
}

bool MetadataController::IsChangeFloatMetadata(
    const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry)
{
    std::string baseValue = std::to_string(*(baseEntry.data.f));
    std::string newValue = std::to_string(*(newEntry.data.f));
    if (strcmp(baseValue.c_str(), newValue.c_str()) == 0) {
        return false;
    }
    return true;
}

bool MetadataController::IsChangeI32ArrayMetadata(
    const camera_metadata_item_t &baseEntry, const camera_metadata_item_t &newEntry)
{
    uint32_t count = newEntry.count;
    bool isDiff = false;
    for (uint32_t i = 0; i < count; i++) {
        if (*(baseEntry.data.i32 + i) != *(newEntry.data.i32 + i)) {
            isDiff = true;
            break;
        }
    }
    if (!isDiff) {
        return false;
    }
    return true;
}

bool MetadataController::UpdateNewTagData(const std::vector<int32_t> &keys,
    const std::shared_ptr<CameraMetadata> &inMeta, std::shared_ptr<CameraMetadata> &outMeta)
{
    if (keys.size() == 0) {
        CAMERA_LOGW("invalid size.");
        return false;
    }
    common_metadata_header_t *data = inMeta->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is null");
        return false;
    }
    return DealUpdateNewTagData(keys, data, outMeta);
}

bool MetadataController::DealUpdateNewTagData(
    const std::vector<int32_t> &keys, common_metadata_header_t *data, std::shared_ptr<CameraMetadata> &outMeta)
{
    bool result = false;
    for (auto it = keys.cbegin(); it != keys.cend(); it++) {
        camera_metadata_item_t entry;
        int ret = FindCameraMetadataItem(data, *it, &entry);
        if (ret != 0) {
            CAMERA_LOGE("get [%{public}d] error", *it);
            return false;
        }

        result = outMeta->addEntry(*it, static_cast<void *>(entry.data.u8), entry.count);
        if (!result) {
            CAMERA_LOGE("update key [%{public}d] error", *it);
            return false;
        }
    }
    return result;
}

void MetadataController::DealMessage()
{
    while (true) {
        std::unique_lock<std::mutex> lock(queueLock_);
        if (!isRunning_.load()) {
            break;
        }
        if (queue_.empty()) {
            cv_.wait(lock, [this] {
                return isRunning_.load() == false || !queue_.empty();
            });
        }
        if (!isRunning_.load()) {
            break;
        }
        std::shared_ptr<CameraMetadata> meta = queue_.front();
        for (auto nodeCallback : nodeFunc_) {
            nodeCallback(meta);
        }
        queue_.pop();
    }
    CAMERA_LOGI("thread closed");
}

void MetadataController::SetDeviceDefaultMetadata(std::shared_ptr<CameraMetadata> &meta)
{
    if (isInit_) {
        CAMERA_LOGE("already set device default meta data.");
        return;
    }
    isInit_ = true;
    if (metaDataConfig_ != nullptr) {
        metaDataConfig_.reset();
    }
    metaDataConfig_ = std::make_shared<MetadataConfig>();
    metaDataConfig_->GetDeviceDefaultMetadata(meta);
    FilterUpdateKeys(DEVICE_STREAM_ID, meta);
    metaDataConfig_->UpdateSettingsConfig(DEVICE_STREAM_ID, true, updateMetaDataKeys_[DEVICE_STREAM_ID], meta);
}

void MetadataController::Start()
{
    if (!isInit_) {
        CAMERA_LOGE("already start.");
        return;
    }
    peerFrame_ = true;
    updateSettingFunc_ = nullptr;

    abilityMetaData_.clear();

    if (isRunning_.load()) {
        isRunning_.store(false);
    }
    cv_.notify_all();
    StopThread();

    isRunning_.store(true);

    std::queue<std::shared_ptr<CameraMetadata>> empty;
    swap(empty, queue_);

    nodeFunc_.clear();
    firstNotifyNodes_.clear();
    updateMetaDataKeys_.clear();
    changeDataKeys_.clear();

    if (notifyChangedMetadata_ == nullptr) {
        notifyChangedMetadata_ = new (std::nothrow) std::thread([this] { this->DealMessage(); });
        if (notifyChangedMetadata_ == nullptr) {
            CAMERA_LOGE("notifyChangedMetadata_ create failed\n");
            return;
        }
    }
}

void MetadataController::Stop()
{
    if (!isInit_) {
        CAMERA_LOGE("invalid stop.");
        return;
    }
    isInit_ = false;

    {
        std::unique_lock<std::mutex> lock(queueLock_);
        isRunning_.store(false);
        cv_.notify_all();
    }

    StopThread();
    ClearNodeCallback();
}

void MetadataController::StopThread()
{
    if (notifyChangedMetadata_ != nullptr) {
        notifyChangedMetadata_->join();
        delete notifyChangedMetadata_;
        notifyChangedMetadata_ = nullptr;
    }
}

void MetadataController::NotifyMetaData(int32_t streamId)
{
    std::unique_lock<std::mutex> lock(dataConfigLock_);
    if (updateSettingFunc_ == nullptr) {
        CAMERA_LOGE("%{public}s updateSettingFunc_ is null and streamId=%{public}d", __FUNCTION__, streamId);
        return;
    }

    std::shared_ptr<CameraMetadata> metaTemp = nullptr;
    bool result = metaDataConfig_->GetMetadata(streamId, metaTemp);
    if (!result) {
        CAMERA_LOGW("%{public}s GetMetaData failed and streamId=%{public}d", __FUNCTION__, streamId);
        return;
    }

    std::shared_ptr<CameraMetadata> metaData = {};
    if (streamId == DEVICE_STREAM_ID) {
        metaData = std::make_shared<CameraMetadata>(ENTRY_CAPACITY, DATA_CAPACITY);
        UpdateNewTagData(abilityMetaData_, metaTemp, metaData);
        metaTemp = std::move(metaData);
    }

    if (peerFrame_) {
        updateSettingFunc_(metaTemp);
        return;
    }
    if (changeDataKeys_.count(streamId) == 0) {
        CAMERA_LOGE("%{public}s invalid streamId and streamId=%{public}d", __FUNCTION__, streamId);
        return;
    }
    updateSettingFunc_(metaTemp);
    changeDataKeys_.erase(streamId);
}
} // namespace Camera
} // namespace OHOS
