/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dmetadata_processor.h"

#include "dbuffer_manager.h"
#include "dcamera.h"
#include "distributed_hardware_log.h"
#include "cJSON.h"
#include "metadata_utils.h"

namespace OHOS {
namespace DistributedHardware {
DCamRetCode DMetadataProcessor::InitDCameraAbility(const std::string &sinkAbilityInfo)
{
    cJSON *rootValue = cJSON_Parse(sinkAbilityInfo.c_str());
    CHECK_NULL_RETURN_LOG(rootValue, FAILED, "The sinkAbilityInfo is null.");
    CHECK_OBJECT_FREE_RETURN(rootValue, FAILED, "The sinkAbilityInfo is not object.");
    cJSON *metaObj = cJSON_GetObjectItemCaseSensitive(rootValue, "MetaData");
    if (metaObj == nullptr || !cJSON_IsString(metaObj) || (metaObj->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return FAILED;
    }
    std::string metadataStr = std::string(metaObj->valuestring);
    if (!metadataStr.empty()) {
        std::hash<std::string> h;
        DHLOGI("Decode distributed camera metadata from base64, hash: %zu, length: %zu",
            h(metadataStr), metadataStr.length());
        std::string decodeString = Base64Decode(metadataStr);
        DHLOGI("Decode distributed camera metadata from string, hash: %zu, length: %zu",
            h(decodeString), decodeString.length());
        dCameraAbility_ = OHOS::Camera::MetadataUtils::DecodeFromString(decodeString);
        DHLOGI("Decode distributed camera metadata from string success.");
    }

    if (dCameraAbility_ == nullptr) {
        DHLOGE("Metadata is null in ability set or failed to decode metadata ability from string.");
        dCameraAbility_ = std::make_shared<CameraAbility>(DEFAULT_ENTRY_CAPACITY, DEFAULT_DATA_CAPACITY);
    }

    if (OHOS::Camera::GetCameraMetadataItemCount(dCameraAbility_->get()) <= 0) {
        DCamRetCode ret = InitDCameraDefaultAbilityKeys(sinkAbilityInfo);
        if (ret != SUCCESS) {
            DHLOGE("Init distributed camera defalult abilily keys failed.");
            dCameraAbility_ = nullptr;
            cJSON_Delete(rootValue);
            return ret;
        }
    }
    DCamRetCode ret = InitDCameraOutputAbilityKeys(sinkAbilityInfo);
    if (ret != SUCCESS) {
        DHLOGE("Init distributed camera output abilily keys failed.");
        dCameraAbility_ = nullptr;
        cJSON_Delete(rootValue);
        return ret;
    }

    camera_metadata_item_entry_t* itemEntry = OHOS::Camera::GetMetadataItems(dCameraAbility_->get());
    uint32_t count = dCameraAbility_->get()->item_count;
    for (uint32_t i = 0; i < count; i++, itemEntry++) {
        allResultSet_.insert((MetaType)(itemEntry->item));
    }
    cJSON_Delete(rootValue);
    return SUCCESS;
}

void DMetadataProcessor::InitDcameraBaseAbility()
{
    const uint8_t cameraType = OHOS_CAMERA_TYPE_LOGICAL;
    AddAbilityEntry(OHOS_ABILITY_CAMERA_TYPE, &cameraType, 1);

    const int64_t exposureTime = 0xFFFFFFFFFFFFFFFF;
    AddAbilityEntry(OHOS_SENSOR_EXPOSURE_TIME, &exposureTime, 1);

    const float correctionGain = 0.0;
    AddAbilityEntry(OHOS_SENSOR_COLOR_CORRECTION_GAINS, &correctionGain, 1);

    const uint8_t faceDetectMode = OHOS_CAMERA_FACE_DETECT_MODE_OFF;
    AddAbilityEntry(OHOS_STATISTICS_FACE_DETECT_MODE, &faceDetectMode, 1);

    const uint8_t histogramMode = OHOS_CAMERA_HISTOGRAM_MODE_OFF;
    AddAbilityEntry(OHOS_STATISTICS_HISTOGRAM_MODE, &histogramMode, 1);

    const uint8_t aeAntibandingMode = OHOS_CAMERA_AE_ANTIBANDING_MODE_OFF;
    AddAbilityEntry(OHOS_CONTROL_AE_ANTIBANDING_MODE, &aeAntibandingMode, 1);

    int32_t aeExposureCompensation = 0xFFFFFFFF;
    AddAbilityEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &aeExposureCompensation, 1);

    const uint8_t aeLock = OHOS_CAMERA_AE_LOCK_OFF;
    AddAbilityEntry(OHOS_CONTROL_AE_LOCK, &aeLock, 1);

    const uint8_t aeMode = OHOS_CAMERA_AE_MODE_OFF;
    AddAbilityEntry(OHOS_CONTROL_AE_MODE, &aeMode, 1);

    const uint8_t afMode = OHOS_CAMERA_AF_MODE_OFF;
    AddAbilityEntry(OHOS_CONTROL_AF_MODE, &afMode, 1);

    const uint8_t awbLock = OHOS_CAMERA_AWB_LOCK_OFF;
    AddAbilityEntry(OHOS_CONTROL_AWB_LOCK, &awbLock, 1);

    const uint8_t awbMode = OHOS_CAMERA_AWB_MODE_OFF;
    AddAbilityEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);

    const uint8_t aeAntibandingModes = OHOS_CAMERA_AE_ANTIBANDING_MODE_AUTO;
    AddAbilityEntry(OHOS_CONTROL_AE_AVAILABLE_ANTIBANDING_MODES, &aeAntibandingModes, 1);

    const uint8_t aeAvailableModes = OHOS_CAMERA_AE_MODE_ON;
    AddAbilityEntry(OHOS_CONTROL_AE_AVAILABLE_MODES, &aeAvailableModes, 1);

    const int32_t compensationRange[] = { 0, 0 };
    AddAbilityEntry(OHOS_ABILITY_AE_COMPENSATION_RANGE, compensationRange,
        (sizeof(compensationRange) / sizeof(compensationRange[0])));

    const camera_rational_t compensationStep[] = { { 0, 1 } };
    AddAbilityEntry(OHOS_ABILITY_AE_COMPENSATION_STEP, compensationStep,
        (sizeof(compensationStep) / sizeof(compensationStep[0])));

    const uint8_t afAvailableModes[] = { OHOS_CAMERA_AF_MODE_AUTO, OHOS_CAMERA_AF_MODE_OFF };
    AddAbilityEntry(OHOS_CONTROL_AF_AVAILABLE_MODES, afAvailableModes,
        (sizeof(afAvailableModes) / sizeof(afAvailableModes[0])));

    const uint8_t awbAvailableModes = OHOS_CAMERA_AWB_MODE_AUTO;
    AddAbilityEntry(OHOS_CONTROL_AWB_AVAILABLE_MODES, &awbAvailableModes, 1);

    const uint8_t deviceExposureMode = OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO;
    AddAbilityEntry(OHOS_ABILITY_DEVICE_AVAILABLE_EXPOSUREMODES, &deviceExposureMode, 1);

    const uint8_t controlExposureMode = OHOS_CAMERA_EXPOSURE_MODE_CONTINUOUS_AUTO;
    AddAbilityEntry(OHOS_CONTROL_EXPOSUREMODE, &controlExposureMode, 1);

    const uint8_t deviceFocusModes = OHOS_CAMERA_FOCUS_MODE_AUTO;
    AddAbilityEntry(OHOS_ABILITY_DEVICE_AVAILABLE_FOCUSMODES, &deviceFocusModes, 1);
    SetFpsRanges();
}

void DMetadataProcessor::SetFpsRanges()
{
    std::vector<int32_t> fpsRanges;
    fpsRanges.push_back(MIN_SUPPORT_DEFAULT_FPS);
    fpsRanges.push_back(MAX_SUPPORT_DEFAULT_FPS);
    AddAbilityEntry(OHOS_CONTROL_AE_TARGET_FPS_RANGE, fpsRanges.data(), fpsRanges.size());
    AddAbilityEntry(OHOS_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES, fpsRanges.data(), fpsRanges.size());
}

bool DMetadataProcessor::GetInfoFromJson(const std::string& sinkAbilityInfo)
{
    cJSON *rootValue = cJSON_Parse(sinkAbilityInfo.c_str());
    CHECK_NULL_RETURN_LOG(rootValue, false, "The sinkAbilityInfo is null.");
    CHECK_OBJECT_FREE_RETURN(rootValue, false, "The sinkAbilityInfo is not object.");
    cJSON *verObj = cJSON_GetObjectItemCaseSensitive(rootValue, "ProtocolVer");
    if (verObj == nullptr || !cJSON_IsString(verObj) || (verObj->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return false;
    }
    protocolVersion_ = std::string(verObj->valuestring);

    cJSON *positionObj = cJSON_GetObjectItemCaseSensitive(rootValue, "Position");
    if (positionObj == nullptr || !cJSON_IsString(positionObj) || (positionObj->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return false;
    }
    dCameraPosition_ = std::string(positionObj->valuestring);
    cJSON_Delete(rootValue);
    return true;
}

DCamRetCode DMetadataProcessor::InitDCameraDefaultAbilityKeys(const std::string &sinkAbilityInfo)
{
    if (!GetInfoFromJson(sinkAbilityInfo)) {
        return FAILED;
    }
    if (dCameraPosition_ == "BACK") {
        const uint8_t position = OHOS_CAMERA_POSITION_BACK;
        AddAbilityEntry(OHOS_ABILITY_CAMERA_POSITION, &position, 1);
    } else if (dCameraPosition_ == "FRONT") {
        const uint8_t position = OHOS_CAMERA_POSITION_FRONT;
        AddAbilityEntry(OHOS_ABILITY_CAMERA_POSITION, &position, 1);
    } else {
        const uint8_t position = OHOS_CAMERA_POSITION_OTHER;
        AddAbilityEntry(OHOS_ABILITY_CAMERA_POSITION, &position, 1);
    }

    InitDcameraBaseAbility();

    const uint8_t controlFocusMode = OHOS_CAMERA_FOCUS_MODE_AUTO;
    AddAbilityEntry(OHOS_CONTROL_FOCUSMODE, &controlFocusMode, 1);

    const uint8_t deviceFlashModes = OHOS_CAMERA_FLASH_MODE_AUTO;
    AddAbilityEntry(OHOS_ABILITY_DEVICE_AVAILABLE_FLASHMODES, &deviceFlashModes, 1);

    const uint8_t controlFlashMode = OHOS_CAMERA_FLASH_MODE_CLOSE;
    AddAbilityEntry(OHOS_CONTROL_FLASHMODE, &controlFlashMode, 1);

    float zoomRatioRange[1] = {1.0};
    AddAbilityEntry(OHOS_ABILITY_ZOOM_RATIO_RANGE, zoomRatioRange,
        (sizeof(zoomRatioRange) / sizeof(zoomRatioRange[0])));

    const float zoomRatio = 1.0;
    AddAbilityEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, 1);

    int32_t activeArraySize[] = {0, 0, static_cast<int32_t>(maxPreviewResolution_.width_),
        static_cast<int32_t>(maxPreviewResolution_.height_)};
    AddAbilityEntry(OHOS_SENSOR_INFO_ACTIVE_ARRAY_SIZE, activeArraySize,
        (sizeof(activeArraySize) / sizeof(activeArraySize[0])));

    int32_t pixelArraySize[] = {
        static_cast<int32_t>(maxPreviewResolution_.width_), static_cast<int32_t>(maxPreviewResolution_.height_)
    };
    AddAbilityEntry(OHOS_SENSOR_INFO_PIXEL_ARRAY_SIZE, pixelArraySize,
        (sizeof(pixelArraySize) / sizeof(pixelArraySize[0])));

    const int32_t jpegThumbnailSizes[] = {0, 0, DEGREE_240, DEGREE_180};
    AddAbilityEntry(OHOS_JPEG_AVAILABLE_THUMBNAIL_SIZES, jpegThumbnailSizes,
        (sizeof(jpegThumbnailSizes) / sizeof(jpegThumbnailSizes[0])));
    return SUCCESS;
}

void DMetadataProcessor::InitOutputAbilityWithoutMode(const std::string &sinkAbilityInfo)
{
    DHLOGI("InitOutputAbilityWithoutMode enter.");
    std::map<int, std::vector<DCResolution>> supportedFormats = GetDCameraSupportedFormats(sinkAbilityInfo);

    std::vector<int32_t> streamConfigs;
    std::vector<int32_t> extendStreamConfigs;
    for (int32_t i = 0; i < ADD_MODE; i++) { // Compatible camera framework modification
        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(dCameraAbility_->get(),
            OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &item);
        if (ret == CAM_META_SUCCESS && item.count != 0) {
            extendStreamConfigs.push_back(i);
        }
        InitBasicConfigTag(supportedFormats, streamConfigs);
        InitExtendConfigTag(supportedFormats, extendStreamConfigs);
        extendStreamConfigs.push_back(EXTEND_EOF); // mode eof
    }

    UpdateAbilityTag(streamConfigs, extendStreamConfigs);
}

DCamRetCode DMetadataProcessor::InitDCameraOutputAbilityKeys(const std::string &sinkAbilityInfo)
{
    cJSON *rootValue = cJSON_Parse(sinkAbilityInfo.c_str());
    CHECK_AND_RETURN_RET_LOG(rootValue == nullptr || !cJSON_IsObject(rootValue), FAILED,
        "sinkAbilityInfo parse error.");

    cJSON *modeArray = cJSON_GetObjectItemCaseSensitive(rootValue, CAMERA_SUPPORT_MODE.c_str());
    if (modeArray == nullptr || !cJSON_IsArray(modeArray)) {
        InitOutputAbilityWithoutMode(sinkAbilityInfo);
        cJSON_Delete(rootValue);
        return SUCCESS;
    }
    CHECK_AND_FREE_RETURN_RET_LOG(cJSON_GetArraySize(modeArray) == 0 || static_cast<uint32_t>(
        cJSON_GetArraySize(modeArray)) > JSON_ARRAY_MAX_SIZE, FAILED, rootValue, "modeArray create error.");

    std::vector<std::string> keys;
    int32_t arraySize = cJSON_GetArraySize(modeArray);
    for (int32_t i = 0; i < arraySize; ++i) {
        cJSON *number = cJSON_GetArrayItem(modeArray, i);
        if (number != nullptr && cJSON_IsNumber(number)) {
            keys.push_back(std::to_string(number->valueint));
        }
    }
    std::vector<int32_t> streamConfigs;
    std::vector<int32_t> extendStreamConfigs;
    for (std::string key : keys) {
        cJSON *value = cJSON_GetObjectItem(rootValue, key.c_str());
        CHECK_AND_FREE_RETURN_RET_LOG(value == nullptr || !cJSON_IsObject(value), FAILED, rootValue, "mode get error.");

        char *jsonValue = cJSON_Print(value);
        std::string format(jsonValue);
        DHLOGI("the current mode :%{public}s. value :%{public}s", key.c_str(), format.c_str());
        std::map<int, std::vector<DCResolution>> supportedFormats = GetDCameraSupportedFormats(format);

        camera_metadata_item_t item;
        int ret = OHOS::Camera::FindCameraMetadataItem(dCameraAbility_->get(),
            OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &item);
        if (ret == CAM_META_SUCCESS && item.count != 0) {
            extendStreamConfigs.push_back(std::stoi(key)); // mode
        }

        InitBasicConfigTag(supportedFormats, streamConfigs);
        InitExtendConfigTag(supportedFormats, extendStreamConfigs);
        extendStreamConfigs.push_back(EXTEND_EOF); // mode eof

        cJSON_free(jsonValue);
        sinkPhotoProfiles_.clear();
        sinkPreviewProfiles_.clear();
        sinkVideoProfiles_.clear();
    }
    UpdateAbilityTag(streamConfigs, extendStreamConfigs);

    cJSON_Delete(rootValue);
    return SUCCESS;
}

void DMetadataProcessor::UpdateAbilityTag(std::vector<int32_t> &streamConfigs,
    std::vector<int32_t> &extendStreamConfigs)
{
    UpdateAbilityEntry(OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, streamConfigs.data(),
        streamConfigs.size());

    UpdateAbilityEntry(OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, extendStreamConfigs.data(),
        extendStreamConfigs.size());

    UpdateAbilityEntry(OHOS_SENSOR_INFO_MAX_FRAME_DURATION, &MAX_FRAME_DURATION, 1);

    const int32_t jpegMaxSize = maxPhotoResolution_.width_ * maxPhotoResolution_.height_;
    UpdateAbilityEntry(OHOS_JPEG_MAX_SIZE, &jpegMaxSize, 1);

    const uint8_t connectionType = OHOS_CAMERA_CONNECTION_TYPE_REMOTE;
    UpdateAbilityEntry(OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &connectionType, 1);
}

void DMetadataProcessor::InitBasicConfigTag(std::map<int, std::vector<DCResolution>> &supportedFormats,
    std::vector<int32_t> &streamConfigs)
{
    std::map<int, std::vector<DCResolution>>::iterator iter;
    for (iter = supportedFormats.begin(); iter != supportedFormats.end(); ++iter) {
        std::vector<DCResolution> resolutionList = iter->second;
        for (auto resolution : resolutionList) {
            DHLOGI("DMetadataProcessor::sink supported formats: { format=%{public}d, width=%{public}d, height="
                "%{public}d }", iter->first, resolution.width_, resolution.height_);
            streamConfigs.push_back(iter->first);
            streamConfigs.push_back(resolution.width_);
            streamConfigs.push_back(resolution.height_);
        }
    }
}

void DMetadataProcessor::InitExtendConfigTag(std::map<int, std::vector<DCResolution>> &supportedFormats,
    std::vector<int32_t> &extendStreamConfigs)
{
    extendStreamConfigs.push_back(EXTEND_PREVIEW); // preview
    std::map<int, std::vector<DCResolution>>::iterator previewIter;
    for (previewIter = sinkPreviewProfiles_.begin(); previewIter != sinkPreviewProfiles_.end(); ++previewIter) {
        std::vector<DCResolution> resolutionList = previewIter->second;
        for (auto resolution : resolutionList) {
            DHLOGI("sink extend supported preview formats: { format=%{public}d, width=%{public}d, height=%{public}d }",
                previewIter->first, resolution.width_, resolution.height_);
            AddConfigs(extendStreamConfigs, previewIter->first, resolution.width_, resolution.height_, PREVIEW_FPS);
        }
    }
    extendStreamConfigs.push_back(EXTEND_EOF); // preview eof

    extendStreamConfigs.push_back(EXTEND_VIDEO); // video
    std::map<int, std::vector<DCResolution>>::iterator videoIter;
    for (videoIter = sinkVideoProfiles_.begin(); videoIter != sinkVideoProfiles_.end(); ++videoIter) {
        std::vector<DCResolution> resolutionList = videoIter->second;
        for (auto resolution : resolutionList) {
            DHLOGI("sink extend supported video formats: { format=%{public}d, width=%{public}d, height=%{public}d }",
                videoIter->first, resolution.width_, resolution.height_);
            AddConfigs(extendStreamConfigs, videoIter->first, resolution.width_, resolution.height_, VIDEO_FPS);
        }
    }
    extendStreamConfigs.push_back(EXTEND_EOF); // video eof

    if (!sinkPhotoProfiles_.empty()) {
        extendStreamConfigs.push_back(EXTEND_PHOTO); // photo
        std::map<int, std::vector<DCResolution>>::iterator photoIter;
        for (photoIter = sinkPhotoProfiles_.begin(); photoIter != sinkPhotoProfiles_.end(); ++photoIter) {
            std::vector<DCResolution> resolutionList = photoIter->second;
            for (auto resolution : resolutionList) {
                DHLOGI("sink extend supported photo formats: {format=%{public}d, width=%{public}d, height=%{public}d}",
                    photoIter->first, resolution.width_, resolution.height_);
                AddConfigs(extendStreamConfigs, photoIter->first, resolution.width_, resolution.height_, PHOTO_FPS);
            }
        }
        extendStreamConfigs.push_back(EXTEND_EOF); // photo eof
    }
}

void DMetadataProcessor::AddConfigs(std::vector<int32_t> &sinkExtendStreamConfigs, int32_t format,
    int32_t width, int32_t height, int32_t fps)
{
    sinkExtendStreamConfigs.push_back(format);
    sinkExtendStreamConfigs.push_back(width);
    sinkExtendStreamConfigs.push_back(height);
    sinkExtendStreamConfigs.push_back(fps); // fixedfps
    sinkExtendStreamConfigs.push_back(fps); // minfps
    sinkExtendStreamConfigs.push_back(fps); // maxfps
    sinkExtendStreamConfigs.push_back(EXTEND_EOF); // eof
}

DCamRetCode DMetadataProcessor::AddAbilityEntry(uint32_t tag, const void *data, size_t size)
{
    if (dCameraAbility_ == nullptr) {
        DHLOGE("Distributed camera abilily is null.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(dCameraAbility_->get(), tag, &item);
    if (ret != CAM_META_SUCCESS) {
        if (!dCameraAbility_->addEntry(tag, data, size)) {
            DHLOGE("Add tag %{public}u failed.", tag);
            return FAILED;
        }
    }
    return SUCCESS;
}

DCamRetCode DMetadataProcessor::UpdateAbilityEntry(uint32_t tag, const void *data, size_t size)
{
    if (dCameraAbility_ == nullptr) {
        DHLOGE("Distributed camera abilily is null.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    camera_metadata_item_t item;
    int ret = OHOS::Camera::FindCameraMetadataItem(dCameraAbility_->get(), tag, &item);
    if (ret == CAM_META_SUCCESS) {
        if (!dCameraAbility_->updateEntry(tag, data, size)) {
            DHLOGE("Update tag %{public}u failed.", tag);
            return FAILED;
        }
    }
    return SUCCESS;
}

DCamRetCode DMetadataProcessor::GetDCameraAbility(std::shared_ptr<CameraAbility> &ability)
{
    ability = dCameraAbility_;
    return SUCCESS;
}

DCamRetCode DMetadataProcessor::SetMetadataResultMode(const ResultCallbackMode &mode)
{
    if (mode < ResultCallbackMode::PER_FRAME || mode > ResultCallbackMode::ON_CHANGED) {
        DHLOGE("Invalid result callback mode.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    metaResultMode_ = mode;
    return SUCCESS;
}

DCamRetCode DMetadataProcessor::GetEnabledMetadataResults(std::vector<MetaType> &results)
{
    auto iter = enabledResultSet_.begin();
    while (iter != enabledResultSet_.end()) {
        results.push_back(*iter);
        iter++;
    }
    return SUCCESS;
}

DCamRetCode DMetadataProcessor::EnableMetadataResult(const std::vector<MetaType> &results)
{
    if (results.size() == 0) {
        DHLOGE("Enable metadata result list is empty.");
        return SUCCESS;
    }

    for (size_t i = 0; i < results.size(); i++) {
        auto iter = allResultSet_.find(results[i]);
        if (iter != allResultSet_.end()) {
            auto anoIter = enabledResultSet_.find(results[i]);
            if (anoIter == enabledResultSet_.end()) {
                enabledResultSet_.insert(results[i]);
            }
        } else {
            DHLOGE("Cannot find match metatype.");
            return SUCCESS;
        }
    }
    return SUCCESS;
}

DCamRetCode DMetadataProcessor::DisableMetadataResult(const std::vector<MetaType> &results)
{
    if (results.size() == 0) {
        DHLOGE("Disable metadata result list is empty.");
        return SUCCESS;
    }

    for (size_t i = 0; i < results.size(); i++) {
        auto iter = allResultSet_.find(results[i]);
        if (iter != allResultSet_.end()) {
            auto anoIter = enabledResultSet_.find(results[i]);
            if (anoIter != enabledResultSet_.end()) {
                enabledResultSet_.erase(*iter);
            }
        } else {
            DHLOGE("Cannot find match metatype.");
            return SUCCESS;
        }
    }
    return SUCCESS;
}

DCamRetCode DMetadataProcessor::ResetEnableResults()
{
    if (enabledResultSet_.size() < allResultSet_.size()) {
        for (auto result : allResultSet_) {
            enabledResultSet_.insert(result);
        }
    }
    return SUCCESS;
}

void DMetadataProcessor::UpdateResultMetadata(const uint64_t &resultTimestamp)
{
    DHLOGD("DMetadataProcessor::UpdateResultMetadata result callback mode: %{public}d", metaResultMode_);
    if (metaResultMode_ != ResultCallbackMode::PER_FRAME) {
        return;
    }

    std::lock_guard<std::mutex> autoLock(producerMutex_);
    if (latestProducerMetadataResult_ == nullptr) {
        DHLOGD("DMetadataProcessor::UpdateResultMetadata latest producer metadata result is null");
        return;
    }

    UpdateAllResult(resultTimestamp);
}

void DMetadataProcessor::SetResultCallback(
    std::function<void(uint64_t, std::shared_ptr<OHOS::Camera::CameraMetadata>)> &resultCbk)
{
    resultCallback_ = resultCbk;
}

void DMetadataProcessor::UpdateAllResult(const uint64_t &resultTimestamp)
{
    uint32_t itemCap = OHOS::Camera::GetCameraMetadataItemCapacity(latestProducerMetadataResult_->get());
    uint32_t dataSize = OHOS::Camera::GetCameraMetadataDataSize(latestProducerMetadataResult_->get());
    DHLOGD("DMetadataProcessor::UpdateAllResult itemCapacity: %{public}u, dataSize: %{public}u", itemCap, dataSize);
    std::shared_ptr<OHOS::Camera::CameraMetadata> result =
        std::make_shared<OHOS::Camera::CameraMetadata>(itemCap, dataSize);
    int32_t ret = OHOS::Camera::CopyCameraMetadataItems(result->get(), latestProducerMetadataResult_->get());
    if (ret != CAM_META_SUCCESS) {
        DHLOGE("DMetadataProcessor::UpdateAllResult copy metadata item failed, ret: %{public}d", ret);
        return;
    }
    resultCallback_(resultTimestamp, result);
}

void DMetadataProcessor::UpdateOnChanged(const uint64_t &resultTimestamp)
{
    bool needReturn = false;
    uint32_t itemCap = OHOS::Camera::GetCameraMetadataItemCapacity(latestProducerMetadataResult_->get());
    uint32_t dataSize = OHOS::Camera::GetCameraMetadataDataSize(latestProducerMetadataResult_->get());
    DHLOGD("DMetadataProcessor::UpdateOnChanged itemCapacity: %{public}u, dataSize: %{public}u", itemCap, dataSize);
    std::shared_ptr<OHOS::Camera::CameraMetadata> result =
        std::make_shared<OHOS::Camera::CameraMetadata>(itemCap, dataSize);
    DHLOGD("DMetadataProcessor::UpdateOnChanged enabledResultSet size: %{public}zu", enabledResultSet_.size());
    for (auto tag : enabledResultSet_) {
        DHLOGD("DMetadataProcessor::UpdateOnChanged cameta device metadata tag: %{public}d", tag);
        camera_metadata_item_t item;
        camera_metadata_item_t anoItem;
        int ret1 = OHOS::Camera::FindCameraMetadataItem(latestProducerMetadataResult_->get(), tag, &item);
        int ret2 = OHOS::Camera::FindCameraMetadataItem(latestConsumerMetadataResult_->get(), tag, &anoItem);
        DHLOGD("DMetadataProcessor::UpdateOnChanged find metadata item ret: %{public}d, %{public}d", ret1, ret2);
        if (ret1 != CAM_META_SUCCESS) {
            continue;
        }

        if (ret2 == CAM_META_SUCCESS) {
            if ((item.count != anoItem.count) || (item.data_type != anoItem.data_type)) {
                needReturn = true;
                result->addEntry(tag, GetMetadataItemData(item), item.count);
                continue;
            }
            uint32_t size = GetDataSize(item.data_type);
            DHLOGD("DMetadataProcessor::UpdateOnChanged data size: %{public}u", size);
            for (uint32_t i = 0; i < (size * static_cast<uint32_t>(item.count)); i++) {
                if (*(item.data.u8 + i) != *(anoItem.data.u8 + i)) {
                    needReturn = true;
                    result->addEntry(tag, GetMetadataItemData(item), item.count);
                    break;
                }
            }
        } else {
            needReturn = true;
            result->addEntry(tag, GetMetadataItemData(item), item.count);
            continue;
        }
    }

    if (needReturn) {
        resultCallback_(resultTimestamp, result);
    }
}

DCamRetCode DMetadataProcessor::SaveResultMetadata(std::string resultStr)
{
    if (resultStr.empty()) {
        DHLOGE("Input result string is null.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    std::string metadataStr = Base64Decode(resultStr);
    std::lock_guard<std::mutex> autoLock(producerMutex_);
    latestConsumerMetadataResult_ = latestProducerMetadataResult_;
    latestProducerMetadataResult_ = OHOS::Camera::MetadataUtils::DecodeFromString(metadataStr);
    if (latestProducerMetadataResult_ == nullptr) {
        DHLOGE("Failed to decode metadata setting from string.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    if (!OHOS::Camera::GetCameraMetadataItemCount(latestProducerMetadataResult_->get())) {
        DHLOGE("Input result metadata item is empty.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    DHLOGD("DMetadataProcessor::SaveResultMetadata result callback mode: %{public}d", metaResultMode_);
    if (metaResultMode_ != ResultCallbackMode::ON_CHANGED) {
        return SUCCESS;
    }

    uint64_t resultTimestamp = GetCurrentLocalTimeStamp();
    if (latestConsumerMetadataResult_ == nullptr) {
        UpdateAllResult(resultTimestamp);
        return SUCCESS;
    }

    camera_metadata_item_entry_t* itemEntry = OHOS::Camera::GetMetadataItems(latestProducerMetadataResult_->get());
    uint32_t count = latestProducerMetadataResult_->get()->item_count;
    for (uint32_t i = 0; i < count; i++, itemEntry++) {
        enabledResultSet_.insert((MetaType)(itemEntry->item));
    }
    UpdateOnChanged(resultTimestamp);
    return SUCCESS;
}

void DMetadataProcessor::ConvertToCameraMetadata(common_metadata_header_t *&input,
    std::shared_ptr<OHOS::Camera::CameraMetadata> &output)
{
    CHECK_AND_RETURN_LOG(output == nullptr, "output is nullptr");
    auto ret = OHOS::Camera::CopyCameraMetadataItems(output->get(), input);
    if (ret != CAM_META_SUCCESS) {
        DHLOGE("Failed to copy the old metadata to new metadata.");
        output = nullptr;
    }
}

void DMetadataProcessor::ResizeMetadataHeader(common_metadata_header_t *&header,
    uint32_t itemCapacity, uint32_t dataCapacity)
{
    if (header) {
        OHOS::Camera::FreeCameraMetadataBuffer(header);
    }
    header = OHOS::Camera::AllocateCameraMetadataBuffer(itemCapacity, dataCapacity);
}

uint32_t DMetadataProcessor::GetDataSize(uint32_t type)
{
    uint32_t size = 0;
    if (type == META_TYPE_BYTE) {
        size = sizeof(uint8_t);
    } else if (type == META_TYPE_INT32) {
        size = sizeof(int32_t);
    } else if (type == META_TYPE_UINT32) {
        size = sizeof(uint32_t);
    } else if (type == META_TYPE_FLOAT) {
        size = sizeof(float);
    } else if (type == META_TYPE_INT64) {
        size = sizeof(int64_t);
    } else if (type == META_TYPE_DOUBLE) {
        size = sizeof(double);
    } else if (type == META_TYPE_RATIONAL) {
        size = sizeof(camera_rational_t);
    } else {
        size = 0;
    }
    return size;
}

void* DMetadataProcessor::GetMetadataItemData(const camera_metadata_item_t &item)
{
    switch (item.data_type) {
        case META_TYPE_BYTE: {
            return item.data.u8;
        }
        case META_TYPE_INT32: {
            return item.data.i32;
        }
        case META_TYPE_UINT32: {
            return item.data.ui32;
        }
        case META_TYPE_FLOAT: {
            return item.data.f;
        }
        case META_TYPE_INT64: {
            return item.data.i64;
        }
        case META_TYPE_DOUBLE: {
            return item.data.d;
        }
        case META_TYPE_RATIONAL: {
            return item.data.r;
        }
        default: {
            DHLOGE("DMetadataProcessor::GetMetadataItemData invalid data type: %{public}u", item.data_type);
            return nullptr;
        }
    }
}

cJSON* DMetadataProcessor::GetFormatObj(const std::string rootNode, cJSON* rootValue, std::string& formatStr)
{
    cJSON* nodeObj = cJSON_GetObjectItemCaseSensitive(rootValue, rootNode.c_str());
    if (nodeObj == nullptr || !cJSON_IsObject(nodeObj)) {
        return nullptr;
    }

    cJSON* resObj = cJSON_GetObjectItemCaseSensitive(nodeObj, "Resolution");
    if (resObj == nullptr || !cJSON_IsObject(resObj)) {
        return nullptr;
    }
    cJSON *formatObj = cJSON_GetObjectItemCaseSensitive(resObj, formatStr.c_str());
    if (formatObj == nullptr || !cJSON_IsArray(formatObj) || cJSON_GetArraySize(formatObj) == 0 ||
        static_cast<uint32_t>(cJSON_GetArraySize(formatObj)) > JSON_ARRAY_MAX_SIZE) {
        return nullptr;
    }
    return formatObj;
}

void DMetadataProcessor::GetEachNodeSupportedResolution(std::vector<int>& formats, const std::string rootNode,
    std::map<int, std::vector<DCResolution>>& supportedFormats, cJSON* rootValue)
{
    for (const auto &format : formats) {
        std::string formatStr = std::to_string(format);
        cJSON *formatObj = GetFormatObj(rootNode, rootValue, formatStr);
        if (formatObj == nullptr) {
            DHLOGE("Resolution or %s error.", formatStr.c_str());
            continue;
        }
        GetNodeSupportedResolution(format, rootNode, supportedFormats, rootValue);
    }
}

void DMetadataProcessor::GetNodeSupportedResolution(int format, const std::string rootNode,
    std::map<int, std::vector<DCResolution>>& supportedFormats, cJSON* rootValue)
{
    std::vector<DCResolution> resolutionVec;
    std::string formatStr = std::to_string(format);
    cJSON* formatObj = GetFormatObj(rootNode, rootValue, formatStr);
    if (formatObj == nullptr) {
        return;
    }
    int32_t size = cJSON_GetArraySize(formatObj);
    for (int32_t i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(formatObj, i);
        if (item == nullptr || !cJSON_IsString(item)) {
            DHLOGE("Resolution %s %d ,is not string.", formatStr.c_str(), i);
            continue;
        }
        std::string resoStr = std::string(item->valuestring);
        std::vector<std::string> reso;
        SplitString(resoStr, reso, STAR_SEPARATOR);
        if (reso.size() != SIZE_FMT_LEN) {
            continue;
        }
        uint32_t width = static_cast<uint32_t>(std::stoi(reso[0]));
        uint32_t height = static_cast<uint32_t>(std::stoi(reso[1]));
        if (height == 0 || width == 0 || ((rootNode == "Photo") &&
            ((width * height) > (MAX_SUPPORT_PHOTO_WIDTH * MAX_SUPPORT_PHOTO_HEIGHT))) ||
            ((rootNode != "Photo") && (width > MAX_SUPPORT_PREVIEW_WIDTH || height > MAX_SUPPORT_PREVIEW_HEIGHT))) {
            continue;
        }
        DCResolution resolution(width, height);
        resolutionVec.push_back(resolution);
    }
    if (!resolutionVec.empty()) {
        std::sort(resolutionVec.begin(), resolutionVec.end());
        supportedFormats[format] = resolutionVec;
        if ((rootNode != "Photo") && (maxPreviewResolution_ < resolutionVec[0])) {
            maxPreviewResolution_.width_ = resolutionVec[0].width_;
            maxPreviewResolution_.height_ = resolutionVec[0].height_;
        }
        if ((rootNode == "Photo") && (maxPhotoResolution_ < resolutionVec[0])) {
            maxPhotoResolution_.width_ = resolutionVec[0].width_;
            maxPhotoResolution_.height_ = resolutionVec[0].height_;
        }
        StoreSinkAndSrcConfig(format, rootNode, resolutionVec);
    }
}

void DMetadataProcessor::StoreSinkAndSrcConfig(int format, const std::string rootNode,
    std::vector<DCResolution> &resolutionVec)
{
    if (rootNode == "Photo") {
        sinkPhotoProfiles_[format] = resolutionVec;
    } else if (rootNode == "Preview") {
        sinkPreviewProfiles_[format] = resolutionVec;
    } else if (rootNode == "Video") {
        sinkVideoProfiles_[format] = resolutionVec;
    }
}

std::map<int, std::vector<DCResolution>> DMetadataProcessor::GetDCameraSupportedFormats(
    const std::string &abilityInfo)
{
    std::map<int, std::vector<DCResolution>> supportedFormats;
    cJSON *rootValue = cJSON_Parse(abilityInfo.c_str());
    CHECK_NULL_RETURN_LOG(rootValue, supportedFormats, "The abilityInfo is null.");
    CHECK_OBJECT_FREE_RETURN(rootValue, supportedFormats, "The abilityInfo is not object.");
    ParsePhotoFormats(rootValue, supportedFormats);
    ParsePreviewFormats(rootValue, supportedFormats);
    ParseVideoFormats(rootValue, supportedFormats);
    cJSON_Delete(rootValue);
    return supportedFormats;
}

void DMetadataProcessor::ParsePhotoFormats(cJSON* rootValue,
    std::map<int, std::vector<DCResolution>>& supportedFormats)
{
    cJSON *photoObj = cJSON_GetObjectItemCaseSensitive(rootValue, "Photo");
    if (photoObj == nullptr || !cJSON_IsObject(photoObj)) {
        DHLOGE("Input Photo info is null.");
        return;
    }

    cJSON *formatObj = cJSON_GetObjectItemCaseSensitive(photoObj, "OutputFormat");
    if (formatObj == nullptr || !cJSON_IsArray(formatObj) || cJSON_GetArraySize(formatObj) == 0 ||
        static_cast<uint32_t>(cJSON_GetArraySize(formatObj)) > JSON_ARRAY_MAX_SIZE) {
        DHLOGE("Photo output format error.");
        return;
    }

    std::vector<int> photoFormats;
    int32_t size = cJSON_GetArraySize(formatObj);
    for (int32_t i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(formatObj, i);
        if (item !=nullptr && cJSON_IsNumber(item)) {
            photoFormats.push_back(item->valueint);
        }
    }
    sinkPhotoFormats_ = photoFormats;
    GetEachNodeSupportedResolution(photoFormats, "Photo", supportedFormats, rootValue);
}

void DMetadataProcessor::ParsePreviewFormats(cJSON* rootValue,
    std::map<int, std::vector<DCResolution>>& supportedFormats)
{
    cJSON *previewObj = cJSON_GetObjectItemCaseSensitive(rootValue, "Preview");
    if (previewObj == nullptr || !cJSON_IsObject(previewObj)) {
        DHLOGE("Preview error.");
        return;
    }
    cJSON *formatObj = cJSON_GetObjectItemCaseSensitive(previewObj, "OutputFormat");
    if (formatObj == nullptr || !cJSON_IsArray(formatObj) || cJSON_GetArraySize(formatObj) == 0 ||
        static_cast<uint32_t>(cJSON_GetArraySize(formatObj)) > JSON_ARRAY_MAX_SIZE) {
        DHLOGE("Preview output format error.");
        return;
    }
    std::vector<int> previewFormats;
    int32_t size = cJSON_GetArraySize(formatObj);
    for (int32_t i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(formatObj, i);
        if (item !=nullptr && cJSON_IsNumber(item)) {
            previewFormats.push_back(item->valueint);
        }
    }
    GetEachNodeSupportedResolution(previewFormats, "Preview", supportedFormats, rootValue);
}

void DMetadataProcessor::ParseVideoFormats(cJSON* rootValue,
    std::map<int, std::vector<DCResolution>>& supportedFormats)
{
    cJSON *videoObj = cJSON_GetObjectItemCaseSensitive(rootValue, "Video");
    if (videoObj == nullptr || !cJSON_IsObject(videoObj)) {
        DHLOGE("Video error.");
        return;
    }
    cJSON *formatObj = cJSON_GetObjectItemCaseSensitive(videoObj, "OutputFormat");
    if (formatObj == nullptr || !cJSON_IsArray(formatObj) || cJSON_GetArraySize(formatObj) == 0 ||
        static_cast<uint32_t>(cJSON_GetArraySize(formatObj)) > JSON_ARRAY_MAX_SIZE) {
        DHLOGE("Video output format error.");
        return;
    }
    std::vector<int> videoFormats;
    int32_t size = cJSON_GetArraySize(formatObj);
    for (int32_t i = 0; i < size; i++) {
        cJSON *item = cJSON_GetArrayItem(formatObj, i);
        if (item !=nullptr && cJSON_IsNumber(item)) {
            videoFormats.push_back(item->valueint);
        }
    }
    GetEachNodeSupportedResolution(videoFormats, "Video", supportedFormats, rootValue);
}

void DMetadataProcessor::PrintDCameraMetadata(const common_metadata_header_t *metadata)
{
    if (metadata == nullptr) {
        DHLOGE("Failed to print metadata, input metadata is null.");
        return;
    }

    uint32_t tagCount = OHOS::Camera::GetCameraMetadataItemCount(metadata);
    DHLOGD("DMetadataProcessor::PrintDCameraMetadata, input metadata item count = %{public}d.", tagCount);
    for (uint32_t i = 0; i < tagCount; i++) {
        camera_metadata_item_t item;
        int ret = OHOS::Camera::GetCameraMetadataItem(metadata, i, &item);
        if (ret != 0) {
            continue;
        }

        const char *name = OHOS::Camera::GetCameraMetadataItemName(item.item);
        if (item.data_type == META_TYPE_BYTE) {
            for (size_t k = 0; k < item.count; k++) {
                DHLOGI("tag index:%d, name:%s, value:%d", item.index, name, (uint8_t)(item.data.u8[k]));
            }
        } else if (item.data_type == META_TYPE_INT32) {
            for (size_t k = 0; k < item.count; k++) {
                DHLOGI("tag index:%d, name:%s, value:%d", item.index, name, (int32_t)(item.data.i32[k]));
            }
        } else if (item.data_type == META_TYPE_UINT32) {
            for (size_t k = 0; k < item.count; k++) {
                DHLOGI("tag index:%d, name:%s, value:%d", item.index, name, (uint32_t)(item.data.ui32[k]));
            }
        } else if (item.data_type == META_TYPE_FLOAT) {
            for (size_t k = 0; k < item.count; k++) {
                DHLOGI("tag index:%d, name:%s, value:%f", item.index, name, (float)(item.data.f[k]));
            }
        } else if (item.data_type == META_TYPE_INT64) {
            for (size_t k = 0; k < item.count; k++) {
                DHLOGI("tag index:%d, name:%s, value:%lld", item.index, name, (long long)(item.data.i64[k]));
            }
        } else if (item.data_type == META_TYPE_DOUBLE) {
            for (size_t k = 0; k < item.count; k++) {
                DHLOGI("tag index:%d, name:%s, value:%lf", item.index, name, (double)(item.data.d[k]));
            }
        } else {
            DHLOGI("tag index:%d, name:%s", item.index, name);
        }
    }
}
} // namespace DistributedHardware
} // namespace OHOS
