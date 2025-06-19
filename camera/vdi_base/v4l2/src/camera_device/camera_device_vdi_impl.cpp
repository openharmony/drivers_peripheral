/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#include <chrono>
#include "camera_device_vdi_impl.h"
#include "ipipeline_core.h"
#include "camera_host_config.h"
#include "idevice_manager.h"
#include "camera_metadata_info.h"
#include "watchdog.h"
#include "metadata_controller.h"
#include "metadata_utils.h"
#include "camera_dump.h"
#ifdef HITRACE_LOG_ENABLED
#include "hdf_trace.h"
#define HDF_CAMERA_TRACE HdfTrace trace(__func__, "HDI:CAM:")
#else
#define HDF_CAMERA_TRACE
#endif
#define HDI_DEVICE_PLACE_A_WATCHDOG \
    PLACE_A_NOKILL_WATCHDOG(std::bind(&CameraDeviceVdiImpl::OnRequestTimeout, this))

namespace OHOS::Camera {
CameraDeviceVdiImpl::CameraDeviceVdiImpl(const std::string &cameraId,
    const std::shared_ptr<IPipelineCore> &pipelineCore)
    : isOpened_(false),
      cameraId_(cameraId),
      pipelineCore_(pipelineCore),
      cameraDeciceCallback_(nullptr),
      spStreamOperator_(nullptr),
      metaResultMode_(PER_FRAME),
      metadataResults_(nullptr)
{
}

std::shared_ptr<CameraDeviceVdiImpl> CameraDeviceVdiImpl::CreateCameraDevice(const std::string &cameraId)
{
    HDF_CAMERA_TRACE;
    // create pipelineCore
    std::shared_ptr<IPipelineCore> pipelineCore = IPipelineCore::Create();
    if (pipelineCore == nullptr) {
        CAMERA_LOGW("create pipeline core failed. [cameraId = %{public}s]", cameraId.c_str());
        return nullptr;
    }

    RetCode rc = pipelineCore->Init();
    if (rc != RC_OK) {
        CAMERA_LOGW("pipeline core init failed. [cameraId = %{public}s]", cameraId.c_str());
        return nullptr;
    }

    std::shared_ptr<CameraDeviceVdiImpl> device = std::make_shared<CameraDeviceVdiImpl>(cameraId, pipelineCore);
    if (device == nullptr) {
        CAMERA_LOGW("create camera device failed. [cameraId = %{public}s]", cameraId.c_str());
        return nullptr;
    }
    CAMERA_LOGD("create camera device success. [cameraId = %{public}s]", cameraId.c_str());

    // set deviceManager metadata & dev status callback
    std::shared_ptr<IDeviceManager> deviceManager = IDeviceManager::GetInstance();
    if (deviceManager != nullptr) {
        deviceManager->SetMetaDataCallBack([device](const std::shared_ptr<CameraMetadata> &metadata) {
            device->OnMetadataChanged(metadata);
        });
        deviceManager->SetDevStatusCallBack([device]() {
            device->OnDevStatusErr();
        });
    }

    return device;
}

int32_t CameraDeviceVdiImpl::GetStreamOperator(const sptr<IStreamOperatorVdiCallback> &callbackObj,
    sptr<IStreamOperatorVdi> &streamOperator)
{
    CAMERA_LOGI("CameraDeviceVdiImpl::GetStreamOperator Begin, deviceName = %{public}s", cameraId_.c_str());
    HDF_CAMERA_TRACE;
    HDI_DEVICE_PLACE_A_WATCHDOG;
    DFX_LOCAL_HITRACE_BEGIN;
    if (callbackObj == nullptr) {
        CAMERA_LOGW("input callback is null.");
        return INVALID_ARGUMENT;
    }

    if (spStreamOperator_ == nullptr) {
#ifdef CAMERA_BUILT_ON_OHOS_LITE
        spStreamOperator_ = std::make_shared<StreamOperatorVdiImpl>(callbackObj, shared_from_this());
#else
        spStreamOperator_ = new(std::nothrow) StreamOperatorVdiImpl(callbackObj, shared_from_this());
#endif
        if (spStreamOperator_ == nullptr) {
            CAMERA_LOGW("create stream operator failed.");
            return DEVICE_ERROR;
        }
        spStreamOperator_->Init();
        ismOperator_ = spStreamOperator_;
    }
    streamOperator = ismOperator_;
#ifndef CAMERA_BUILT_ON_OHOS_LITE
    InitMetadataController();
#endif
    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraDeviceVdiImpl::UpdateSettings(const std::vector<uint8_t> &settings)
{
    HDF_CAMERA_TRACE;
    HDI_DEVICE_PLACE_A_WATCHDOG;
    DFX_LOCAL_HITRACE_BEGIN;
    if (settings.empty()) {
        CAMERA_LOGE("input vector settings is empty.");
        return INVALID_ARGUMENT;
    }

    if (pipelineCore_ == nullptr) {
        CAMERA_LOGE("pipeline core is null.");
        return CAMERA_CLOSED;
    }

    std::shared_ptr<CameraMetadata> updateSettings;
    MetadataUtils::ConvertVecToMetadata(settings, updateSettings);

    CameraDumper &dumper = CameraDumper::GetInstance();
    dumper.DumpMetadata("updatesetting", ENABLE_METADATA, updateSettings);

    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.UpdateSettingsConfig(updateSettings);
    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraDeviceVdiImpl::GetSettings(std::vector<uint8_t> &settings)
{
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(ENTRY_CAPACITY, DATA_CAPACITY);
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr.");
        return DEVICE_ERROR;
    }
    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.GetSettingsConfig(meta);
    MetadataUtils::ConvertMetadataToVec(meta, settings);
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraDeviceVdiImpl::SetResultMode(VdiResultCallbackMode mode)
{
    CAMERA_LOGD("entry.");
    MetadataController &metaDataController = MetadataController::GetInstance();
    if (mode < PER_FRAME || mode > ON_CHANGED) {
        CAMERA_LOGE("parameter out of range.");
        return INVALID_ARGUMENT;
    } else if (mode == PER_FRAME) {
        metaDataController.SetPeerFrameFlag(true);
    } else {
        metaDataController.SetPeerFrameFlag(false);
    }

    metaResultMode_ = mode;
    return VDI::Camera::V1_0::NO_ERROR;
}

VdiResultCallbackMode CameraDeviceVdiImpl::GetMetaResultMode() const
{
    return metaResultMode_;
}

int32_t CameraDeviceVdiImpl::GetEnabledResults(std::vector<int32_t> &results)
{
    HDF_CAMERA_TRACE;
    HDI_DEVICE_PLACE_A_WATCHDOG;
    DFX_LOCAL_HITRACE_BEGIN;
    if (deviceMetaTypes_.empty()) {
        RetCode rc = GetEnabledFromCfg();
        if (rc != RC_OK) {
            CAMERA_LOGE("get enabled results from device manager failed.");
            return DEVICE_ERROR;
        }
    }

    std::unique_lock<std::mutex> l(enabledRstMutex_);
    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.GetEnabledAbility(results);
    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

RetCode CameraDeviceVdiImpl::GetEnabledFromCfg()
{
    // Get devicemanager
    std::shared_ptr<IDeviceManager> deviceManager = IDeviceManager::GetInstance();
    if (deviceManager == nullptr) {
        CAMERA_LOGW("device manager is null.");
        return RC_ERROR;
    }

    CameraHostConfig *config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        return RC_ERROR;
    }
    std::shared_ptr<CameraMetadata> ability;
    RetCode rc = config->GetCameraAbility(cameraId_, ability);
    if (rc != RC_OK || ability == nullptr) {
        CAMERA_LOGD("GetCameraAbility failed.");
        return RC_ERROR;
    }

    common_metadata_header_t *metadata = ability->get();
    if (metadata == nullptr) {
        CAMERA_LOGD("ability get metadata is null.");
        return RC_ERROR;
    }

    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(metadata,
        OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &entry);
    if (ret == 0) {
        CAMERA_LOGD("FindCameraMetadataIte tags = %{public}d. type = %{public}d", entry.count, entry.data_type);
        for (uint32_t i = 0; i < entry.count; i++) {
            deviceMetaTypes_.push_back(*(entry.data.i32 + i));
        }
    }

    return RC_OK;
}

int32_t CameraDeviceVdiImpl::EnableResult(const std::vector<int32_t> &results)
{
    HDF_CAMERA_TRACE;
    HDI_DEVICE_PLACE_A_WATCHDOG;
    DFX_LOCAL_HITRACE_BEGIN;
    std::unique_lock<std::mutex> l(enabledRstMutex_);
    for (auto &metaType : results) {
        auto itr = std::find(enabledResults_.begin(), enabledResults_.end(), metaType);
        if (itr == enabledResults_.end()) {
            enabledResults_.push_back(metaType);
        } else {
            CAMERA_LOGW("enabled result is existed. [metaType = %{public}d]", metaType);
        }
    }
    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.AddEnabledAbility(enabledResults_);
    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraDeviceVdiImpl::DisableResult(const std::vector<int32_t> &results)
{
    HDF_CAMERA_TRACE;
    HDI_DEVICE_PLACE_A_WATCHDOG;
    DFX_LOCAL_HITRACE_BEGIN;
    VdiCamRetCode ret = VDI::Camera::V1_0::NO_ERROR;
    std::unique_lock<std::mutex> l(enabledRstMutex_);
    for (auto &metaType : results) {
        auto itr = std::find(enabledResults_.begin(), enabledResults_.end(), metaType);
        if (itr != enabledResults_.end()) {
            enabledResults_.erase(itr);
        } else {
            CAMERA_LOGW("enabled result is not found. [metaType = %{public}d]", metaType);
            ret = INVALID_ARGUMENT;
        }
    }
    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.DelEnabledAbility(results);
    DFX_LOCAL_HITRACE_END;
    return ret;
}

int32_t CameraDeviceVdiImpl::Close()
{
    HDI_DEVICE_PLACE_A_WATCHDOG;
    HDF_CAMERA_TRACE;
    DFX_LOCAL_HITRACE_BEGIN;

    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.Stop();
    metaDataController.UnSetUpdateSettingCallback();

    if (spStreamOperator_ != nullptr) {
        spStreamOperator_->ReleaseStreams();
        spStreamOperator_ = nullptr;
    }

    std::shared_ptr<IDeviceManager> deviceManager = IDeviceManager::GetInstance();
    if (deviceManager == nullptr) {
        CAMERA_LOGW("device manager is null [dm name MpiDeviceManager].");
        return INVALID_ARGUMENT;
    }

    CameraHostConfig *config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        CAMERA_LOGD("CameraHostConfig get failed.");
        return INVALID_ARGUMENT;
    }

    std::vector<std::string> phyCameraIds;
    RetCode rc = config->GetPhysicCameraIds(cameraId_, phyCameraIds);
    if (rc != RC_OK) {
        CAMERA_LOGW("get physic cameraId failed.[cameraId = %{public}s]", cameraId_.c_str());
        return INVALID_ARGUMENT;
    }

    for (auto &phyCameraId : phyCameraIds) {
        auto itr = CameraHostConfig::enumCameraIdMap_.find(phyCameraId);
        if (itr == CameraHostConfig::enumCameraIdMap_.end()) {
            CAMERA_LOGW("config phyCameraId undefined in device manager.");
            continue;
        }

        rc = deviceManager->PowerDown(itr->second);
        if (rc != RC_OK) {
            CAMERA_LOGE("physic camera powerdown failed [phyCameraId = %{public}s].", phyCameraId.c_str());
            continue;
        }
        CAMERA_LOGD("[phyCameraId = %{public}s] powerdown success.", phyCameraId.c_str());
    }

    isOpened_ = false;
    cameraDeciceCallback_ = nullptr;
    DFX_LOCAL_HITRACE_END;
    CAMERA_LOGD("camera close success.");
    return VDI::Camera::V1_0::NO_ERROR;
}

VdiCamRetCode CameraDeviceVdiImpl::SetCallback(const OHOS::sptr<ICameraDeviceVdiCallback> &callback)
{
    if (callback == nullptr) {
        return INVALID_ARGUMENT;
    }
    cameraDeciceCallback_ = callback;
    return VDI::Camera::V1_0::NO_ERROR;
}

std::shared_ptr<IPipelineCore> CameraDeviceVdiImpl::GetPipelineCore() const
{
    return pipelineCore_;
}

uint64_t CameraDeviceVdiImpl::GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return static_cast<uint64_t>(tmp.count());
}

void CameraDeviceVdiImpl::InitMetadataController()
{
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraMetadata>(ENTRY_CAPACITY, DATA_CAPACITY);
    const int32_t deviceStreamId = 0;
    meta->addEntry(OHOS_CAMERA_STREAM_ID, &deviceStreamId, 1);
    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.SetDeviceDefaultMetadata(meta);
    metaDataController.Start();
    metaDataController.SetUpdateSettingCallback([this](const std::shared_ptr<CameraMetadata> &metadata) {
        OnMetadataChanged(metadata);
    });
}

void CameraDeviceVdiImpl::GetCameraId(std::string &cameraId) const
{
    cameraId = cameraId_;
}

void CameraDeviceVdiImpl::OnRequestTimeout()
{
    CAMERA_LOGD("OnRequestTimeout callback success.");
    // request error
    cameraDeciceCallback_->OnError(REQUEST_TIMEOUT, 0);
}

void CameraDeviceVdiImpl::OnMetadataChanged(const std::shared_ptr<CameraMetadata> &metadata)
{
    CAMERA_LOGI("OnMetadataChanged callback success.");

    if (cameraDeciceCallback_ == nullptr) {
        CAMERA_LOGE("camera device callback is null.");
        return;
    }

    uint64_t timestamp = GetCurrentLocalTimeStamp();
    std::vector<uint8_t> result;
    MetadataUtils::ConvertMetadataToVec(metadata, result);

    CameraDumper &dumper = CameraDumper::GetInstance();
    dumper.DumpMetadata("reportmeta", ENABLE_METADATA, metadata);

    cameraDeciceCallback_->OnResult(timestamp, result);
}

void CameraDeviceVdiImpl::OnDevStatusErr()
{
    CAMERA_LOGD("OnDevStatusErr callback success.");
    // device error
    cameraDeciceCallback_->OnError(FATAL_ERROR, 0);
}

bool CameraDeviceVdiImpl::IsOpened() const
{
    return isOpened_;
}

void CameraDeviceVdiImpl::SetStatus(bool isOpened)
{
    isOpened_ = isOpened;
}
} // end namespace OHOS::Camera
