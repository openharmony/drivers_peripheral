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

#include <algorithm>
#include "camera_host_vdi_impl.h"
#include "idevice_manager.h"
#include "camera_host_config.h"
#include "metadata_utils.h"

#include "v1_0/icamera_host_vdi_callback.h"
#include "camera_dump.h"
#ifdef HITRACE_LOG_ENABLED
#include "hdf_trace.h"
#define HDF_CAMERA_TRACE HdfTrace trace(__func__, "HDI:CAM:")
#else
#define HDF_CAMERA_TRACE
#endif

namespace OHOS::Camera {

CameraHostVdiImpl::CameraHostVdiImpl()
{
    CAMERA_LOGD("ctor, instance");
}

CameraHostVdiImpl::~CameraHostVdiImpl()
{
    CAMERA_LOGD("dtor, instance");
}

VdiCamRetCode CameraHostVdiImpl::Init()
{
    std::shared_ptr<IDeviceManager> deviceManager =
        IDeviceManager::GetInstance();
    if (deviceManager == nullptr) {
        return INVALID_ARGUMENT;
    }

    RetCode ret = RC_OK;
    ret = deviceManager->Init();
    if (ret == RC_ERROR) {
        return INVALID_ARGUMENT;
    }

    CameraHostConfig *config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        return INVALID_ARGUMENT;
    }

    std::vector<std::string> cameraIds;
    RetCode rc = config->GetCameraIds(cameraIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("host get camera id failed.");
        return INVALID_ARGUMENT;
    }

    for (auto &cameraId : cameraIds) {
        std::vector<std::string> phyCameraIds;
        rc = config->GetPhysicCameraIds(cameraId, phyCameraIds);
        if (rc != RC_OK) {
            continue;
        }
        std::shared_ptr<CameraDeviceVdiImpl> cameraDevice =
            CameraDeviceVdiImpl::CreateCameraDevice(cameraId);
        if (cameraDevice != nullptr) {
            cameraDeviceMap_.insert(std::make_pair(cameraId, cameraDevice));
        } else {
            CAMERA_LOGW("host implement new device failed [cameraid = %{public}s].", cameraId.c_str());
        }
    }

    deviceManager->SetHotplugDevCallBack([this](const std::shared_ptr<CameraAbility> &meta,
        const bool &status, const CameraId &cameraId) {
            VdiCameraStatus cameraStatus = status ? AVAILABLE : UN_AVAILABLE;
            OnCameraStatus(cameraId, cameraStatus, meta);
        });

    (void)DevHostRegisterDumpHost(CameraDumpEvent);
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraHostVdiImpl::SetCallback(const OHOS::sptr<ICameraHostVdiCallback> &callbackObj)
{
    DFX_LOCAL_HITRACE_BEGIN;
    HDF_CAMERA_TRACE;

    if (callbackObj == nullptr) {
        CAMERA_LOGW("host callback is null.");
        return INVALID_ARGUMENT;
    }
    ICameraHostVdi::SetCallback(callbackObj);

    cameraHostCallback_ = callbackObj;

    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraHostVdiImpl::GetCameraIds(std::vector<std::string> &cameraIds)
{
    DFX_LOCAL_HITRACE_BEGIN;
    HDF_CAMERA_TRACE;

    CameraHostConfig *config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        return INVALID_ARGUMENT;
    }
    RetCode rc = config->GetCameraIds(cameraIds);
    if (rc != RC_OK) {
        return INVALID_ARGUMENT;
    }

    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraHostVdiImpl::GetCameraAbility(const std::string &cameraId,
    std::vector<uint8_t> &cameraAbility)
{
    DFX_LOCAL_HITRACE_BEGIN;
    HDF_CAMERA_TRACE;
    CameraHostConfig *config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        return INVALID_ARGUMENT;
    }
    std::shared_ptr<CameraAbility> ability;
    RetCode rc = config->GetCameraAbility(cameraId, ability);
    if (rc != RC_OK) {
        return INVALID_ARGUMENT;
    }

    common_metadata_header_t *data = ability->get();
    camera_metadata_item_t entry;
    if (FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_CONNECTION_TYPE, &entry) == 0) {
        uint8_t conectType = *(entry.data.u8);
        if (conectType == OHOS_CAMERA_CONNECTION_TYPE_BUILTIN &&
            FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &entry) == 0) {
            (void)DeleteCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS);
        }
    }

    CameraDumper &dumper = CameraDumper::GetInstance();
    dumper.DumpMetadata("cameraAbility", ENABLE_METADATA, ability);

    MetadataUtils::ConvertMetadataToVec(ability, cameraAbility);
    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraHostVdiImpl::OpenCamera(const std::string &cameraId, const sptr<ICameraDeviceVdiCallback> &callbackObj,
    sptr<ICameraDeviceVdi> &device)
{
    CAMERA_LOGD("OpenCamera entry");
    DFX_LOCAL_HITRACE_BEGIN;
    HDF_CAMERA_TRACE;
    if (CameraIdInvalid(cameraId) != RC_OK || callbackObj == nullptr) {
        CAMERA_LOGW("open camera id is empty or callback is null.");
        return INVALID_ARGUMENT;
    }

    auto itr = cameraDeviceMap_.find(cameraId);
    if (itr == cameraDeviceMap_.end()) {
        CAMERA_LOGE("camera device not found.");
        return INSUFFICIENT_RESOURCES;
    }
    CAMERA_LOGD("OpenCamera cameraId find success.");

    std::shared_ptr<CameraDeviceVdiImpl> cameraDevice = itr->second;
    if (cameraDevice == nullptr) {
        CAMERA_LOGE("camera device is null.");
        return INSUFFICIENT_RESOURCES;
    }

    VdiCamRetCode ret = cameraDevice->SetCallback(callbackObj);
    CHECK_IF_NOT_EQUAL_RETURN_VALUE(ret, VDI::Camera::V1_0::NO_ERROR, ret);

    CameraHostConfig *config = CameraHostConfig::GetInstance();
    CHECK_IF_PTR_NULL_RETURN_VALUE(config, INVALID_ARGUMENT);

    std::vector<std::string> phyCameraIds;
    RetCode rc = config->GetPhysicCameraIds(cameraId, phyCameraIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("get physic cameraId failed.");
        return DEVICE_ERROR;
    }
    if (CameraPowerUp(cameraId, phyCameraIds) != RC_OK) {
        CAMERA_LOGE("camera powerup failed.");
        CameraPowerDown(phyCameraIds);
        return DEVICE_ERROR;
    }

    auto sptrDevice = deviceBackup_.find(cameraId);
    if (sptrDevice == deviceBackup_.end()) {
#ifdef CAMERA_BUILT_ON_OHOS_LITE
        deviceBackup_[cameraId] = cameraDevice;
#else
        deviceBackup_[cameraId] = cameraDevice.get();
#endif
    }
    device = deviceBackup_[cameraId];
    cameraDevice->SetStatus(true);
    CameraDumper& dumper = CameraDumper::GetInstance();
    dumper.DumpStart();
    CAMERA_LOGD("open camera success.");
    DFX_LOCAL_HITRACE_END;
    return VDI::Camera::V1_0::NO_ERROR;
}

RetCode CameraHostVdiImpl::CameraIdInvalid(const std::string &cameraId)
{
    if (cameraId.empty()) {
        return RC_ERROR;
    }

    CameraHostConfig *config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        return RC_ERROR;
    }
    std::vector<std::string> cameraIds;
    RetCode ret = config->GetCameraIds(cameraIds);
    if (ret != RC_OK || cameraIds.empty()) {
        return RC_ERROR;
    }

    auto itr = std::find(cameraIds.begin(), cameraIds.end(), cameraId);
    if (itr == cameraIds.end()) {
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode CameraHostVdiImpl::CameraPowerUp(const std::string &cameraId,
    const std::vector<std::string> &phyCameraIds)
{
    VdiFlashlightStatus flashlightStatus = FLASHLIGHT_UNAVAILABLE;
    RetCode rc = SetFlashlight(phyCameraIds, false, flashlightStatus);
    if (rc != RC_OK) {
        CAMERA_LOGW("flash light close failed. [cameraId = %{public}s]", cameraId.c_str());
    }
    if (cameraHostCallback_ != nullptr) {
        cameraHostCallback_->OnFlashlightStatus(cameraId, flashlightStatus);
    }

    std::shared_ptr<IDeviceManager> deviceManager = IDeviceManager::GetInstance();
    if (deviceManager == nullptr) {
        CAMERA_LOGW("device manager is null [dm name MpiDeviceManager].");
        return RC_ERROR;
    }

    for (auto &phyCameraId : phyCameraIds) {
        auto itr = CameraHostConfig::enumCameraIdMap_.find(phyCameraId);
        if (itr == CameraHostConfig::enumCameraIdMap_.end()) {
            CAMERA_LOGW("config phyCameraId undefined in device manager.");
            continue;
        }
        rc = deviceManager->PowerUp(itr->second);
        if (rc != RC_OK) {
            CAMERA_LOGE("physic camera powerup failed [phyCameraId = %{public}s].", phyCameraId.c_str());
            return RC_ERROR;
        }
    }
    CAMERA_LOGD("camera powerup success.");

    return RC_OK;
}

void CameraHostVdiImpl::CameraPowerDown(const std::vector<std::string> &phyCameraIds)
{
    std::shared_ptr<IDeviceManager> deviceManager = IDeviceManager::GetInstance();
    if (deviceManager == nullptr) {
        CAMERA_LOGW("device manager is null [dm name MpiDeviceManager].");
        return;
    }

    RetCode ret = RC_OK;
    for (auto &cameraId : phyCameraIds) {
        auto itr = CameraHostConfig::enumCameraIdMap_.find(cameraId);
        if (itr == CameraHostConfig::enumCameraIdMap_.end()) {
            CAMERA_LOGW("config cameraId undefined in device manager.");
            continue;
        }

        ret = deviceManager->PowerDown(itr->second);
        if (ret != RC_OK) {
            CAMERA_LOGE("physic camera powerdown failed [cameraId = %{public}s].", cameraId.c_str());
            continue;
        }
        CAMERA_LOGD("[cameraId = %{public}s] powerdown success.", cameraId.c_str());
    }
}

int32_t CameraHostVdiImpl::SetFlashlight(const std::string &cameraId,  bool isEnable)
{
    DFX_LOCAL_HITRACE_BEGIN;
    HDF_CAMERA_TRACE;
    if (CameraIdInvalid(cameraId) != RC_OK) {
        CAMERA_LOGE("camera id is not found [cameraId = %{public}s].", cameraId.c_str());
        return INVALID_ARGUMENT;
    }

    for (auto &itr : cameraDeviceMap_) {
        std::shared_ptr<CameraDeviceVdiImpl> cameraDevice = itr.second;
        if (cameraDevice->IsOpened()) {
            CAMERA_LOGE("camera id opend [cameraId = %{public}s].", itr.first.c_str());
            return METHOD_NOT_SUPPORTED;
        }
    }

    CameraHostConfig *config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        return INVALID_ARGUMENT;
    }
    std::vector<std::string> phyCameraIds;
    RetCode rc = config->GetPhysicCameraIds(cameraId, phyCameraIds);
    if (rc != RC_OK) {
        CAMERA_LOGE("get physic cameraIds failed.");
        return DEVICE_ERROR;
    }

    VdiFlashlightStatus flashlightStatus = FLASHLIGHT_UNAVAILABLE;
    rc = SetFlashlight(phyCameraIds, isEnable, flashlightStatus);
    if (rc == RC_OK && flashlightStatus != FLASHLIGHT_UNAVAILABLE) {
        if (cameraHostCallback_ != nullptr) {
            cameraHostCallback_->OnFlashlightStatus(cameraId, flashlightStatus);
        }
        return VDI::Camera::V1_0::NO_ERROR;
    } else {
        return DEVICE_ERROR;
    }
    DFX_LOCAL_HITRACE_END;
}

RetCode CameraHostVdiImpl::SetFlashlight(const std::vector<std::string> &phyCameraIds,
    bool isEnable, VdiFlashlightStatus &flashlightStatus)
{
    std::shared_ptr<IDeviceManager> deviceManager = IDeviceManager::GetInstance();
    (void)phyCameraIds;
    if (deviceManager == nullptr) {
        CAMERA_LOGW("device manager is null [dm name MpiDeviceManager].");
        return RC_ERROR;
    }

    RetCode rc = deviceManager->SetFlashlight(FLASH_TORCH, isEnable);
    if (rc == RC_OK) {
        if (isEnable) {
            flashlightStatus = FLASHLIGHT_OFF;
        } else {
            flashlightStatus = FLASHLIGHT_ON;
        }
    }

    return rc;
}

void CameraHostVdiImpl::OnCameraStatus(CameraId cameraId,
    VdiCameraStatus status, const std::shared_ptr<CameraAbility> ability)
{
    CameraHostConfig *config = CameraHostConfig::GetInstance();
    if (config == nullptr) {
        CAMERA_LOGE("config is nullptr");
        return;
    }
    if (cameraId < 0 && cameraId > CAMERA_MAX) {
        CAMERA_LOGE("dvice manager callback cameraId error.");
        return;
    }
    std::vector<std::string> physicalCameraIds;
    std::string physicalCameraId = config->ReturnPhysicalCameraIdToString(cameraId);
    if (physicalCameraId.size() == 0) {
        CAMERA_LOGE("config cameraId undefined in device manager.");
        return;
    }
    physicalCameraIds.push_back(physicalCameraId);

    if (status == AVAILABLE) {
        std::string logicalCameraId = config->GenerateNewLogicalCameraId();
        config->AddUsbCameraId(logicalCameraId);
        RetCode rc = config->AddCameraId(logicalCameraId, physicalCameraIds, ability);
        if (rc == RC_OK && logicalCameraId.size() > 0) {
            CAMERA_LOGI("add physicalCameraIds %{public}d logicalCameraId %{public}s",
                static_cast<int>(cameraId), logicalCameraId.c_str());
            if (cameraHostCallback_ != nullptr) {
                cameraHostCallback_->OnCameraEvent(logicalCameraId, CAMERA_EVENT_DEVICE_ADD);
                cameraHostCallback_->OnCameraStatus(logicalCameraId, status);
            }
        }
        std::shared_ptr<CameraDeviceVdiImpl> cameraDevice =
            CameraDeviceVdiImpl::CreateCameraDevice(logicalCameraId);
        if (cameraDevice != nullptr) {
            std::lock_guard<std::mutex> lck (mtx);
            cameraDeviceMap_[logicalCameraId] = cameraDevice;
        }
    } else {
        std::string logicalCameraId = config->SubtractCameraId(physicalCameraIds);
        if (logicalCameraId.size() > 0) {
            CAMERA_LOGI("physicalCameraIds %{public}d logicalCameraId %{public}s",
                static_cast<int>(cameraId), logicalCameraId.c_str());
            if (cameraHostCallback_ != nullptr) {
                cameraHostCallback_->OnCameraStatus(logicalCameraId, status);
                cameraHostCallback_->OnCameraEvent(logicalCameraId, CAMERA_EVENT_DEVICE_RMV);
            }
            std::lock_guard<std::mutex> lck (mtx);
            cameraDeviceMap_.erase(logicalCameraId);
        }
    }
}

int32_t CameraHostVdiImpl::CloseAllCameras()
{
    std::lock_guard<std::mutex> lck (mtx);
    for (auto it : cameraDeviceMap_) {
        if (it.second->IsOpened()) {
            (void) it.second->Close();
        }
    }

    return VDI::Camera::V1_0::NO_ERROR;
}

static int CreateCameraHostVdiInstance(struct HdfVdiBase *vdiBase)
{
    using OHOS::Camera::CameraHostVdiImpl;
    struct VdiWrapperCameraHost *vdiWrapperCameraHost = reinterpret_cast<struct VdiWrapperCameraHost *>(vdiBase);
    CameraHostVdiImpl *cameraHostVdiImpl = new (std::nothrow) CameraHostVdiImpl();
    if (cameraHostVdiImpl == nullptr) {
        CAMERA_LOGE("Create camera host vdi instance error, cameraHostVdiImpl is nullptr");
        return VDI::Camera::V1_0::NO_ERROR;
    }
    cameraHostVdiImpl->Init();
    vdiWrapperCameraHost->module = cameraHostVdiImpl;

    return HDF_SUCCESS;
}

static int DestoryCameraHostVdiInstance(struct HdfVdiBase *vdiBase)
{
    using OHOS::Camera::CameraHostVdiImpl;
    struct VdiWrapperCameraHost *vdiWrapperCameraHost = reinterpret_cast<struct VdiWrapperCameraHost *>(vdiBase);
    CameraHostVdiImpl *cameraHostVdiImpl = reinterpret_cast<CameraHostVdiImpl *>(vdiWrapperCameraHost->module);
    delete cameraHostVdiImpl;
    vdiWrapperCameraHost->module = nullptr;
    return HDF_SUCCESS;
}

static struct VdiWrapperCameraHost g_vdiCameraHost = {
    .base = {
        .moduleVersion = 1,
        .moduleName = "CameraHostVdiImplement",
        .CreateVdiInstance = CreateCameraHostVdiInstance,
        .DestoryVdiInstance = DestoryCameraHostVdiInstance,
    },
    .module = nullptr,
};

} // end namespace OHOS::Camera

HDF_VDI_INIT(OHOS::Camera::g_vdiCameraHost);
