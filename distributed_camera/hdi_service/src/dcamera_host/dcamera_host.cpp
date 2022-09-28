/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "dcamera_host.h"

#include "anonymous_string.h"
#include "distributed_hardware_log.h"
#include "metadata_utils.h"
#include "dcamera.h"

namespace OHOS {
namespace DistributedHardware {
OHOS::sptr<DCameraHost> DCameraHost::instance_ = nullptr;
DCameraHost::AutoRelease DCameraHost::autoRelease_;

extern "C" ICameraHost *CameraHostImplGetInstance(void)
{
    return static_cast<ICameraHost *>(DCameraHost::GetInstance().GetRefPtr());
}

OHOS::sptr<DCameraHost> DCameraHost::GetInstance()
{
    if (instance_ == nullptr) {
        instance_ = new DCameraHost();
        if (instance_ == nullptr) {
            DHLOGE("Get distributed camera host instance failed.");
            return nullptr;
        }
    }
    return instance_;
}

int32_t DCameraHost::SetCallback(const sptr<ICameraHostCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        DHLOGE("DCameraHost::SetCallback, input camera host callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }
    dCameraHostCallback_ = callbackObj;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::GetCameraIds(std::vector<std::string> &cameraIds)
{
    auto iter = dhBaseHashDCamIdMap_.begin();
    while (iter != dhBaseHashDCamIdMap_.end()) {
        if (!(iter->second).empty()) {
            cameraIds.push_back(iter->second);
        }
        iter++;
    }
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::GetCameraAbility(const std::string &cameraId, std::vector<uint8_t> &cameraAbility)
{
    if (IsCameraIdInvalid(cameraId)) {
        DHLOGE("DCameraHost::GetCameraAbility, input cameraId is invalid.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    DHLOGE("DCameraHost::GetCameraAbility for cameraId: %s", GetAnonyString(cameraId).c_str());

    auto iter = dCameraDeviceMap_.find(cameraId);
    std::shared_ptr<CameraAbility> ability = nullptr;
    int32_t ret = (iter->second)->GetDCameraAbility(ability);
    if (ret != CamRetCode::NO_ERROR) {
        DHLOGE("DCameraHost::GetCameraAbility, GetDCameraAbility failed, ret: %d.", ret);
        return ret;
    }
    bool retBool = OHOS::Camera::MetadataUtils::ConvertMetadataToVec(ability, cameraAbility);
    if (!retBool) {
        DHLOGE("DCameraHost::GetCameraAbility, ConvertMetadataToVec failed.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    do {
        camera_metadata_item_t item;
        constexpr uint32_t WIDTH_OFFSET = 1;
        constexpr uint32_t HEIGHT_OFFSET = 2;
        constexpr uint32_t UNIT_LENGTH = 3;
        ret = OHOS::Camera::FindCameraMetadataItem(ability->get(),
            OHOS_ABILITY_STREAM_AVAILABLE_BASIC_CONFIGURATIONS, &item);
        DHLOGI("FindCameraMetadataItem item=%u, count=%u, dataType=%u", item.item, item.count, item.data_type);
        if (ret != CAM_META_SUCCESS) {
            DHLOGE("Failed to find stream configuration in camera ability with return code %d", ret);
            break;
        }
        if (item.count % UNIT_LENGTH != 0) {
            DHLOGE("Invalid stream configuration count: %u", item.count);
            break;
        }
        for (uint32_t index = 0; index < item.count; index += UNIT_LENGTH) {
            int32_t format = item.data.i32[index];
            int32_t width = item.data.i32[index + WIDTH_OFFSET];
            int32_t height = item.data.i32[index + HEIGHT_OFFSET];
            DHLOGD("format: %d, width: %d, height: %d", format, width, height);
        }
    } while (0);
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::OpenCamera(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
    sptr<ICameraDevice> &device)
{
    if (IsCameraIdInvalid(cameraId) || callbackObj == nullptr) {
        DHLOGE("DCameraHost::OpenCamera, open camera id is invalid or camera device callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    DHLOGI("DCameraHost::OpenCamera for cameraId: %s", GetAnonyString(cameraId).c_str());

    auto iter = dCameraDeviceMap_.find(cameraId);
    if (iter == dCameraDeviceMap_.end()) {
        DHLOGE("DCameraHost::OpenCamera, dcamera device not found.");
        return CamRetCode::INSUFFICIENT_RESOURCES;
    }

    OHOS::sptr<DCameraDevice> dcameraDevice = iter->second;
    if (dcameraDevice == nullptr) {
        DHLOGE("DCameraHost::OpenCamera, dcamera device is null.");
        return INSUFFICIENT_RESOURCES;
    }

    if (dcameraDevice->IsOpened()) {
        DHLOGE("DCameraHost::OpenCamera, dcamera device %s already opened.", GetAnonyString(cameraId).c_str());
        return CamRetCode::CAMERA_BUSY;
    }

    CamRetCode ret = dcameraDevice->OpenDCamera(callbackObj);
    if (ret != CamRetCode::NO_ERROR) {
        DHLOGE("DCameraHost::OpenCamera, open camera failed.");
        return ret;
    }
    device = dcameraDevice;

    DHLOGI("DCameraHost::OpenCamera, open camera %s success.", GetAnonyString(cameraId).c_str());
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::SetFlashlight(const std::string &cameraId, bool isEnable)
{
    (void)cameraId;
    (void)isEnable;
    DHLOGI("DCameraHost::SetFlashlight, distributed camera not support.");

    return CamRetCode::METHOD_NOT_SUPPORTED;
}

DCamRetCode DCameraHost::AddDCameraDevice(const DHBase &dhBase, const std::string &abilityInfo,
    const sptr<IDCameraProviderCallback> &callback)
{
    if (IsDhBaseInfoInvalid(dhBase)) {
        DHLOGE("DCameraHost::AddDCameraDevice, devId or dhId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    DHLOGI("DCameraHost::AddDCameraDevice for {devId: %s, dhId: %s}",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    if (abilityInfo.empty() || abilityInfo.length() > ABILITYINFO_MAX_LENGTH) {
        DHLOGE("DCameraHost::AddDCameraDevice, input abilityInfo is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    OHOS::sptr<DCameraDevice> dcameraDevice = new (std::nothrow) DCameraDevice(dhBase, abilityInfo);
    if (dcameraDevice == nullptr) {
        DHLOGE("DCameraHost::AddDCameraDevice, create dcamera device failed.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    std::string dCameraId = dcameraDevice->GetDCameraId();
    dCameraDeviceMap_[dCameraId] = dcameraDevice;
    DCameraBase dcameraBase(dhBase.deviceId_, dhBase.dhId_);
    dhBaseHashDCamIdMap_.emplace(dcameraBase, dCameraId);
    dcameraDevice->SetProviderCallback(callback);

    if (dCameraHostCallback_ != nullptr) {
        dCameraHostCallback_->OnCameraEvent(dCameraId, CameraEvent::CAMERA_EVENT_DEVICE_ADD);
    }

    DHLOGI("DCameraHost::AddDCameraDevice, create dcamera device success, dCameraId: %s",
        GetAnonyString(dCameraId).c_str());
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraHost::RemoveDCameraDevice(const DHBase &dhBase)
{
    DHLOGI("DCameraHost::RemoveDCameraDevice for {devId: %s, dhId: %s}",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    std::string dCameraId = GetCameraIdByDHBase(dhBase);
    if (dCameraId.empty()) {
        DHLOGE("DCameraHost::RemoveDCameraDevice, dhBase not exist.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    OHOS::sptr<DCameraDevice> dcameraDevice = GetDCameraDeviceByDHBase(dhBase);
    if (dcameraDevice != nullptr) {
        if (dcameraDevice->IsOpened()) {
            dcameraDevice->Close();
        }
        dcameraDevice->SetProviderCallback(nullptr);
    }

    DCameraBase dcameraBase(dhBase.deviceId_, dhBase.dhId_);
    dhBaseHashDCamIdMap_.erase(dcameraBase);
    dCameraDeviceMap_.erase(dCameraId);

    if (dCameraHostCallback_ != nullptr) {
        dCameraHostCallback_->OnCameraEvent(dCameraId, CameraEvent::CAMERA_EVENT_DEVICE_RMV);
    }

    DHLOGI("DCameraHost::RemoveDCameraDevice, remove dcamera device success, dCameraId: %s",
        GetAnonyString(dCameraId).c_str());
    return DCamRetCode::SUCCESS;
}

bool DCameraHost::IsCameraIdInvalid(const std::string &cameraId)
{
    if (cameraId.empty() || cameraId.length() > ID_MAX_SIZE) {
        return true;
    }

    auto iter = dhBaseHashDCamIdMap_.begin();
    while (iter != dhBaseHashDCamIdMap_.end()) {
        if (cameraId == iter->second) {
            return false;
        }
        iter++;
    }
    return true;
}

std::string DCameraHost::GetCameraIdByDHBase(const DHBase &dhBase)
{
    DCameraBase dcameraBase(dhBase.deviceId_, dhBase.dhId_);
    auto iter = dhBaseHashDCamIdMap_.find(dcameraBase);
    if (iter == dhBaseHashDCamIdMap_.end()) {
        return "";
    }
    return iter->second;
}

OHOS::sptr<DCameraDevice> DCameraHost::GetDCameraDeviceByDHBase(const DHBase &dhBase)
{
    std::string dCameraId = GetCameraIdByDHBase(dhBase);
    if (dCameraId.empty()) {
        DHLOGE("DCameraHost::GetDCameraDeviceByDHBase, dhBase not exist.");
        return nullptr;
    }

    auto iter = dCameraDeviceMap_.find(dCameraId);
    if (iter == dCameraDeviceMap_.end()) {
        DHLOGE("DCameraHost::GetDCameraDeviceByDHBase, dcamera device not found.");
        return nullptr;
    }
    return iter->second;
}

void DCameraHost::NotifyDCameraStatus(const DHBase &dhBase, int32_t result)
{
    std::string dCameraId = GetCameraIdByDHBase(dhBase);
    if (dCameraId.empty()) {
        DHLOGE("DCameraHost::NotifyDCameraStatus, dhBase not exist.");
        return;
    }
    if (dCameraHostCallback_ != nullptr) {
        dCameraHostCallback_->OnCameraStatus(dCameraId, CameraStatus::UN_AVAILABLE);
    }
}
} // namespace DistributedHardware
} // namespace OHOS
