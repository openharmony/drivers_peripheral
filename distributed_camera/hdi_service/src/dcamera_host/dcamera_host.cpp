/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include "iservice_registry.h"
#include "iproxy_broker.h"
#include "iservmgr_hdi.h"

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
        instance_ = sptr<DCameraHost>(new DCameraHost());
        if (instance_ == nullptr) {
            DHLOGE("Get distributed camera host instance failed.");
            return nullptr;
        }
    }
    return instance_;
}

int32_t DCameraHost::SetCallback(const sptr<HDI::Camera::V1_0::ICameraHostCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        DHLOGE("DCameraHost::SetCallback, input camera host callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }
    std::lock_guard<std::mutex> autoLock(deviceMapLock_);
    dCameraHostCallback_ = callbackObj;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::SetCallback_V1_2(const sptr<HDI::Camera::V1_2::ICameraHostCallback> &callbackObj)
{
    if (callbackObj == nullptr) {
        DHLOGE("DCameraHost::SetCallback_V1_2, input camera host callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }
    std::lock_guard<std::mutex> autoLock(deviceMapLock_);
    dCameraHostCallback_V1_2_ = callbackObj;
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::GetCameraIds(std::vector<std::string> &cameraIds)
{
    std::lock_guard<std::mutex> autoLock(deviceMapLock_);
    auto iter = dCameraDeviceMap_.begin();
    while (iter != dCameraDeviceMap_.end()) {
        if (!(iter->first).empty()) {
            cameraIds.push_back(iter->first);
        }
        iter++;
    }
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::GetCameraAbilityFromDev(const std::string &cameraId, std::shared_ptr<CameraAbility> &cameraAbility)
{
    OHOS::sptr<DCameraDevice> device = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(deviceMapLock_);
        auto iter = dCameraDeviceMap_.find(cameraId);
        if (iter == dCameraDeviceMap_.end() || iter->second == nullptr) {
            DHLOGE("DCameraHost::Get Cameradevice failed");
            return CamRetCode::INVALID_ARGUMENT;
        } else {
            device = iter->second;
        }
    }
    if (device->GetDCameraAbility(cameraAbility) != CamRetCode::NO_ERROR) {
        DHLOGE("DCameraHost::GetCameraAbilityFromDev, GetDCameraAbility failed.");
        return CamRetCode::INVALID_ARGUMENT;
    }
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::GetCameraAbility(const std::string &cameraId, std::vector<uint8_t> &cameraAbility)
{
    if (IsCameraIdInvalid(cameraId)) {
        DHLOGE("DCameraHost::GetCameraAbility, input cameraId is invalid.");
        return CamRetCode::INVALID_ARGUMENT;
    }
    DHLOGI("DCameraHost::GetCameraAbility for cameraId: %{public}s", GetAnonyString(cameraId).c_str());
    std::shared_ptr<CameraAbility> ability;
    int32_t ret = GetCameraAbilityFromDev(cameraId, ability);
    if (ret != CamRetCode::NO_ERROR) {
        DHLOGE("DCameraHost::GetCameraAbility, GetCameraAbilityFromDev failed.");
        return CamRetCode::INVALID_ARGUMENT;
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
        DHLOGI("FindCameraMetadataItem item=%{public}u, count=%{public}u, dataType=%{public}u", item.item,
            item.count, item.data_type);
        if (ret != CAM_META_SUCCESS) {
            DHLOGE("Failed to find stream configuration in camera ability with return code %{public}d", ret);
            break;
        }
        if (item.count % UNIT_LENGTH != 0) {
            DHLOGE("Invalid stream configuration count: %{public}u", item.count);
            break;
        }
        for (uint32_t index = 0; index < item.count; index += UNIT_LENGTH) {
            if (item.data.i32 == nullptr) {
                DHLOGE("Invalid stream configuration data");
                continue;
            }
            int32_t format = item.data.i32[index];
            int32_t width = item.data.i32[index + WIDTH_OFFSET];
            int32_t height = item.data.i32[index + HEIGHT_OFFSET];
            DHLOGD("format: %{public}d, width: %{public}d, height: %{public}d", format, width, height);
        }
    } while (0);
    return CamRetCode::NO_ERROR;
}

template<typename Callback, typename Device>
int32_t DCameraHost::OpenCameraImpl(const std::string &cameraId, const Callback &callbackObj, Device &device)
{
    if (IsCameraIdInvalid(cameraId) || callbackObj == nullptr) {
        DHLOGE("OpenCameraImpl, open camera id is invalid or camera device callback is null.");
        return CamRetCode::INVALID_ARGUMENT;
    }

    DHLOGI("OpenCameraImpl for cameraId: %{public}s", GetAnonyString(cameraId).c_str());

    OHOS::sptr<DCameraDevice> dcameraDevice = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(deviceMapLock_);
        auto iter = dCameraDeviceMap_.find(cameraId);
        if (iter == dCameraDeviceMap_.end()) {
            DHLOGE("OpenCameraImpl, dcamera device not found.");
            return CamRetCode::INSUFFICIENT_RESOURCES;
        }

        dcameraDevice = iter->second;
        if (dcameraDevice == nullptr) {
            DHLOGE("OpenCameraImpl, dcamera device is null.");
            return INSUFFICIENT_RESOURCES;
        }
    }

    if (dcameraDevice->IsOpened()) {
        DHLOGE("OpenCameraImpl, dcamera device %{public}s already opened.", GetAnonyString(cameraId).c_str());
        return CamRetCode::CAMERA_BUSY;
    }

    CamRetCode ret = dcameraDevice->OpenDCamera(callbackObj);
    if (ret != CamRetCode::NO_ERROR) {
        DHLOGE("OpenCameraImpl, open camera failed.");
        return ret;
    }
    device = dcameraDevice;

    DHLOGI("OpenCameraImpl, open camera %{public}s success.", GetAnonyString(cameraId).c_str());
    return CamRetCode::NO_ERROR;
}

int32_t DCameraHost::OpenCamera(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
    sptr<HDI::Camera::V1_0::ICameraDevice> &device)
{
    return OpenCameraImpl(cameraId, callbackObj, device);
}

int32_t DCameraHost::OpenCamera_V1_1(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
    sptr<HDI::Camera::V1_1::ICameraDevice> &device)
{
    return OpenCameraImpl(cameraId, callbackObj, device);
}

int32_t DCameraHost::OpenCamera_V1_2(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
    sptr<HDI::Camera::V1_2::ICameraDevice> &device)
{
    return OpenCameraImpl(cameraId, callbackObj, device);
}

int32_t DCameraHost::OpenCamera_V1_3(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
    sptr<ICameraDevice> &device)
{
    return OpenCameraImpl(cameraId, callbackObj, device);
}

int32_t DCameraHost::OpenSecureCamera(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
    sptr<ICameraDevice> &device)
{
    return OpenCameraImpl(cameraId, callbackObj, device);
}

int32_t DCameraHost::GetResourceCost(const std::string &cameraId,
    OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost &resourceCost)
{
    (void)cameraId;
    (void)resourceCost;
    return CamRetCode::METHOD_NOT_SUPPORTED;
}

int32_t DCameraHost::NotifyDeviceStateChangeInfo(int notifyType, int deviceState)
{
    (void)notifyType;
    (void)deviceState;
    DHLOGI("DCameraHost::NotifyDeviceStateChangeInfo, distributed camera not support.");

    return CamRetCode::METHOD_NOT_SUPPORTED;
}

int32_t DCameraHost::SetFlashlight(const std::string &cameraId, bool isEnable)
{
    (void)cameraId;
    (void)isEnable;
    DHLOGI("DCameraHost::SetFlashlight, distributed camera not support.");

    return CamRetCode::METHOD_NOT_SUPPORTED;
}

int32_t DCameraHost::SetFlashlight_V1_2(float level)
{
    (void)level;
    DHLOGI("DCameraHost::SetFlashlight_V1_2, distributed camera not support.");

    return CamRetCode::METHOD_NOT_SUPPORTED;
}

int32_t DCameraHost::PreCameraSwitch(const std::string &cameraId)
{
    (void)cameraId;
    DHLOGI("DCameraHost::PreCameraSwitch, distributed camera not support.");

    return CamRetCode::METHOD_NOT_SUPPORTED;
}

int32_t DCameraHost::PrelaunchWithOpMode(const PrelaunchConfig &config, int32_t operationMode)
{
    (void)config;
    (void)operationMode;
    DHLOGI("DCameraHost::PrelaunchWithOpMode, distributed camera not support.");

    return CamRetCode::METHOD_NOT_SUPPORTED;
}

int32_t DCameraHost::Prelaunch(const PrelaunchConfig &config)
{
    (void)config;
    DHLOGI("DCameraHost::Prelaunch, distributed camera not support.");

    return CamRetCode::METHOD_NOT_SUPPORTED;
}

DCamRetCode DCameraHost::AddDeviceParamCheck(const DHBase &dhBase, const std::string& sinkAbilityInfo,
    const std::string &sourceCodecInfo, const sptr<IDCameraProviderCallback> &callback)
{
    if (IsDhBaseInfoInvalid(dhBase)) {
        DHLOGE("DCameraHost::AddDCameraDevice, devId or dhId is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    DHLOGI("DCameraHost::AddDCameraDevice for {devId: %{public}s, dhId: %{public}s}",
        GetAnonyString(dhBase.deviceId_).c_str(), GetAnonyString(dhBase.dhId_).c_str());

    if (sinkAbilityInfo.empty() || sinkAbilityInfo.length() > ABILITYINFO_MAX_LENGTH) {
        DHLOGE("DCameraHost::AddDCameraDevice, input sinkAbilityInfo is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    if (sourceCodecInfo.empty() || sourceCodecInfo.length() > ABILITYINFO_MAX_LENGTH) {
        DHLOGE("DCameraHost::AddDCameraDevice, input sourceCodecInfo is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (GetCamDevNum() > MAX_DCAMERAS_NUMBER) {
        DHLOGE("DCameraHost::AddDCameraDevice, cameras exceed the upper limit.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraHost::AddDCameraDevice(const DHBase &dhBase, const std::string& sinkAbilityInfo,
    const std::string &sourceCodecInfo, const sptr<IDCameraProviderCallback> &callback)
{
    if (AddDeviceParamCheck(dhBase, sinkAbilityInfo, sourceCodecInfo, callback) != DCamRetCode::SUCCESS) {
        DHLOGE("DCameraHost::AddDCameraDevice, input param is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    std::string dCameraId = dhBase.deviceId_ + "__" + dhBase.dhId_;

    std::optional<DCamRetCode> refreshStatus = HandleExistingDCamera(dCameraId, sinkAbilityInfo);
    if (refreshStatus.has_value()) {
        return refreshStatus.value();
    }
    return HandleNewDCamera(dhBase, sinkAbilityInfo, sourceCodecInfo, callback);
}

std::optional<DCamRetCode> DCameraHost::HandleExistingDCamera(const std::string& dCameraId,
    const std::string& sinkAbilityInfo)
{
    std::lock_guard<std::mutex> autoLock(deviceMapLock_);
    auto iter = dCameraDeviceMap_.find(dCameraId);
    if (iter == dCameraDeviceMap_.end()) {
        return std::nullopt;
    }
    if (iter->second == nullptr) {
        DHLOGI("AddDCameraDevice device is null");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    iter->second->SetDcameraAbility(sinkAbilityInfo);
    DHLOGI("AddDCameraDevice refresh data success");
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraHost::HandleNewDCamera(const DHBase &dhBase, const std::string& sinkAbilityInfo,
    const std::string &sourceCodecInfo, const sptr<IDCameraProviderCallback> &callback)
{
    std::string dCameraId = dhBase.deviceId_ + "__" + dhBase.dhId_;
    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo,
        sourceCodecInfo));
    if (dcameraDevice == nullptr) {
        DHLOGE("DCameraHost::AddDCameraDevice, create dcamera device failed.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    {
        std::lock_guard<std::mutex> autoLock(deviceMapLock_);
        dCameraDeviceMap_[dCameraId] = dcameraDevice;
    }
    if (callback == nullptr) {
        DHLOGE("DCameraHost::SetProviderCallback failed, callback is null");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    dcameraDevice->SetProviderCallback(callback);
    sptr<HDI::Camera::V1_0::ICameraHostCallback> callback_v1_0 = nullptr;
    sptr<HDI::Camera::V1_2::ICameraHostCallback> callback_v1_2 = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(deviceMapLock_);
        callback_v1_0 = dCameraHostCallback_;
        callback_v1_2 = dCameraHostCallback_V1_2_;
    }
    if (callback_v1_0 != nullptr) {
        callback_v1_0->OnCameraEvent(dCameraId, CameraEvent::CAMERA_EVENT_DEVICE_ADD);
    }
    if (callback_v1_2 != nullptr) {
        callback_v1_2->OnCameraEvent(dCameraId, CameraEvent::CAMERA_EVENT_DEVICE_ADD);
    }
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<IDCameraProviderCallback>(callback);
    if (remote != nullptr) {
        AddClearRegisterRecipient(remote, dhBase);
    }
    DHLOGI("AddDCameraDevice create dcamera device success, dCameraId: %{public}s", GetAnonyString(dCameraId).c_str());
    return DCamRetCode::SUCCESS;
}

size_t DCameraHost::GetCamDevNum()
{
    std::lock_guard<std::mutex> autoLock(deviceMapLock_);
    return dCameraDeviceMap_.size();
}

DCamRetCode DCameraHost::RemoveDCameraDevice(const DHBase &dhBase)
{
    DHLOGI("DCameraHost::RemoveDCameraDevice for {devId: %{public}s, dhId: %{public}s}",
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
        sptr<IDCameraProviderCallback> callback = dcameraDevice->GetProviderCallback();
        if (callback != nullptr) {
            sptr<IRemoteObject> remoteObj = OHOS::HDI::hdi_objcast<IDCameraProviderCallback>(callback);
            if (remoteObj != nullptr) {
                RemoveClearRegisterRecipient(remoteObj, dhBase);
            }
        }
    }
    {
        std::lock_guard<std::mutex> autoLock(deviceMapLock_);
        dCameraDeviceMap_.erase(dCameraId);
    }
    sptr<HDI::Camera::V1_0::ICameraHostCallback> callback_v1_0 = nullptr;
    sptr<HDI::Camera::V1_2::ICameraHostCallback> callback_v1_2 = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(deviceMapLock_);
        callback_v1_0 = dCameraHostCallback_;
        callback_v1_2 = dCameraHostCallback_V1_2_;
    }
    if (callback_v1_0 != nullptr) {
        callback_v1_0->OnCameraEvent(dCameraId, CameraEvent::CAMERA_EVENT_DEVICE_RMV);
    }

    if (callback_v1_2 != nullptr) {
        callback_v1_2->OnCameraEvent(dCameraId, CameraEvent::CAMERA_EVENT_DEVICE_RMV);
    }
    DHLOGI("DCameraHost::RemoveDCameraDevice, remove dcamera device success, dCameraId: %{public}s",
        GetAnonyString(dCameraId).c_str());
    return DCamRetCode::SUCCESS;
}

bool DCameraHost::IsCameraIdInvalid(const std::string &cameraId)
{
    if (cameraId.empty() || cameraId.length() > ID_MAX_SIZE) {
        return true;
    }

    std::lock_guard<std::mutex> autoLock(deviceMapLock_);
    auto iter = dCameraDeviceMap_.begin();
    while (iter != dCameraDeviceMap_.end()) {
        if (cameraId == iter->first) {
            return false;
        }
        iter++;
    }
    return true;
}

std::string DCameraHost::GetCameraIdByDHBase(const DHBase &dhBase)
{
    std::string dcameraId = dhBase.deviceId_ + "__" + dhBase.dhId_;
    return dcameraId;
}

OHOS::sptr<DCameraDevice> DCameraHost::GetDCameraDeviceByDHBase(const DHBase &dhBase)
{
    std::string dCameraId = GetCameraIdByDHBase(dhBase);
    if (dCameraId.empty()) {
        DHLOGE("DCameraHost::GetDCameraDeviceByDHBase, dhBase not exist.");
        return nullptr;
    }

    std::lock_guard<std::mutex> autoLock(deviceMapLock_);
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
    sptr<HDI::Camera::V1_0::ICameraHostCallback> callback_v1_0 = nullptr;
    sptr<HDI::Camera::V1_2::ICameraHostCallback> callback_v1_2 = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(deviceMapLock_);
        callback_v1_0 = dCameraHostCallback_;
        callback_v1_2 = dCameraHostCallback_V1_2_;
    }
    if (callback_v1_0 != nullptr) {
        callback_v1_0->OnCameraStatus(dCameraId, CameraStatus::UN_AVAILABLE);
    }
    if (callback_v1_2 != nullptr) {
        callback_v1_2->OnCameraStatus(dCameraId, CameraStatus::UN_AVAILABLE);
    }
}

//LCOV_EXCL_START
DCamRetCode DCameraHost::RegisterCameraHdfListener(const std::string &serviceName,
    const sptr<IDCameraHdfCallback> &callbackObj)
{
    DHLOGI("Register camera HDF listener, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    if (callbackObj == nullptr) {
        DHLOGE("dcamera hdf callback is null.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<IDCameraHdfCallback>(callbackObj);
    if (remote == nullptr) {
        DHLOGE("Remote callback is nullptr.");
        return DCamRetCode::FAILED;
    }
    if (dCameraHostRecipient_ == nullptr) {
        DHLOGE("dcamera host recipient is null.");
        return DCamRetCode::FAILED;
    }
    if (!remote->AddDeathRecipient(dCameraHostRecipient_)) {
        DHLOGE("AddDeathRecipient failed, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
        return DCamRetCode::FAILED;
    }
    std::lock_guard<std::mutex> lock(hdfCallbackMapMtx_);
    if (mapCameraHdfCallback_.find(serviceName) != mapCameraHdfCallback_.end()) {
        DHLOGI("The callback has been registered and will be replaced, serviceName: %{public}s.",
            GetAnonyString(serviceName).c_str());
    }
    mapCameraHdfCallback_[serviceName] = callbackObj;
    DHLOGI("Register camera HDF listener suncess, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    return DCamRetCode::SUCCESS;
}
//LCOV_EXCL_STOP

DCamRetCode DCameraHost::UnRegisterCameraHdfListener(const std::string &serviceName)
{
    DHLOGI("Unregister camera HDF listener, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    std::lock_guard<std::mutex> lock(hdfCallbackMapMtx_);
    auto itCallback = mapCameraHdfCallback_.find(serviceName);
    if (itCallback == mapCameraHdfCallback_.end() || itCallback->second == nullptr) {
        DHLOGE("Camera HDF callback has not been created or is null ptr.");
        return DCamRetCode::FAILED;
    }
    sptr<IRemoteObject> remote = OHOS::HDI::hdi_objcast<IDCameraHdfCallback>(itCallback->second);
    if (remote == nullptr) {
        DHLOGE("Remote callback is nullptr.");
        return DCamRetCode::FAILED;
    }
    if (!remote->RemoveDeathRecipient(dCameraHostRecipient_)) {
        DHLOGE("RemoveDeathRecipient failed, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
        return DCamRetCode::FAILED;
    }
    mapCameraHdfCallback_.erase(itCallback);
    DHLOGI("Unregister camera HDF listener suncess, serviceName: %{public}s.", GetAnonyString(serviceName).c_str());
    return DCamRetCode::SUCCESS;
}

//LCOV_EXCL_START
void DCameraHost::ClearRegisterRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    DHLOGI("Remote died, remote dcamera device begin.");
    auto dCameraHost = DCameraHost::GetInstance();
    if (dCameraHost != nullptr) {
        dCameraHost->RemoveDCameraDevice(dhBase_);
    }
    needErase_ = true;
    DHLOGI("Remote died, remote dcamera device end.");
}

void DCameraHost::DCameraHostRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    DHLOGE("Exit the current process.");
    _Exit(0);
}
//LCOV_EXCL_STOP

int32_t DCameraHost::AddClearRegisterRecipient(sptr<IRemoteObject> &remote, const DHBase &dhBase)
{
    DHLOGI("add clear register recipient begin.");
    auto clearRegisterRecipient = sptr<ClearRegisterRecipient>(new ClearRegisterRecipient(dhBase));
    if (clearRegisterRecipient == nullptr) {
        DHLOGE("Create clear register recipient object failed.");
        return DCamRetCode::FAILED;
    }
    if (remote != nullptr && remote->AddDeathRecipient(clearRegisterRecipient) == false) {
        DHLOGE("call AddDeathRecipient failed.");
        return DCamRetCode::FAILED;
    }
    std::lock_guard<std::mutex> lock(clearRegisterRecipientsMtx_);
    clearRegisterRecipients_.erase(std::remove_if(clearRegisterRecipients_.begin(), clearRegisterRecipients_.end(),
        [](sptr<ClearRegisterRecipient> &clearRegisterRecipient) {
            return clearRegisterRecipient->IsNeedErase();
        }), clearRegisterRecipients_.end());
    clearRegisterRecipients_.push_back(clearRegisterRecipient);
    DHLOGI("add clear register recipient end.");
    return DCamRetCode::SUCCESS;
}

int32_t DCameraHost::RemoveClearRegisterRecipient(sptr<IRemoteObject> &remote, const DHBase &dhBase)
{
    DHLOGI("remove clear register recipient begin.");
    std::lock_guard<std::mutex> lock(clearRegisterRecipientsMtx_);
    for (auto itRecipient = clearRegisterRecipients_.begin();
        itRecipient != clearRegisterRecipients_.end(); ++itRecipient) {
        auto &clearRegisterRecipient = *itRecipient;
        if (clearRegisterRecipient->IsMatch(dhBase)) {
            if (remote != nullptr && remote->RemoveDeathRecipient(clearRegisterRecipient) == false) {
                DHLOGE("call RemoveDeathRecipient failed.");
            }
            clearRegisterRecipients_.erase(itRecipient);
            DHLOGI("remove one clear register recipient.");
            break;
        }
    }
    DHLOGI("remove clear register recipient end.");
    return DCamRetCode::SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
