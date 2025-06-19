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

#ifndef DISTRIBUTED_CAMERA_HOST_H
#define DISTRIBUTED_CAMERA_HOST_H

#include "dcamera_base.h"
#include "dcamera_device.h"

#include "v1_0/icamera_host.h"
#include "v1_3/icamera_host.h"
#include "v1_0/icamera_device_callback.h"
#include "v1_0/icamera_host_callback.h"
#include "v1_2/icamera_host_callback.h"
#include "v1_1/dcamera_types.h"
#include "v1_1/id_camera_provider.h"
#include "v1_0/types.h"
#include "v1_2/types.h"
#include "constants.h"
#include "iremote_object.h"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::DistributedCamera::V1_1;
using HDI::Camera::V1_3::ICameraDevice;
using HDI::Camera::V1_0::ICameraDeviceCallback;
using HDI::Camera::V1_0::FlashlightStatus;
using HDI::Camera::V1_0::CameraStatus;
using HDI::Camera::V1_3::ICameraHost;
using HDI::Camera::V1_1::PrelaunchConfig;
class DCameraHost : public OHOS::HDI::Camera::V1_3::ICameraHost {
const uint32_t ABILITYINFO_MAX_LENGTH = 50 * 1024 * 1024;
const uint32_t ID_MAX_SIZE = 2 * DEVID_MAX_LENGTH;
const size_t MAX_DCAMERAS_NUMBER = 32;
public:
    DCameraHost() = default;
    ~DCameraHost() override = default;
    DCameraHost(const DCameraHost &other) = delete;
    DCameraHost(DCameraHost &&other) = delete;
    DCameraHost& operator=(const DCameraHost &other) = delete;
    DCameraHost& operator=(DCameraHost &&other) = delete;

public:
    static OHOS::sptr<DCameraHost> GetInstance();

    int32_t OpenCamera_V1_3(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
        sptr<ICameraDevice> &device) override;
    int32_t OpenSecureCamera(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
        sptr<ICameraDevice> &device) override;
    int32_t GetResourceCost(const std::string &cameraId,
        OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost &resourceCost) override;

    int32_t OpenCamera_V1_2(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
        sptr<HDI::Camera::V1_2::ICameraDevice> &device) override;
    int32_t NotifyDeviceStateChangeInfo(int notifyType, int deviceState) override;
    int32_t SetCallback_V1_2(const sptr<HDI::Camera::V1_2::ICameraHostCallback> &callbackObj) override;
    int32_t SetFlashlight_V1_2(float level) override;
    int32_t PreCameraSwitch(const std::string &cameraId) override;
    int32_t PrelaunchWithOpMode(const PrelaunchConfig &config, int32_t operationMode) override;

    int32_t OpenCamera_V1_1(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
        sptr<HDI::Camera::V1_1::ICameraDevice> &device) override;
    int32_t Prelaunch(const PrelaunchConfig &config) override;

    int32_t SetCallback(const sptr<HDI::Camera::V1_0::ICameraHostCallback> &callbackObj) override;
    int32_t GetCameraIds(std::vector<std::string> &cameraIds) override;
    int32_t GetCameraAbility(const std::string &cameraId, std::vector<uint8_t> &cameraAbility) override;
    int32_t OpenCamera(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
        sptr<HDI::Camera::V1_0::ICameraDevice> &device) override;
    int32_t SetFlashlight(const std::string &cameraId, bool isEnable) override;
    int32_t GetCameraAbilityFromDev(const std::string &cameraId,
        std::shared_ptr<CameraAbility> &cameraAbility);
    DCamRetCode AddDCameraDevice(const DHBase &dhBase, const std::string &sinkAbilityInfo,
        const std::string &sourceCodecInfo, const sptr<IDCameraProviderCallback> &callback);
    DCamRetCode AddDeviceParamCheck(const DHBase &dhBase, const std::string &sinkAbilityInfo,
        const std::string &sourceCodecInfo, const sptr<IDCameraProviderCallback> &callback);
    DCamRetCode RemoveDCameraDevice(const DHBase &dhBase);
    OHOS::sptr<DCameraDevice> GetDCameraDeviceByDHBase(const DHBase &dhBase);
    void NotifyDCameraStatus(const DHBase &dhBase, int32_t result);
    DCamRetCode RegisterCameraHdfListener(const std::string &serviceName,
        const sptr<IDCameraHdfCallback> &callbackObj);
    DCamRetCode UnRegisterCameraHdfListener(const std::string &serviceName);

private:
    bool IsCameraIdInvalid(const std::string &cameraId);
    std::string GetCameraIdByDHBase(const DHBase &dhBase);
    size_t GetCamDevNum();
    void AddDcameraId(const DHBase &dhBase, std::string &cameraId, const std::string &dCameraId);
    std::string GetDcameraIdById(const std::string &cameraId);

    template<typename Callback, typename Device>
    int32_t OpenCameraImpl(const std::string &cameraId, const Callback &callbackObj, Device &device);
    int32_t AddClearRegisterRecipient(sptr<IRemoteObject> &remote, const DHBase &dhBase);
    int32_t RemoveClearRegisterRecipient(sptr<IRemoteObject> &remote, const DHBase &dhBase);

private:
    class AutoRelease {
    public:
        AutoRelease() {}
        ~AutoRelease()
        {
            if (DCameraHost::instance_ != nullptr) {
                DCameraHost::instance_ = nullptr;
            }
        }
    };
    class ClearRegisterRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit ClearRegisterRecipient(const DHBase &dhBase)
            : dhBase_(dhBase)
        {
        }
        bool IsNeedErase()
        {
            return needErase_;
        }
        bool IsMatch(const DHBase &dhBase)
        {
            return (dhBase.deviceId_ == dhBase_.deviceId_) && (dhBase.dhId_ == dhBase_.dhId_);
        }
    protected:
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        DHBase dhBase_;
        bool needErase_ = false;
    };
    std::mutex clearRegisterRecipientsMtx_;
    std::vector<sptr<ClearRegisterRecipient>> clearRegisterRecipients_;
    class DCameraHostRecipient : public IRemoteObject::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    sptr<DCameraHostRecipient> dCameraHostRecipient_;
    static AutoRelease autoRelease_;
    static OHOS::sptr<DCameraHost> instance_;

    OHOS::sptr<HDI::Camera::V1_0::ICameraHostCallback> dCameraHostCallback_;
    OHOS::sptr<HDI::Camera::V1_2::ICameraHostCallback> dCameraHostCallback_V1_2_;
    std::map<std::string, OHOS::sptr<DCameraDevice>> dCameraDeviceMap_;
    std::mutex deviceMapLock_;
    std::map<std::string, std::string> dCameraIdMap_;
    std::mutex dCameraIdMapLock_;
    std::map<std::string, sptr<IDCameraHdfCallback>> mapCameraHdfCallback_;
    std::mutex hdfCallbackMapMtx_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DISTRIBUTED_CAMERA_HOST_H