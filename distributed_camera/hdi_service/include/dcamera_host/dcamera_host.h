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

#ifndef DISTRIBUTED_CAMERA_HOST_H
#define DISTRIBUTED_CAMERA_HOST_H

#include "dcamera_base.h"
#include "dcamera_device.h"

#include "v1_0/icamera_host.h"
#include "v1_0/icamera_host_callback.h"
#include "v1_0/dcamera_types.h"
#include "v1_0/types.h"
#include "constants.h"
#include "iremote_object.h"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::DistributedCamera::V1_0;
using namespace OHOS::HDI::Camera::V1_0;
class DCameraHost : public ICameraHost {
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
    int32_t SetCallback(const sptr<ICameraHostCallback> &callbackObj) override;
    int32_t GetCameraIds(std::vector<std::string> &cameraIds) override;
    int32_t GetCameraAbility(const std::string &cameraId, std::vector<uint8_t> &cameraAbility) override;
    int32_t OpenCamera(const std::string &cameraId, const sptr<ICameraDeviceCallback> &callbackObj,
         sptr<ICameraDevice> &device) override;
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

private:
    bool IsCameraIdInvalid(const std::string &cameraId);
    std::string GetCameraIdByDHBase(const DHBase &dhBase);
    size_t GetCamDevNum();

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
    class DCameraHostRecipient : public IRemoteObject::DeathRecipient {
    public:
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
    sptr<DCameraHostRecipient> dCameraHostRecipient_;
    static AutoRelease autoRelease_;
    static OHOS::sptr<DCameraHost> instance_;

    OHOS::sptr<ICameraHostCallback> dCameraHostCallback_;
    std::map<std::string, OHOS::sptr<DCameraDevice>> dCameraDeviceMap_;
    std::mutex deviceMapLock_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DISTRIBUTED_CAMERA_HOST_H