/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "camera_host_selfkiller.h"
#include "idevmgr_hdi.h"
#include "parameters.h"
#include "camera.h"
namespace OHOS::Camera {
CameraHostSelfkiller::CameraHostSelfkiller(uint8_t sleepInteral, uint32_t noCameraForExitMaxTimeSecond)
    : sleepInteral_(sleepInteral), noCameraForExitMaxTimeSecond_(noCameraForExitMaxTimeSecond)
{
    CAMERA_LOGD("Ctor, instance");
}
CameraHostSelfkiller::~CameraHostSelfkiller()
{
    CAMERA_LOGD("Dtor, instance");
}

void CameraHostSelfkiller::Init(std::function<bool(void)> canBeKilledFn, std::function<void(void)> killerTimeoutCb,
    std::string selfKillParamName, std::string cameraServiceName)
{
    if (selfKillerThread_ != nullptr) {
        CAMERA_LOGE("CameraHostSelfkiller::Init failed, resaon: alreay inited");
        return;
    }
    killerTimeoutCb_ = killerTimeoutCb;
    canBeKilledFn_ = canBeKilledFn;
    selfKillParamName_ = selfKillParamName;
    cameraServiceName_ = cameraServiceName;
    selfKillerThreadLoopFlag_ = true;
    selfKillerThread_ = new std::thread([this] { CameraHostSelfkillerHandler(); });
}

void CameraHostSelfkiller::DeInit()
{
    CAMERA_LOGD("CameraHostSelfkiller::DeInit");
    selfKillerThreadLoopFlag_ = false;
    if (selfKillerThread_ != nullptr && selfKillerThread_->joinable()) {
        selfKillerThread_->join();
        selfKillerThread_ = nullptr;
    }
}

void CameraHostSelfkiller::UnloadHdfServiceByName(const std::string &serviceName)
{
    int32_t ret = 0;
    CAMERA_LOGI("begin unload %{public}s", serviceName.c_str());
    OHOS::sptr<HDI::DeviceManager::V1_0::IDeviceManager> devMgr = HDI::DeviceManager::V1_0::IDeviceManager::Get();
    if (devMgr == nullptr) {
        CAMERA_LOGE("get devMgr object failed");
        return;
    }
    ret = devMgr->UnloadDevice(serviceName);
    if (ret != 0) {
        CAMERA_LOGE("%{public}s unload failed", serviceName.c_str());
        return;
    }
    CAMERA_LOGI("unload %{public}s sucess", serviceName.c_str());
}

void CameraHostSelfkiller::CameraHostSelfkillerHandler()
{
    uint32_t noCameraForExitMax = noCameraForExitMaxTimeSecond_ / sleepInteral_;
    uint32_t count = 0;
    if (selfKillParamName_ != "") {
        bool isEnableSelfKill = OHOS::system::GetBoolParameter(selfKillParamName_.c_str(), false);
        if (!isEnableSelfKill) {
            CAMERA_LOGI("%{public}s is false, no need to selfkill", selfKillParamName_.c_str());
            return;
        }
    }

    CAMERA_LOGI("CameraHostSelfkillerHandler Begin");
    while (selfKillerThreadLoopFlag_) {
        sleep(sleepInteral_);
        if (canBeKilledFn_ == nullptr) {
            CAMERA_LOGW("canBeKilledFn_ is nullptr, just break");
            break;
        }
        if (!canBeKilledFn_()) {
            CAMERA_LOGD("selfkill condition not matched");
            count = 0;
            continue;
        }
        CAMERA_LOGI("selfkill condition matched, timeout is %{public}us / %{public}us",
            count * sleepInteral_,
            noCameraForExitMaxTimeSecond_);
        if (count++ < noCameraForExitMax) {
            continue;
        }
        if (killerTimeoutCb_ != nullptr) {
            killerTimeoutCb_();
        }
        if (cameraServiceName_ != "") {
            CameraHostSelfkiller::UnloadHdfServiceByName(cameraServiceName_);
        }
        break;
    }
}

}  // namespace OHOS::Camera