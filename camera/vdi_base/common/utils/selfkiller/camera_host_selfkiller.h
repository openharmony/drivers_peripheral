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

#ifndef CAMERA_HOST_SELFKILL_H
#define CAMERA_HOST_SELFKILL_H
#include "thread"
#include "stdint.h"
#include "functional"
#include "string"
namespace OHOS::Camera {

class CameraHostSelfkiller {
public:
    CameraHostSelfkiller(uint8_t sleepInteral_ = 3, uint32_t noCameraForExitMaxTimeSecond_ = 30);
    ~CameraHostSelfkiller();
    void Init(std::function<bool(void)> canBeKilledFn, std::function<void(void)> killerTimeoutCb = nullptr,
        std::string selfKillParamName = DEFAULT_SELF_KILL_PARAM_NAME,
        std::string cameraServiceName = DEFAULT_CAMERA_SERVICE_NAME);
    void DeInit();
    static void UnloadHdfServiceByName(const std::string &serviceName);

private:
    std::thread *selfKillerThread_ = nullptr;
    bool selfKillerThreadLoopFlag_ = false;
    std::string selfKillParamName_ = "";
    std::string cameraServiceName_ = "";
    std::function<void(void)> killerTimeoutCb_ = nullptr;
    std::function<bool(void)> canBeKilledFn_ = nullptr;
    void CameraHostSelfkillerHandler();
    static constexpr const char *DEFAULT_SELF_KILL_PARAM_NAME = "const.camera.setting.selfkill.enable";
    static constexpr const char *DEFAULT_CAMERA_SERVICE_NAME = "camera_service_usb";
    uint8_t sleepInteral_ = 3;
    uint32_t noCameraForExitMaxTimeSecond_ = 30;
};  // class CameraHostSelfkiller
};  // namespace OHOS::Camera
#endif