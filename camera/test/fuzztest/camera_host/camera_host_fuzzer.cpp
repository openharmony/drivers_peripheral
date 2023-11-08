/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "camera_host_fuzzer.h"
#include "camera.h"

namespace OHOS {
const size_t THRESHOLD = 10;

enum HostCmdId {
    CAMERA_HOST_PRELAUNCH,
    CAMERA_HOST_GET_CAMERA_ABILITY,
    CAMERA_HOST_OPEN_CAMERA,
    CAMERA_HOST_OPEN_CAMERA_V1_1,
    CAMERA_HOST_SET_FLASH_LIGHTS,
    CAMERA_HOST_SET_FLASH_LIGHTS_V1_2,
    CAMERA_HOST_NOTIFY_DEVICE_STATE_CHANGE_INFO,
    CAMERA_HOST_END, // Enumerated statistical value. The new enumerated value is added before
};

void FuncPrelaunch(const uint8_t *rawData, size_t size)
{
    if (size < sizeof(struct HDI::Camera::V1_1::PrelaunchConfig)) {
        return;
    }
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = const_cast<char*>(reinterpret_cast<const char*>(rawData));
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting.push_back(*rawData);
    cameraTest->serviceV1_2->Prelaunch(*cameraTest->prelaunchConfig);
}

void FuncGetCameraAbility(const uint8_t *rawData, size_t size)
{
    cameraTest->serviceV1_2->GetCameraAbility(const_cast<char*>(reinterpret_cast<const char*>(rawData)),
        cameraTest->abilityVec);
}

void FuncOpenCamera(const uint8_t *rawData, size_t size)
{
    sptr<HDI::Camera::V1_0::ICameraDevice> g_CameraDevice = nullptr;
    const sptr<HDI::Camera::V1_0::ICameraDeviceCallback> callback =
        new Camera::CameraManager::DemoCameraDeviceCallback();
    cameraTest->serviceV1_2->OpenCamera(
        const_cast<char*>(reinterpret_cast<const char*>(rawData)), callback, g_CameraDevice);
}

void FuncOpenCamera_V1_1(const uint8_t *rawData, size_t size)
{
    sptr<HDI::Camera::V1_1::ICameraDevice> g_CameraDevice = nullptr;
    const sptr<HDI::Camera::V1_0::ICameraDeviceCallback> callback =
        new Camera::CameraManager::DemoCameraDeviceCallback();
    cameraTest->serviceV1_2->OpenCamera_V1_1(
        const_cast<char*>(reinterpret_cast<const char*>(rawData)), callback, g_CameraDevice);
}

void FuncSetFlashlight(const uint8_t *rawData, size_t size)
{
    cameraTest->serviceV1_2->SetFlashlight(
        const_cast<char*>(reinterpret_cast<const char*>(rawData)), true);
}

void FuncSetFlashlightV1_2(const uint8_t *rawData, size_t size)
{
    float *level = const_cast<float*>(reinterpret_cast<const float*>(rawData));
    cameraTest->serviceV1_2->SetFlashlightV1_2(*level);
}

void FuncNotifyDeviceStateChangeInfo(const uint8_t *rawData, size_t size)
{
    int *data = const_cast<int *>(reinterpret_cast<const int *>(rawData));
    cameraTest->serviceV1_2->NotifyDeviceStateChangeInfo(data[0], data[1]);
}

static void HostFuncSwitch(uint32_t cmd, const uint8_t *rawData, size_t size)
{
    switch (cmd) {
        case CAMERA_HOST_PRELAUNCH: {
            FuncPrelaunch(rawData, size);
            break;
        }
        case CAMERA_HOST_GET_CAMERA_ABILITY: {
            FuncGetCameraAbility(rawData, size);
            break;
        }
        case CAMERA_HOST_OPEN_CAMERA: {
            FuncOpenCamera(rawData, size);
            break;
        }
        case CAMERA_HOST_OPEN_CAMERA_V1_1: {
            FuncOpenCamera_V1_1(rawData, size);
            break;
        }
        case CAMERA_HOST_SET_FLASH_LIGHTS: {
            FuncSetFlashlight(rawData, size);
            break;
        }
        case CAMERA_HOST_SET_FLASH_LIGHTS_V1_2: {
            FuncSetFlashlightV1_2(rawData, size);
            break;
        }
        case CAMERA_HOST_NOTIFY_DEVICE_STATE_CHANGE_INFO: {
            FuncNotifyDeviceStateChangeInfo(rawData, size);
            break;
        }
        default:
            return;
    }
}

bool DoSomethingInterestingWithMyApi(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    uint32_t cmd = 0;
    rawData += sizeof(cmd);

    cameraTest = std::make_shared<OHOS::Camera::CameraManager>();
    cameraTest->InitV1_2();
    if (cameraTest->serviceV1_2 == nullptr) {
        return false;
    }
    cameraTest->OpenV1_2();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return false;
    }

    for (cmd = 0; cmd < CAMERA_HOST_END; cmd++) {
        HostFuncSwitch(cmd, rawData, size);
    }
    cameraTest->Close();
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyApi(data, size);
    return 0;
}
} // namespace OHOS
