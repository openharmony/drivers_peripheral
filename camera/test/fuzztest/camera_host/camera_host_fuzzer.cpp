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
    CAMERA_HOST_GET_CAMERA_IDS,
    CAMERA_HOST_GET_CAMERA_ABILITY,
    CAMERA_HOST_OPEN_CAMERA,
    CAMERA_HOST_OPEN_CAMERA_V1_1,
    CAMERA_HOST_SET_FLASH_LIGHTS,
};

enum BitOperat {
    INDEX_0 = 0,
    INDEX_1,
    INDEX_2,
    INDEX_3,
    MOVE_EIGHT_BITS = 8,
    MOVE_SIXTEEN_BITS = 16,
    MOVE_TWENTY_FOUR_BITS = 24,
};

static uint32_t ConvertUint32(const uint8_t *bitOperat)
{
    if (bitOperat == nullptr) {
        return 0;
    }

    return (bitOperat[INDEX_0] << MOVE_TWENTY_FOUR_BITS) | (bitOperat[INDEX_1] << MOVE_SIXTEEN_BITS) |
        (bitOperat[INDEX_2] << MOVE_EIGHT_BITS) | (bitOperat[INDEX_3]);
}

static void HostFuncSwitch(uint32_t cmd, const uint8_t *&rawData)
{
    switch (cmd) {
        case CAMERA_HOST_PRELAUNCH: {
            cameraTest->serviceV1_1->Prelaunch(reinterpret_cast<const HDI::Camera::V1_1::PrelaunchConfig &>(rawData));
            break;
        }
        case CAMERA_HOST_GET_CAMERA_IDS: {
            std::vector<std::string> cameraIds = {};
            std::string *data = const_cast<std::string *>(reinterpret_cast<const std::string *>(rawData));
            cameraIds.push_back(*data);
            cameraTest->serviceV1_1->GetCameraIds(cameraIds);
            break;
        }
        case CAMERA_HOST_GET_CAMERA_ABILITY: {
            std::vector<uint8_t> abilityVec = {};
            uint8_t *data = const_cast<uint8_t *>(rawData);
            abilityVec.push_back(*data);
            cameraTest->serviceV1_1->GetCameraAbility(*reinterpret_cast<const std::string *>(rawData), abilityVec);
            break;
        }
        case CAMERA_HOST_OPEN_CAMERA: {
            sptr<HDI::Camera::V1_0::ICameraDevice> g_CameraDevice = nullptr;
            const sptr<HDI::Camera::V1_0::ICameraDeviceCallback> callback =
                const_cast<HDI::Camera::V1_0::ICameraDeviceCallback *>(
                    reinterpret_cast<const HDI::Camera::V1_0::ICameraDeviceCallback *>(rawData));

            cameraTest->serviceV1_1->OpenCamera(
                *reinterpret_cast<const std::string *>(rawData), callback, g_CameraDevice);
            break;
        }
        case CAMERA_HOST_OPEN_CAMERA_V1_1: {
            sptr<HDI::Camera::V1_1::ICameraDevice> g_CameraDevice = nullptr;
            const sptr<HDI::Camera::V1_0::ICameraDeviceCallback> callback =
                const_cast<HDI::Camera::V1_0::ICameraDeviceCallback *>(
                    reinterpret_cast<const HDI::Camera::V1_0::ICameraDeviceCallback *>(rawData));
            cameraTest->serviceV1_1->OpenCamera_V1_1(
                *reinterpret_cast<const std::string *>(rawData), callback, g_CameraDevice);
            break;
        }
        case CAMERA_HOST_SET_FLASH_LIGHTS: {
            cameraTest->serviceV1_1->SetFlashlight(*reinterpret_cast<const std::string *>(rawData), true);
            break;
        }
        default:
            return;
    }
}

bool DoSomethingInterestingWithMyApi(const uint8_t *rawData, size_t size)
{
    (void)size;
    if (rawData == nullptr) {
        return false;
    }

    uint32_t cmd = ConvertUint32(rawData);
    rawData += sizeof(cmd);

    cameraTest = std::make_shared<OHOS::Camera::CameraManager>();
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return false;
    }
    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return false;
    }

    HostFuncSwitch(cmd, rawData);
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
