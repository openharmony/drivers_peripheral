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

#include "camera_device_fuzzer.h"
#include "camera.h"
#include "v1_1/icamera_device.h"

namespace OHOS {
const size_t THRESHOLD = 10;

enum DeviceCmdId {
    CAMERA_DEVICE_GET_DEFAULT_SETTINGS,
    CAMERA_DEVICE_GET_STREAM_V1_1,
    CAMERA_DEVICE_GET_STREAM,
    CAMERA_DEVICE_UPDATE_SETTINGS,
    CAMERA_DEVICE_SET_RESULT_MODE,
    CAMERA_DEVICE_GET_ENABLED_RESULTS,
    CAMERA_DEVICE_ENABLE_RESULT,
    CAMERA_DEVICE_DISABLE_RESULT,
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

static void DeviceFuncSwitch(uint32_t cmd, const uint8_t *&rawData)
{
    CAMERA_LOGI("DeviceFuncSwitch start, the cmd is:%{public}u", cmd);
    switch (cmd) {
        case CAMERA_DEVICE_GET_DEFAULT_SETTINGS: {
            std::vector<uint8_t> abilityVec = {};
            uint8_t *data = const_cast<uint8_t *>(rawData);
            abilityVec.push_back(*data);
            cameraTest->cameraDeviceV1_1->GetDefaultSettings(abilityVec);
            break;
        }
        case CAMERA_DEVICE_GET_STREAM_V1_1: {
            sptr<HDI::Camera::V1_1::IStreamOperator> g_StreamOperator = nullptr;
            const sptr<HDI::Camera::V1_0::IStreamOperatorCallback> callback =
                const_cast<HDI::Camera::V1_0::IStreamOperatorCallback *>(
                    reinterpret_cast<const HDI::Camera::V1_0::IStreamOperatorCallback *>(rawData));

            cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(callback, g_StreamOperator);
            break;
        }
        case CAMERA_DEVICE_GET_STREAM: {
            sptr<HDI::Camera::V1_0::IStreamOperator> g_StreamOperator = nullptr;
            const sptr<HDI::Camera::V1_0::IStreamOperatorCallback> callback =
                const_cast<HDI::Camera::V1_0::IStreamOperatorCallback *>(
                    reinterpret_cast<const HDI::Camera::V1_0::IStreamOperatorCallback *>(rawData));

            cameraTest->cameraDeviceV1_1->GetStreamOperator(callback, g_StreamOperator);
            break;
        }
        case CAMERA_DEVICE_UPDATE_SETTINGS: {
            std::vector<uint8_t> abilityVec = {};
            uint8_t *data = const_cast<uint8_t *>(rawData);
            abilityVec.push_back(*data);
            cameraTest->cameraDeviceV1_1->UpdateSettings(abilityVec);
            break;
        }
        case CAMERA_DEVICE_SET_RESULT_MODE: {
            cameraTest->cameraDeviceV1_1->SetResultMode(
                *reinterpret_cast<const HDI::Camera::V1_0::ResultCallbackMode *>(rawData));
            break;
        }
        case CAMERA_DEVICE_GET_ENABLED_RESULTS: {
            std::vector<int32_t> result = {};
            int32_t *data = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
            result.push_back(*data);
            cameraTest->cameraDeviceV1_1->GetEnabledResults(result);
            break;
        }
        case CAMERA_DEVICE_ENABLE_RESULT: {
            std::vector<int32_t> result = {};
            int32_t *data = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
            result.push_back(*data);
            cameraTest->cameraDeviceV1_1->EnableResult(result);
            break;
        }
        case CAMERA_DEVICE_DISABLE_RESULT: {
            std::vector<int32_t> result = {};
            int32_t *data = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
            result.push_back(*data);
            cameraTest->cameraDeviceV1_1->DisableResult(result);
            break;
        }
        default: {
            CAMERA_LOGW("The interfaces is not tested, the cmd is:%{public}u", cmd);
            return;
        }
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

    DeviceFuncSwitch(cmd, rawData);
    cameraTest->Close();
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        CAMERA_LOGW("Fuzz test input is invalid. The size is smaller than %{public}d", OHOS::THRESHOLD);
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyApi(data, size);
    return 0;
}
} // namespace OHOS
