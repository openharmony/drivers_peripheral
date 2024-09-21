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
const size_t RAW_DATA_SIZE_MAX = 256;
const size_t THRESHOLD = 10;

enum DeviceCmdId {
    CAMERA_DEVICE_GET_DEFAULT_SETTINGS,
    CAMERA_DEVICE_GET_STREAM_V1_1,
    CAMERA_DEVICE_UPDATE_SETTINGS,
    CAMERA_DEVICE_SET_RESULT_MODE,
    CAMERA_DEVICE_GET_ENABLED_RESULTS,
    CAMERA_DEVICE_ENABLE_RESULT,
    CAMERA_DEVICE_DISABLE_RESULT,
    CAMERA_DEVICE_GET_STATUS,
    CAMERA_DEVICE_GET_SECURECAMERASEQ,
    CAMERA_DEVICE_END, // Enumerated statistical value. The new enumerated value is added before
};

void FuncGetDefaultSettings(const uint8_t *rawData, size_t size)
{
    if (size >= RAW_DATA_SIZE_MAX) {
        return;
    }
    std::vector<uint8_t> abilityVec = {};
    uint8_t *data = const_cast<uint8_t *>(rawData);
    abilityVec.push_back(*data);
    cameraTest->cameraDeviceV1_1->GetDefaultSettings(abilityVec);
}

void FuncGetStreamOperator_V1_1(const uint8_t *rawData, size_t size)
{
    (void)size;
    sptr<HDI::Camera::V1_0::IStreamOperatorCallback> g_callback =
        new OHOS::Camera::CameraManager::TestStreamOperatorCallback();
    sptr<HDI::Camera::V1_1::IStreamOperator> g_StreamOperator = nullptr;
    cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(g_callback, g_StreamOperator);
}

void FuncUpdateSettings(const uint8_t *rawData, size_t size)
{
    if (size >= RAW_DATA_SIZE_MAX) {
        return;
    }
    float *data = const_cast<float *>(reinterpret_cast<const float *>(rawData));
    std::shared_ptr<Camera::CameraMetadata> meta = std::make_shared<Camera::CameraMetadata>(
        cameraTest->itemCapacity, cameraTest->dataCapacity);
    meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &data[0], cameraTest->dataCount);
    std::vector<uint8_t> metaVec;
    Camera::MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDeviceV1_1->UpdateSettings(metaVec);
}

void FuncSetResultMode(const uint8_t *rawData, size_t size)
{
    (void)size;
    cameraTest->cameraDeviceV1_1->SetResultMode(
        *reinterpret_cast<const HDI::Camera::V1_0::ResultCallbackMode *>(rawData));
}

void FuncGetEnabledResults(const uint8_t *rawData, size_t size)
{
    (void)size;
    std::vector<int32_t> result = {};
    int32_t *data = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    result.push_back(*data);
    cameraTest->cameraDeviceV1_1->GetEnabledResults(result);
}

void FuncEnableResult(const uint8_t *rawData, size_t size)
{
    (void)size;
    std::vector<int32_t> result = {};
    int32_t *data = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    result.push_back(*data);
    cameraTest->cameraDeviceV1_1->EnableResult(result);
}

void FuncDisableResult(const uint8_t *rawData, size_t size)
{
    (void)size;
    std::vector<int32_t> result = {};
    int32_t *data = const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
    result.push_back(*data);
    cameraTest->cameraDeviceV1_1->DisableResult(result);
}

void FuncGetStatus(const uint8_t *rawData, size_t size)
{
    (void)size;
    std::vector<uint8_t> resultOut = {};
    float *data = const_cast<float *>(reinterpret_cast<const float *>(rawData));
    std::shared_ptr<Camera::CameraMetadata> meta = std::make_shared<Camera::CameraMetadata>(
        cameraTest->itemCapacity, cameraTest->dataCapacity);
    meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &data[0], cameraTest->dataCount);
    std::vector<uint8_t> metaVec;
    Camera::MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    if (nullptr == cameraTest->cameraDeviceV1_2) {
        return;
    }
    cameraTest->cameraDeviceV1_2->GetStatus(metaVec, resultOut);
}

void FuncGetSecureCameraSeq(const uint8_t *rawData, size_t size)
{
    (void)size;
    if (nullptr == cameraTest->cameraDeviceV1_3) {
        return;
    }
    uint64_t SeqId;
    // Output do not need fuzz
    cameraTest->cameraDeviceV1_3->GetSecureCameraSeq(SeqId);
}

static void DeviceFuncSwitch(uint32_t cmd, const uint8_t *rawData, size_t size)
{
    CAMERA_LOGI("DeviceFuncSwitch start, the cmd is:%{public}u", cmd);
    switch (cmd) {
        case CAMERA_DEVICE_GET_DEFAULT_SETTINGS: {
            FuncGetDefaultSettings(rawData, size);
            break;
        }
        case CAMERA_DEVICE_GET_STREAM_V1_1: {
            FuncGetStreamOperator_V1_1(rawData, size);
            break;
        }

        case CAMERA_DEVICE_UPDATE_SETTINGS: {
            FuncUpdateSettings(rawData, size);
            break;
        }
        case CAMERA_DEVICE_SET_RESULT_MODE: {
            FuncSetResultMode(rawData, size);
            break;
        }
        case CAMERA_DEVICE_GET_ENABLED_RESULTS: {
            FuncGetEnabledResults(rawData, size);
            break;
        }
        case CAMERA_DEVICE_ENABLE_RESULT: {
            FuncEnableResult(rawData, size);
            break;
        }
        case CAMERA_DEVICE_DISABLE_RESULT: {
            FuncDisableResult(rawData, size);
            break;
        }
        case CAMERA_DEVICE_GET_STATUS: {
            FuncGetStatus(rawData, size);
            break;
        }
        case CAMERA_DEVICE_GET_SECURECAMERASEQ: {
            FuncGetSecureCameraSeq(rawData, size);
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
    if (rawData == nullptr) {
        return false;
    }

    uint32_t cmd = 0;
    rawData += sizeof(cmd);

    cameraTest = std::make_shared<OHOS::Camera::CameraManager>();
    cameraTest->InitV1_3();
    if (cameraTest->serviceV1_1 == nullptr) {
        return false;
    }
    cameraTest->OpenV1_3();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return false;
    }

    for (cmd = 0; cmd < CAMERA_DEVICE_END; cmd++) {
        DeviceFuncSwitch(cmd, rawData, size);
    }
    cameraTest->Close();
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        CAMERA_LOGW("Fuzz test input is invalid. The size is smaller than %{public}zu", OHOS::THRESHOLD);
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyApi(data, size);
    return 0;
}
} // namespace OHOS
