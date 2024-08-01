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

#include "stream_operator_fuzzer.h"

namespace OHOS {
const size_t THRESHOLD = 10;

enum HostCmdId {
    STREAM_OPERATOR_FUZZ_TEST,
    STREAM_OPERATOR_ISSTREAMSUPPORTED_V1_1,
    STREAM_OPERATOR_COMMITSTREAM_V1_1,
    STREAM_OPERATOR_UPDATESTREAMS,
    STREAM_OPERATOR_CONFIRMCAPTURE,
    STREAM_OPERATOR_END,
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

void IsStreamSupportedApi(const uint8_t *&rawData)
{
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::CameraManager::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    std::vector<uint8_t> abilityVec = {};
    uint8_t *data = const_cast<uint8_t *>(rawData);
    abilityVec.push_back(*data);

    std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfosV1_1;
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo;
    extendedStreamInfo.type = OHOS::HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL;
    extendedStreamInfo.width = 0;
    extendedStreamInfo.height = 0;
    extendedStreamInfo.format = 0;
    extendedStreamInfo.dataspace = 0;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoCapture = nullptr;
    streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoCapture->v1_0 = {};
    streamInfoCapture->extendedStreamInfos = {extendedStreamInfo};
    streamInfosV1_1.push_back(*streamInfoCapture);
    HDI::Camera::V1_0::StreamSupportType pType;

    cameraTest->streamOperator_V1_2->IsStreamsSupported_V1_1(
        *reinterpret_cast<const HDI::Camera::V1_1::OperationMode_V1_1 *>(rawData), abilityVec,
        streamInfosV1_1, pType);
}

void UpdateStreams(const uint8_t *rawData)
{
    if (rawData == nullptr) {
        return;
    }
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::CameraManager::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    int *data = const_cast<int *>(reinterpret_cast<const int *>(rawData));
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoV1_1->v1_0.streamId_ = data[0];
    cameraTest->streamInfoV1_1->v1_0.width_ = data[0];
    cameraTest->streamInfoV1_1->v1_0.height_ = data[0];
    cameraTest->streamInfoV1_1->v1_0.format_ = Camera::PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfoV1_1->v1_0.tunneledMode_ = data[0];
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = Camera::OHOS_CAMERA_SRGB_FULL;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    cameraTest->rc = cameraTest->streamOperator_V1_2->UpdateStreams(cameraTest->streamInfosV1_1);
}

void funcConfirmCapture(const uint8_t *rawData)
{
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::CameraManager::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    cameraTest->streamOperator_V1_2->ConfirmCapture(*rawData);
}

static void HostFuncSwitch(uint32_t cmd, const uint8_t *rawData)
{
    switch (cmd) {
        case STREAM_OPERATOR_ISSTREAMSUPPORTED_V1_1: {
            IsStreamSupportedApi(rawData);
            break;
        }
        case STREAM_OPERATOR_COMMITSTREAM_V1_1: {
            cameraTest->streamOperatorCallbackV1_2 =
                new OHOS::Camera::CameraManager::TestStreamOperatorCallbackV1_2();
            cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(
                cameraTest->streamOperatorCallbackV1_2, cameraTest->streamOperator_V1_2);
            std::vector<uint8_t> abilityVec = {};
            uint8_t *data = const_cast<uint8_t *>(rawData);
            abilityVec.push_back(*data);
            cameraTest->streamOperator_V1_2->CommitStreams_V1_1(
                *reinterpret_cast<const HDI::Camera::V1_1::OperationMode_V1_1 *>(rawData), abilityVec);
            break;
        }
        case STREAM_OPERATOR_UPDATESTREAMS:
            UpdateStreams(rawData);
            break;
        case STREAM_OPERATOR_CONFIRMCAPTURE:
            funcConfirmCapture(rawData);
            break;
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
    cameraTest->InitV1_2();
    if (cameraTest->serviceV1_2 == nullptr) {
        return false;
    }
    cameraTest->OpenCameraV1_2();
    if (cameraTest->cameraDeviceV1_2 == nullptr) {
        return false;
    }

    for (cmd = 0; cmd < STREAM_OPERATOR_END; cmd++) {
        HostFuncSwitch(cmd, rawData);
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
}
