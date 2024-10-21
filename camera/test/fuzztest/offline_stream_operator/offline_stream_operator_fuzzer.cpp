/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "offline_stream_operator_fuzzer.h"

using namespace OHOS::Camera;

namespace OHOS::Camera {
const size_t THRESHOLD = 10;

enum HostCmdId {
    OFFLINE_STREAM_OPERATOR_CONCERCAPTURE,
    OFFLINE_STREAM_OPERATOR_RELEASESTREAMS,
    OFFLINE_STREAM_OPERATOR_RELEASE,
    OFFLINE_STREAM_OPERATOR_END,
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

static int32_t ConvertInt32(const uint8_t *bitOperat)
{
    if (bitOperat == nullptr) {
        return 0;
    }

    return ((int32_t)bitOperat[INDEX_0] << MOVE_TWENTY_FOUR_BITS) | ((int32_t)bitOperat[INDEX_1] << MOVE_SIXTEEN_BITS) |
        ((int32_t)bitOperat[INDEX_2] << MOVE_EIGHT_BITS) | ((int32_t)bitOperat[INDEX_3]);
}

void FuncCancelCapture(const uint8_t *rawData)
{
    if (rawData == nullptr) {
        CAMERA_LOGI("%{public}s rawData is null", __FUNCTION__);
        return;
    }
    cameraTest->streamOperatorCallback = new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);
    cameraTest->streamInfoSnapshot = std::make_shared<OHOS::HDI::Camera::V1_0::StreamInfo>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoSnapshot);
    cameraTest->streamInfos.push_back(*cameraTest->streamInfoSnapshot);
    cameraTest->captureInfo = std::make_shared<CaptureInfo>();
    cameraTest->captureInfo->streamIds_ = {101};
    cameraTest->captureInfo->captureSetting_ = cameraTest->abilityVec;
    cameraTest->captureInfo->enableShutterCallback_ = true;
    bool isStreaming = true;
    cameraTest->rc = cameraTest->streamOperator->Capture(*rawData, *cameraTest->captureInfo, isStreaming);
    OHOS::sptr<OHOS::HDI::Camera::V1_0::IStreamOperatorCallback> streamOperatorCallback =
        new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;

    cameraTest->rc = cameraTest->streamOperator->ChangeToOfflineStream(
        {cameraTest->streamInfoSnapshot->streamId_}, streamOperatorCallback, offlineStreamOperator);
    cameraTest->rc = offlineStreamOperator->CancelCapture(*rawData);
}

void FuncReleaseStreams(const uint8_t *rawData)
{
    if (rawData == nullptr) {
        CAMERA_LOGI("%{public}s rawData is null", __FUNCTION__);
        return;
    }
    cameraTest->streamOperatorCallback = new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDevice->GetStreamOperator(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator);

    int32_t data = static_cast<int32_t>(ConvertInt32(rawData));
    OHOS::sptr<OHOS::HDI::Camera::V1_0::IStreamOperatorCallback> streamOperatorCallback =
        new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;

    cameraTest->rc = cameraTest->streamOperator->ChangeToOfflineStream(
        {data}, streamOperatorCallback, offlineStreamOperator);
    cameraTest->rc = offlineStreamOperator->ReleaseStreams({data});
}

void FuncRelease()
{
    cameraTest->streamInfoSnapshot = std::make_shared<OHOS::HDI::Camera::V1_0::StreamInfo>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoSnapshot);
    cameraTest->streamInfos.push_back(*cameraTest->streamInfoSnapshot);
    OHOS::sptr<OHOS::HDI::Camera::V1_0::IStreamOperatorCallback> streamOperatorCallback =
        new OHOS::Camera::HdiCommon::TestStreamOperatorCallback();
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;

    cameraTest->rc = cameraTest->streamOperator->ChangeToOfflineStream(
        {cameraTest->streamInfoSnapshot->streamId_}, streamOperatorCallback, offlineStreamOperator);
    cameraTest->rc = offlineStreamOperator->Release();
}

static void HostFuncSwitch(uint32_t cmd, const uint8_t *rawData)
{
    switch (cmd) {
        case OFFLINE_STREAM_OPERATOR_CONCERCAPTURE: {
            FuncCancelCapture(rawData);
            break;
        }
        case OFFLINE_STREAM_OPERATOR_RELEASESTREAMS: {
            FuncReleaseStreams(rawData);
            break;
        }
        case OFFLINE_STREAM_OPERATOR_RELEASE:
            FuncRelease();
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

    cameraTest = std::make_shared<OHOS::Camera::HdiCommon>();
    cameraTest->Init();
    if (cameraTest->service == nullptr) {
        return false;
    }
    cameraTest->Open();
    if (cameraTest->cameraDevice == nullptr) {
        return false;
    }
    for (cmd = 0; cmd < OFFLINE_STREAM_OPERATOR_END; cmd++) {
        HostFuncSwitch(cmd, rawData);
    }
    cameraTest->Close();
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < THRESHOLD) {
        return 0;
    }

    DoSomethingInterestingWithMyApi(data, size);
    return 0;
}
} // namespace OHOS
