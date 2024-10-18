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

#include "defferred_delivery_image_fuzzer.h"
#include "camera.h"

namespace OHOS::Camera {
const size_t THRESHOLD = 10;
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

bool GetConcurrencyApi(const uint8_t *rawData)
{
    int taskCount;
    cameraTest_->imageProcessSession_->GetCoucurrency(
        static_cast<OHOS::HDI::Camera::V1_2::ExecutionMode>(ConvertUint32(rawData)), taskCount);
    return true;
}

bool SetExecutionModeApi(const uint8_t *rawData)
{
    cameraTest_->imageProcessSession_->SetExecutionMode(
        static_cast<OHOS::HDI::Camera::V1_2::ExecutionMode>(ConvertUint32(rawData)));
    return true;
}

bool GetPendingImagesApi(const uint8_t *rawData)
{
    (void) rawData;
    cameraTest_->imageProcessSession_->GetPendingImages(cameraTest_->pendingImageIds_);
    return true;
}

bool ProcessImageApi(const uint8_t *rawData)
{
    int imagesCount = cameraTest_->pendingImageIds_.size();
    std::string imageId;
    if (imagesCount != 0) {
        imageId = cameraTest_->pendingImageIds_[rawData[0] % imagesCount];
    }
    cameraTest_->imageProcessSession_->ProcessImage(imageId);
    return true;
}

bool RemoveImageApi(const uint8_t *rawData)
{
    int imagesCount = cameraTest_->pendingImageIds_.size();
    std::string imageId;
    if (imagesCount != 0) {
        imageId = cameraTest_->pendingImageIds_[rawData[0] % imagesCount];
    }
    cameraTest_->imageProcessSession_->RemoveImage(imageId);
    return true;
}

bool InterruptApi(const uint8_t *rawData)
{
    (void) rawData;
    cameraTest_->imageProcessSession_->Interrupt();
    return true;
}

typedef bool (*TestFuncDef)(const uint8_t *rawData);
static TestFuncDef g_allTestFunc[] = {
    GetConcurrencyApi,
    GetPendingImagesApi,
    SetExecutionModeApi,
    ProcessImageApi,
    RemoveImageApi,
    InterruptApi,
};


static void TestFuncSwitch(uint32_t cmd, const uint8_t *rawData)
{
    int testCount = sizeof(g_allTestFunc) / sizeof(g_allTestFunc[0]);
    TestFuncDef curFunc = g_allTestFunc[cmd % testCount];
    curFunc(rawData);
}

bool DoSomethingInterestingWithMyApi(const uint8_t *rawData, size_t size)
{
    (void)size;
    if (rawData == nullptr) {
        return false;
    }

    uint32_t cmd = ConvertUint32(rawData);
    rawData += sizeof(cmd);

    cameraTest_ = std::make_shared<OHOS::Camera::HdiCommonV1_2>();
    cameraTest_->Init();
    if (cameraTest_->serviceV1_2 == nullptr) {
        return false;
    }
    cameraTest_->OpenCameraV1_2(DEVICE_0);
    if (cameraTest_->cameraDeviceV1_2 == nullptr) {
        return false;
    }
    cameraTest_->rc = cameraTest_->DefferredImageTestInit();
    if (cameraTest_->rc != 0) {
        return false;
    }
    TestFuncSwitch(cmd, rawData);
    cameraTest_->Close();
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
