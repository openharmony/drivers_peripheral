/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expected in compliance with the License.
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
#include "camera_hdi_uttest_v1_1.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraHdiUtTestV1_1::SetUpTestCase(void) {}
void CameraHdiUtTestV1_1::TearDownTestCase(void) {}
void CameraHdiUtTestV1_1::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
}

void CameraHdiUtTestV1_1::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: Prelaunch
 * @tc.desc: Prelaunch cameraId:device/0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_001, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return;
    }
    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return;
    }
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/0";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: Prelaunch
 * @tc.desc: Prelaunch cameraId:device/1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_002, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return;
    }
    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return;
    }
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/1";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: Prelaunch
 * @tc.desc: Prelaunch cameraId:device/10
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_003, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return;
    }
    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return;
    }
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "device/10";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
}

/**
 * @tc.name: Prelaunch
 * @tc.desc: Prelaunch cameraId:ABC
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_004, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return;
    }
    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return;
    }
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = "ABC";
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::INVALID_ARGUMENT);
}

/**
 * @tc.name: GetStreamOperator_V1_1
 * @tc.desc: GetStreamOperator_V1_1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_005, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return;
    }
    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return;
    }
    EXPECT_EQ(true, cameraTest->cameraDevice != nullptr);
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(
        cameraTest->streamOperatorCallback, cameraTest->streamOperator_V1_1);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: GetStreamOperator_V1_1
 * @tc.desc: GetStreamOperator_V1_1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_006, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return;
    }
    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return;
    }
    EXPECT_EQ(true, cameraTest->cameraDevice != nullptr);
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetDefaultSettings(cameraTest->abilityVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: Quick Thumbnail
 * @tc.desc: Quick Thumbnail
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_007, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return;
    }

    cameraTest->Open();
    if (cameraTest->cameraDeviceV1_1 == nullptr) {
        return;
    }

    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(
        cameraTest->streamOperatorCallback, cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // capture extended streamInfo
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo;
    extendedStreamInfo.type = OHOS::HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer2 =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    extendedStreamInfo.bufferQueue = consumer2->CreateProducerSeq([this](void *addr, uint32_t size) {
        cameraTest->DumpImageFile(105, "yuv", addr, size);
    });
    EXPECT_NE(extendedStreamInfo.bufferQueue, nullptr);
    EXPECT_NE(extendedStreamInfo.bufferQueue->producer_, nullptr);
    extendedStreamInfo.bufferQueue->producer_->SetQueueSize(UT_DATA_SIZE);
    // quikThumbnial do not need these param
    extendedStreamInfo.width = 0;
    extendedStreamInfo.height = 0;
    extendedStreamInfo.format = 0;
    extendedStreamInfo.dataspace = 0;

    // capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoCapture->extendedStreamInfos = {extendedStreamInfo};
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}
