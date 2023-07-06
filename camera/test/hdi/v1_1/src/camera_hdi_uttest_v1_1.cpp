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
 * @tc.desc: Prelaunch
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
    cameraTest->prelaunchConfig = std::make_shared<OHOS::HDI::Camera::V1_1::PrelaunchConfig>();
    cameraTest->prelaunchConfig->cameraId = {};
    cameraTest->prelaunchConfig->streamInfos_V1_1 = {};
    cameraTest->prelaunchConfig->setting = {};

    cameraTest->rc = cameraTest->serviceV1_1->Prelaunch(*cameraTest->prelaunchConfig);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: GetStreamOperator_V1_1
 * @tc.desc: GetStreamOperator_V1_1
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
    EXPECT_EQ(true, cameraTest->cameraDevice != nullptr);
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: GetStreamOperator_V1_1
 * @tc.desc: GetStreamOperator_V1_1
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
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_004, TestSize.Level1)
{
    cameraTest->Init();
    if (cameraTest->serviceV1_1 == nullptr) {
        return;
    }
    cameraTest->Open();
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
    
    // preview streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoV1_1->v1_0.streamId_ = 1201;
    cameraTest->streamInfoV1_1->v1_0.width_ = 720;
    cameraTest->streamInfoV1_1->v1_0.height_ = 480;
    cameraTest->streamInfoV1_1->v1_0.format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = UT_DATA_SIZE;
    cameraTest->streamInfoV1_1->v1_0.intent_ = PREVIEW; // capture stream
    cameraTest->streamInfoV1_1->v1_0.tunneledMode_ = UT_TUNNEL_MODE;

    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer1 =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfoV1_1->v1_0.bufferQueue_ = consumer1->CreateProducerSeq([this](void* addr, uint32_t size) {
        cameraTest->DumpImageFile(cameraTest->streamIdPreview, "yuv", addr, size);
    });

    cameraTest->streamInfoV1_1->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->consumerMap_[cameraTest->streamInfoV1_1->v1_0.intent_] = consumer1;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // capture streamInfo
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    OHOS::HDI::Camera::V1_1::ExtendedStreamInfo extendedStreamInfo;
    extendedStreamInfo.type = OHOS::HDI::Camera::V1_1::EXTENDED_STREAM_INFO_QUICK_THUMBNAIL;
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer2 =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    extendedStreamInfo.bufferQueue = consumer2->CreateProducerSeq([this](void* addr, uint32_t size) {
        cameraTest->DumpImageFile(101, "yuv", addr, size);
    });

    // quikThumbnial do not need these param
    extendedStreamInfo.width = 0;
    extendedStreamInfo.height = 0;
    extendedStreamInfo.format = 0;
    extendedStreamInfo.dataspace = 0;
    cameraTest->streamInfoV1_1->extendedStreamInfos = {extendedStreamInfo};

    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer3 =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    cameraTest->streamInfoV1_1->v1_0.bufferQueue_ = consumer3->CreateProducerSeq([this](void* addr, uint32_t size) {
        cameraTest->DumpImageFile(102, "yuv", addr, size);
    });

    cameraTest->streamInfoV1_1->v1_0.streamId_ = 103;
    cameraTest->streamInfoV1_1->v1_0.width_ = 720;
    cameraTest->streamInfoV1_1->v1_0.height_ = 480;
    cameraTest->streamInfoV1_1->v1_0.format_ = PIXEL_FMT_YCRCB_420_SP;
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = UT_DATA_SIZE;
    cameraTest->streamInfoV1_1->v1_0.intent_ = STILL_CAPTURE; // capture stream
    cameraTest->streamInfoV1_1->v1_0.tunneledMode_ = UT_TUNNEL_MODE;

    cameraTest->streamInfoV1_1->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->consumerMap_[cameraTest->streamInfoV1_1->v1_0.intent_] = consumer3;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(1201, cameraTest->captureIdPreview, true, true);
    cameraTest->StartCapture(103, cameraTest->captureIdPreview + 1, true, true);

    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdPreview + 1};
    cameraTest->streamIds = {1201, 103};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}
