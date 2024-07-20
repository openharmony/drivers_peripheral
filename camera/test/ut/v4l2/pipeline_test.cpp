/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "pipeline_test.h"

void UtestPipelineTest::SetUpTestCase(void)
{}
void UtestPipelineTest::TearDownTestCase(void)
{}
void UtestPipelineTest::SetUp(void)
{
    if (cameraBase == nullptr)
    cameraBase = std::make_shared<TestCameraBase>();
    cameraBase->FBInit();
    cameraBase->Init();
}
void UtestPipelineTest::TearDown(void)
{
    cameraBase->Close();
}

/**
  * @tc.name: Check ppl
  * @tc.desc: preview success.
  * @tc.level: Level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestPipelineTest, camera_ppl_0001)
{
    std::cout << "==========[test log] Check ppl: preview success." << std::endl;
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: Check ppl
  * @tc.desc: preview + capture success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestPipelineTest, camera_ppl_0002)
{
    std::cout << "==========[test log] Check ppl: preview + capture success." << std::endl;
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_CAPTURE, cameraBase->CAPTURE_ID_CAPTURE, false, true);
    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_CAPTURE};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_CAPTURE};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: Check ppl
  * @tc.desc: preview + video success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestPipelineTest, camera_ppl_0003)
{
    std::cout << "==========[test log] Check ppl: preview + video success." << std::endl;
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW, VIDEO};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_VIDEO, cameraBase->CAPTURE_ID_VIDEO, false, true);
    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_VIDEO};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_VIDEO};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: Check ppl
  * @tc.desc: video mode without preview, system not support, expected return fail.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestPipelineTest, camera_ppl_0004)
{
    std::cout << "==========[test log] Video mode without preview, system not support, ";
    std::cout << "expected return fail." << std::endl;

    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    cameraBase->AchieveStreamOperator();
    // Create video stream
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferqueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferqueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        cameraBase->BufferCallback(b, cameraBase->video_mode);
        return;
    };
    producer->SetCallback(callback);
    cameraBase->streamInfo = std::make_shared<StreamInfo>();
    cameraBase->streamInfo->streamId_ = cameraBase->STREAM_ID_VIDEO;
    cameraBase->streamInfo->width_ = 640; // 640:picture width // 640:picture width
    cameraBase->streamInfo->height_ = 480; // 480:picture height // 480:picture height
    cameraBase->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    cameraBase->streamInfo->dataspace_ = 10; // 10:picture dataspace
    cameraBase->streamInfo->intent_ = VIDEO;
    cameraBase->streamInfo->tunneledMode_ = 5; // 5:tunnel mode // 5:tunnel mode
    cameraBase->streamInfo->bufferQueue_ = producer;
    std::vector<std::shared_ptr<StreamInfo>>().swap(streamInfos);
    streamInfos.push_back(cameraBase->streamInfo);
    cameraBase->rc = cameraBase->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(false, cameraBase->rc == Camera::METHOD_NOT_SUPPORTED);
    if (cameraBase->rc == Camera::METHOD_NOT_SUPPORTED) {
        std::cout << "==========[test log] CreateStreams METHOD_NOT_SUPPORTED, streamId = ";
        std::cout << cameraBase->STREAM_ID_VIDEO <<", intent = VIDEO" << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << cameraBase->rc << std::endl;
    }

    cameraBase->rc = cameraBase->streamOperator->CommitStreams(Camera::NORMAL, nullptr);
    EXPECT_EQ(false, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CommitStreams fail, rc = ." << cameraBase->rc << std::endl;
    }
}