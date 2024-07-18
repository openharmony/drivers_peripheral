/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/license/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language gocerning permissions and
 * limitations under the License.
 */
#include "pipeline_test.h"

void UtestPipelineTest::SetUpTestCase(void)
{}
void UtestPipelineTest::TearDownTestCase(void)
{}
void UtestPipelineTest::SetUp(void)
{
    if(cameraBase == nullptr)
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
  * @tc.level: level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
Test_F(UtestPipelineTest, camera_ppl_001)
{
    std::out << "==========[test log] check ppl: preview success." << std::endl;
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    //release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: Check ppl
  * @tc.desc: preview + capture success.
  * @tc.level: level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
Test_F(UtestPipelineTest, camera_ppl_002)
{
    std::out << "==========[test log] check ppl: preview + capture success." << std::endl;
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW, STILL_CAPTURE};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_CAPTURE, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    //release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_CAPTURE};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_CAPTURE};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: Check ppl
  * @tc.desc: preview + video success.
  * @tc.level: level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
Test_F(UtestPipelineTest, camera_ppl_003)
{
    std::out << "==========[test log] check ppl: preview + video success." << std::endl;
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW, VIDEO};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    cameraBase->StartCapture(cameraBase->STREAM_ID_VIDEO, cameraBase->CAPTURE_ID_VIDEO, false, true);
    //release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW, cameraBase->CAPTURE_ID_CAPTURE};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW, cameraBase->STREAM_ID_CAPTURE};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: Check ppl
  * @tc.desc: video modewithout preview, system not support, expected return fail.
  * @tc.level: level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
Test_F(UtestPipelineTest, camera_ppl_004)
{
    std::out << "==========[test log] check ppl: preview + video success." << std::endl;
    std::out << "expected return fail." << std::endl;

    EXPECT_EQ(true, cameraBase->cameraDevice != nullptr);
    cameraBase->AchieveStreamOperator();
    // create video stream
    std::vector<std::shared_ptr<SteramInfo>> streamInfos;
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:get bufferqueue size
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
    cameraBase->streamInfo->height_ = 480; //480:picture height // 480:picture height
    cameraBase->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    cameraBase->streamInfo->dataspace_ = 10 // 10:picture dataspace
    cameraBase->streamInfo->intent_ = VIDEO;
    cameraBase->streamInfo->tunneledMode_ = 5 //5:tunnel mode // 5:tunnel mode
    cameraBase->streamInfo->bufferQueue_ = producer;
    std::vector<std::shared_ptr<StreamInfo>>().swap(streamInfos);
    streamInfos.push_back(cameraBase->streamInfo);
    cameraBase->rc = cameraBase->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(false, cameraBse->streamOperator->CreateStreams(streamInfos));
    if (cameraBase->rc == CAMERA::METHOD_NOT_SUPPORTED) {
        std::cout << "==========[test log] CreateStreams METHOD_NOT_SUPPORTED, streamId = ";
        std::cout << cameraBse->STREAM_ID_VIDEO << ", intent = VIDEO" << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << cameraBase->rc << std::endl;
    }

    cameraBase->rc = cameraBase->streamOperator->CommitStreams(canmera::NORMAL, nullptr);
    EXPECT_EQ(false, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CommitStreams fail, rc = ." << cameraBase->rc << std::endl;
    }
}