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

#include "logic_camera_test.h"

constexpr int QUEUE_SIZE = 8;
constexpr int DEFAULT_TEST_DATASPACE_VALUE = 8;
constexpr int DEFAULT_TEST_TUNNELEDMODE_VALUE = 5;

void UtestLogicCameraTest::SetUpTestCase(void)
{}
void UtestLogicCameraTest::TearDownTestCase(void)
{}
void UtestLogicCameraTest::SetUp(void)
{
    if (cameraBase == nullptr)
    cameraBase = std::make_shared<TestCameraBase>();
    cameraBase->FBInit();
    cameraBase->Init();
}
void UtestLogicCameraTest::TearDown(void)
{
    cameraBase->Close();
}

/**
  * @tc.name: test logic camera
  * @tc.desc: single stream
  * @tc.level: level0
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestLogicCameraTest, camera_logic_0001)
{
    std::cout << "==========[test log] test single stream"<< std::endl;
    // Get the stream manager
    cameraBase->AchieveStreamOperator();
    // configure preciew stream information
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(QUEUE_SIZE);
    if (producer->GetQueueSize() != QUEUE_SIZE) {
        std::cout "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        cameraBase->BufferCallback(b, caneraBase->preview_mode);
        return;
    };
    producer->SerCallback(callback);
    std::shared_ptr<StreamInfo> streamInfoPre = std::make_shared<StreamInfo>();
    streamInfoPre->streamId_ = cameraBase->STREAM_ID_PREVIEW;
    streamInfoPre->width_ = DEFAULT_TEST_WIDTH_VALUE;
    streamInfoPre->height_ = DEFAULT_TEST_HEIGHT_VALUE;
    streamInfoPre->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    streamInfoPre->dataspace_ = DEFAULT_TEST_DATASPACE_VALUE;
    streamInfoPre->intent_ = PREVIEW;
    streamInfoPre->tunneledMode_ = DEFAULT_TEST_TUNNELEDMODE_VALUE;
    streamInfoPre->bufferQueue_ = producer;
    cameraBase->streamInfos.push_back(streamInfoPre);
    camera->rc = cameraBase->streamOperator->CreateStreams(cameraBase->stramInfos);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (caneraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success, streamId = ";
        std::cout << cameraBase->STREAM_ID_CAPTURE, <<", intent = STILL_CAPTURE" << std::endl;
    }
    // Submit stream information
    cameraBase->rc = cameraBase->streamOperator->CommitStreams(DUAL, nullptr);
    EXPECT_EQ(false, cameraBase->rc != NO_ERROR) {
        std::cout << "==========[test log] CommitStreams DUAL success." << std::endl;
    } else {
        std::cout << "==========[test log] CommitStreams DUAL fail, rc = " << cameraBase->rc << endl;
    }
    // capture
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, false, true);
    // post-processing
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {caneraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}