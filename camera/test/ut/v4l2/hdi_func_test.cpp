/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "hdi_func_test.h"

void UtestHdiFuncTest::SetUpTestCase(void)
{}
void UtestHdiFuncTest::TearDownTestCase(void)
{}
void UtestHdiFuncTest::SetUp(void)
{
    if (cameraBase == nullptr)
    cameraBase = std::make_shared<TestCameraBase>();
    cameraBase->FBInit();
    cameraBase->Init();
}
void UtestHdiFuncTest::TearDown(void)
{
    cameraBase->Close();
}

/**
  * @tc.name: Capture
  * @tc.desc: Capture, input normal.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0190)
{
    std::cout << "==========[test log] Capture, input normal." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // Create data stream
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
  * @tc.name: Capture
  * @tc.desc: Preview, Capture->captureInfo->streamID = -1 ,return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0191)
{
    std::cout << "==========[test log] Preview, Capture->captureInfo->streamID = -1 ,return error." << std::endl;
    cameraBase->OpenCamera();
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    int captureId = 2001;
    std::shared_ptr<CaptureInfo> captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {-1};
    captureInfo->enableShutterCallback_ = true;
    cameraBase->rc = cameraBase->streamOperator->Capture(captureId, captureInfo, true);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase->rc);
    if (cameraBase->rc == INVALID_ARGUMENT) {
        std::cout << "==========[test log] Capture fail." << std::endl;
    } else {
        std::cout << "==========[test log] Capture success." << std::endl;
    }
    sleep(3); // waiting resource release for 3s.
}

/**
  * @tc.name: Capture
  * @tc.desc: Preview, Capture->captureInfo->streamID = 2147483647 ,return success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0192)
{
    std::cout << "==========[test log] Preview,";
    std::cout << "Capture->captureInfo->streamID = 2147483647 ,return success." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    int captureId = 2001;
    std::shared_ptr<CaptureInfo> captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {2147483647};
    captureInfo->enableShutterCallback_ = true;
    bool isStreaming = true;
    cameraBase->rc = cameraBase->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] Capture success." << std::endl;
    } else {
        std::cout << "==========[test log] Capture fail, rc = " << cameraBase->rc << std::endl;
    }
    sleep(3); // waiting function Capture execute for 3s.
    cameraBase->rc = cameraBase->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success." << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << cameraBase->rc << std::endl;
    }
    cameraBase->cameraDevice->Close();
    std::cout << "cameraDevice->Close" << std::endl;
}

/**
  * @tc.name: Capture
  * @tc.desc: Preview, Capture->captureInfo->enableShutterCallback = false ,return success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0193)
{
    std::cout << "==========[test log] Preview,";
    std::cout << "Capture->captureInfo->enableShutterCallback = false ,return success." << std::endl;
    // Create and get streamOperator information
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
  * @tc.name: Capture
  * @tc.desc: Preview, Capture->isStreaming = false ,expected success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0194)
{
    std::cout << "==========[test log] Preview, Capture->isStreaming = false ,expected success." << std::endl;
    std::cout << "==========[test log] Preview, Capture->isStreaming = false ,expected success." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    int captureId = 2001;
    std::shared_ptr<CaptureInfo> captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {cameraBase->STREAM_ID_PREVIEW};
    captureInfo->enableShutterCallback_ = true;
    cameraBase->rc = cameraBase->streamOperator->Capture(captureId, captureInfo, false);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    sleep(3); // waiting 3s, prepare for execute function CancelCapture
    cameraBase->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success." << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << cameraBase->rc << std::endl;
    }
    // release stream
    cameraBase->rc = cameraBase->streamOperator->ReleaseStreams(captureInfo->streamIds_);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << cameraBase->rc << std::endl;
    }
}

/**
  * @tc.name: Capture
  * @tc.desc: Preview, Capture->captureId = -1 ,return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0195)
{
    std::cout << "==========[test log] Preview, Capture->captureId = -1 ,return error." << std::endl;
    cameraBase->OpenCamera();
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    int captureId = -1;
    std::shared_ptr<CaptureInfo> captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {cameraBase->STREAM_ID_PREVIEW};
    captureInfo->enableShutterCallback_ = false;
    bool isStreaming = true;
    cameraBase->rc = cameraBase->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase->rc);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] Capture success." << std::endl;
    } else {
        std::cout << "==========[test log] Capture fail, rc = " << cameraBase->rc << std::endl;
    }
    sleep(3); // waiting resource release for 3s.
}

/**
  * @tc.name: Capture
  * @tc.desc: Preview, Capture->captureInfo->enableShutterCallback = true ,return success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0196)
{
    std::cout << "==========[test log] Preview,";
    std::cout << "Capture->captureInfo->enableShutterCallback = true ,return success." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    cameraBase->StartCapture(cameraBase->STREAM_ID_PREVIEW, cameraBase->CAPTURE_ID_PREVIEW, true, true);
    // release stream
    cameraBase->captureIds = {cameraBase->CAPTURE_ID_PREVIEW};
    cameraBase->streamIds = {cameraBase->STREAM_ID_PREVIEW};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: CancelCapture
  * @tc.desc: CancelCapture, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0200)
{
    std::cout << "==========[test log] CancelCapture, success." << std::endl;
    // Create and get streamOperator information
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
  * @tc.name: CancelCapture
  * @tc.desc: CancelCapture captureID = -1
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0201)
{
    std::cout << "==========[test log] CancelCapture captureID = -1, expected fail." << std::endl;
    // Create and get streamOperator information
    cameraBase->AchieveStreamOperator();
    // start stream
    cameraBase->intents = {PREVIEW};
    cameraBase->StartStream(cameraBase->intents);
    // Get preview
    int captureId = 100;
    std::shared_ptr<CaptureInfo> captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {cameraBase->STREAM_ID_PREVIEW};
    captureInfo->enableShutterCallback_ = false;
    bool isStreaming = true;
    cameraBase->rc = cameraBase->streamOperator->Capture(captureId, captureInfo, isStreaming);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    sleep(3); // waiting 3s, prepare for execute function CancelCapture
    cameraBase->rc = cameraBase->streamOperator->CancelCapture(-1);
    EXPECT_EQ(INVALID_ARGUMENT, cameraBase->rc);
    cameraBase->rc = cameraBase->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success." << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << cameraBase->rc << std::endl;
    }
    // release stream
    cameraBase->rc = cameraBase->streamOperator->ReleaseStreams(captureInfo->streamIds_);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << cameraBase->rc << std::endl;
    }
}

/**
  * @tc.name: AttachBufferQueue
  * @tc.desc: AttachBufferQueue, normal input.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  //*/
TEST_F(UtestHdiFuncTest, camera_hdi_0210)
{
    std::cout << "==========[test log] AttachBufferQueue, normal input." << std::endl;
    cameraBase->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        cameraBase->BufferCallback(b, cameraBase->preview_mode);
        return;
    };
    producer->SetCallback(callback);

    cameraBase->streamInfo = std::make_shared<StreamInfo>();
    cameraBase->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    cameraBase->streamInfo->width_ = 640; // 640:picture width
    cameraBase->streamInfo->height_ = 480; // 480:picture height
    cameraBase->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    cameraBase->streamInfo->dataspace_ = 8; // 8:picture dataspace
    cameraBase->streamInfo->intent_ = PREVIEW;
    cameraBase->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    cameraBase->streamInfos.push_back(cameraBase->streamInfo);
    cameraBase->rc = cameraBase->streamOperator->CreateStreams(cameraBase->streamInfos);
    std::cout << "==========[test log] streamOperator->CreateStreams's RetCode = " << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << cameraBase->rc << std::endl;
    }
    cameraBase->rc = cameraBase->streamOperator->AttachBufferQueue(cameraBase->streamInfo->streamId_, producer);
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] AttachBufferQueue success. " << std::endl;
    } else {
        std::cout << "==========[test log] AttachBufferQueue fail, rc = " << cameraBase->rc << std::endl;
    }
    sleep(3); // waiting 3s, prepare for release stream.
    // release stream
    cameraBase->streamIds = {DEFAULT_STREAM_ID};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: AttachBufferQueue
  * @tc.desc: AttachBufferQueue, streamID is not exist.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0211)
{
    std::cout << "==========[test log] AttachBufferQueue, streamID is not exist.." << std::endl;
    cameraBase->AchieveStreamOperator();
    // Create data stream
    cameraBase->streamInfo = std::make_shared<StreamInfo>();
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this] (std::shared_ptr<SurfaceBuffer> b) {
        cameraBase->BufferCallback(b, cameraBase->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    cameraBase->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    cameraBase->streamInfo->width_ = 640; // 640:picture width
    cameraBase->streamInfo->height_ = 480; // 480:picture height
    cameraBase->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    cameraBase->streamInfo->dataspace_ = 8; // 8:picture dataspace
    cameraBase->streamInfo->intent_ = PREVIEW;
    cameraBase->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    cameraBase->streamInfos.push_back(cameraBase->streamInfo);
    cameraBase->rc = cameraBase->streamOperator->CreateStreams(cameraBase->streamInfos);
    std::cout << "==========[test log] streamOperator->CreateStreams's RetCode = " << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << cameraBase->rc << std::endl;
    }
    cameraBase->rc = cameraBase->streamOperator->AttachBufferQueue(0, producer);
    EXPECT_EQ(true, cameraBase->rc != NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] AttachBufferQueue success. " << std::endl;
    } else {
        std::cout << "==========[test log] AttachBufferQueue fail, rc = " << cameraBase->rc << std::endl;
    }
    sleep(3); // waiting 3s, prepare for release stream.
    // Release the stream
    cameraBase->streamIds = {DEFAULT_STREAM_ID};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: AttachBufferQueue
  * @tc.desc: AttachBufferQueue, producer is nullptr.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0212)
{
    std::cout << "==========[test log] AttachBufferQueue, producer is nullptr." << std::endl;
    cameraBase->AchieveStreamOperator();
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] GetStreamOperator success. " << std::endl;
    } else {
        std::cout << "==========[test log] GetStreamOperator fail, rc = " << cameraBase->rc << std::endl;
    }
    // Create data stream
    cameraBase->streamInfo = std::make_shared<StreamInfo>();
    cameraBase->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    cameraBase->streamInfo->width_ = 640; // 640:picture width
    cameraBase->streamInfo->height_ = 480; // 480:picture height
    cameraBase->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    cameraBase->streamInfo->dataspace_ = 8; // 8:picture dataspace
    cameraBase->streamInfo->intent_ = PREVIEW;
    cameraBase->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    cameraBase->streamInfos.push_back(cameraBase->streamInfo);
    cameraBase->rc = cameraBase->streamOperator->CreateStreams(cameraBase->streamInfos);
    std::cout << "==========[test log] streamOperator->CreateStreams's RetCode = ";
    std::cout << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success. " << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << cameraBase->rc << std::endl;
    }
    cameraBase->rc = cameraBase->streamOperator->AttachBufferQueue(cameraBase->streamInfo->streamId_, nullptr);
    EXPECT_EQ(true, cameraBase->rc != NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] AttachBufferQueue success. " << std::endl;
    } else {
        std::cout << "==========[test log] AttachBufferQueue fail, rc = " << cameraBase->rc << std::endl;
    }
    sleep(3); // waiting 3s, prepare for release stream.
    // release stream
    cameraBase->streamIds = {DEFAULT_STREAM_ID};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: DetachBufferQueue
  * @tc.desc: DetachBufferQueue, normal input.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0220)
{
    std::cout << "==========[test log] DetachBufferQueue, normal input." << std::endl;
    cameraBase->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this] (std::shared_ptr<SurfaceBuffer> b) {
        cameraBase->BufferCallback(b, cameraBase->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    cameraBase->streamInfo = std::make_shared<StreamInfo>();
    cameraBase->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    cameraBase->streamInfo->width_ = 640; // 640:picture width
    cameraBase->streamInfo->height_ = 480; // 480:picture height
    cameraBase->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    cameraBase->streamInfo->dataspace_ = 8; // 8:picture dataspace
    cameraBase->streamInfo->intent_ = PREVIEW;
    cameraBase->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    cameraBase->streamInfos.push_back(cameraBase->streamInfo);
    cameraBase->rc = cameraBase->streamOperator->CreateStreams(cameraBase->streamInfos);
    std::cout << "==========[test log] streamOperator->CreateStreams's RetCode = ";
    std::cout << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    std::cout << "==========[test log] CreateStreams success. " << std::endl;
    cameraBase->rc = cameraBase->streamOperator->AttachBufferQueue(cameraBase->streamInfo->streamId_, producer);
    std::cout << "==========[test log] streamOperator->AttachBufferQueue's RetCode = ";
    std::cout << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    sleep(3); // waiting 3s, prepare for attach bufferQueue.
    std::cout << "==========[test log] AttachBufferQueue success. " << std::endl;
    cameraBase->rc = cameraBase->streamOperator->DetachBufferQueue(cameraBase->streamInfo->streamId_);
    std::cout << "==========[test log] streamOperator->DetachBufferQueue's RetCode = ";
    std::cout << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] DetachBufferQueue success. " << std::endl;
    } else {
        std::cout << "==========[test log] DetachBufferQueue fail, rc = " << cameraBase->rc << std::endl;
    }
    // release stream
    cameraBase->streamIds = {DEFAULT_STREAM_ID};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}

/**
  * @tc.name: DetachBufferQueue
  * @tc.desc: DetachBufferQueue, streamID is not exist.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiFuncTest, camera_hdi_0221)
{
    std::cout << "==========[test log] DetachBufferQueue, streamID is not exist." << std::endl;
    cameraBase->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this] (std::shared_ptr<SurfaceBuffer> b) {
        cameraBase->BufferCallback(b, cameraBase->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    cameraBase->streamInfo = std::make_shared<StreamInfo>();
    cameraBase->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    cameraBase->streamInfo->width_ = 640; // 640:picture width
    cameraBase->streamInfo->height_ = 480; // 480:picture height
    cameraBase->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    cameraBase->streamInfo->dataspace_ = 8; // 8:picture dataspace
    cameraBase->streamInfo->intent_ = PREVIEW;
    cameraBase->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    cameraBase->streamInfos.push_back(cameraBase->streamInfo);
    cameraBase->rc = cameraBase->streamOperator->CreateStreams(cameraBase->streamInfos);
    std::cout << "==========[test log] streamOperator->CreateStreams's RetCode = ";
    std::cout << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    std::cout << "==========[test log] CreateStreams success. " << std::endl;
    cameraBase->rc = cameraBase->streamOperator->AttachBufferQueue(cameraBase->streamInfo->streamId_, producer);
    std::cout << "==========[test log] streamOperator->AttachBufferQueue's RetCode = " << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc == NO_ERROR);
    std::cout << "==========[test log] AttachBufferQueue success. " << std::endl;
    sleep(3); // waiting 3s, prepare for detach bufferQueue.

    cameraBase->rc = cameraBase->streamOperator->DetachBufferQueue(0);
    std::cout << "==========[test log] streamOperator->DetachBufferQueue's RetCode = " << cameraBase->rc << std::endl;
    EXPECT_EQ(true, cameraBase->rc != NO_ERROR);
    if (cameraBase->rc == NO_ERROR) {
        std::cout << "==========[test log] DetachBufferQueue success." << std::endl;
    } else {
        std::cout << "==========[test log] DetachBufferQueue fail, rc = " << cameraBase->rc << std::endl;
    }
    // release stream
    cameraBase->streamIds = {DEFAULT_STREAM_ID};
    cameraBase->StopStream(cameraBase->captureIds, cameraBase->streamIds);
}
