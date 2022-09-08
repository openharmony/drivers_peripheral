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
#include "hdi_iter_test.h"

constexpr int ITEM_CAPACITY_SIZE = 2;
constexpr int DATA_CAPACITY_SIZE = 128;

void UtestHdiIterTest::SetUpTestCase(void)
{}
void UtestHdiIterTest::TearDownTestCase(void)
{}
void UtestHdiIterTest::SetUp(void)
{
    if (display_ == nullptr)
    display_ = std::make_shared<TestDisplay>();
    display_->FBInit();
    display_->Init();
}
void UtestHdiIterTest::TearDown(void)
{
    display_->Close();
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0130)
{
    std::cout << "==========[test log] CreateStreams, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->streamId = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0131)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->streamId = -1, return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = -1;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->streamId = 2147483647, return success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0132)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->streamId = 2147483647, return success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    std::shared_ptr<StreamInfo> streamInfo = std::make_shared<StreamInfo>();
    streamInfo->streamId_ = INVALID_VALUE_TEST;
    streamInfo->width_ = 640; // 640:picture width
    streamInfo->height_ = 480; // 480:picture height
    streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    streamInfo->dataspace_ = 8; // 8:picture dataspace
    streamInfo->intent_ = PREVIEW;
    streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    streamInfo->bufferQueue_ = producer;

    std::vector<std::shared_ptr<StreamInfo>>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->width = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0133)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->width = -1, return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = -1;
    display_->streamInfo->height_ = 640; // 640:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->width = 2147483647, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0134)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->width = 2147483647, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = INVALID_VALUE_TEST;
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->height = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0135)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->height = -1, return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = -1;
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->height = 2147483647, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0136)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->height = 2147483647, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = INVALID_VALUE_TEST;
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->format = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0137)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->format = -1, return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = -1;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->format = 2147483647, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0138)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->format = 2147483647, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = INVALID_VALUE_TEST;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
    EXPECT_EQ(true, display_->rc == NO_ERROR);
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->dataspace = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0139)
{
    std::cout << "==========[test log] CreateStreams, StreamInfo->dataspace = -1, return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = -1;
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->dataspace = 2147483647, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0140)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->dataspace = 2147483647, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = INVALID_VALUE_TEST;
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = PREVIEW, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0141)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->StreamIntent = PREVIEW, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 1080; // 1080:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
    EXPECT_EQ(true, display_->rc == NO_ERROR);
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = VIDEO, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0142)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->StreamIntent = VIDEO, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream1080
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->video_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 1080; // 1080:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = VIDEO;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = STILL_CAPTURE, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0143)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->StreamIntent = STILL_CAPTURE, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->capture_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 1080; // 1080:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = STILL_CAPTURE;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = POST_VIEW;, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0144)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->StreamIntent = POST_VIEW;, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 1080; // 1080:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = POST_VIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = ANALYZE;, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0145)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->StreamIntent = ANALYZE;, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 1080; // 1080:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = ANALYZE;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->StreamIntent = Camera::CUSTOM;, not support.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0146)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->StreamIntent = Camera::CUSTOM;, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    std::shared_ptr<StreamInfo> streamInfo = std::make_shared<StreamInfo>();
    streamInfo->streamId_ = DEFAULT_STREAM_ID;
    streamInfo->width_ = 640; // 640:picture width
    streamInfo->height_ = 480; // 480:picture height
    streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    streamInfo->dataspace_ = 8; // 8:picture dataspace
    streamInfo->intent_ = Camera::CUSTOM;
    streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    streamInfo->bufferQueue_ = producer;

    std::vector<std::shared_ptr<StreamInfo>>().swap(streamInfos);
    streamInfos.push_back(streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc != NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->tunneledMode = false, success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0147)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->tunneledMode = false, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 1080; // 1080:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = Camera::CUSTOM;
    display_->streamInfo->tunneledMode_ = false;
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == Camera::METHOD_NOT_SUPPORTED);
    if (display_->rc == Camera::METHOD_NOT_SUPPORTED) {
        std::cout << "==========[test log] CreateStreams fail." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams success"<< std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->minFrameDuration = -1, return error.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0148)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->minFrameDuration = -1, return error." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 1080; // 1080:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = Camera::CUSTOM;
    display_->streamInfo->tunneledMode_ = 0;
    display_->streamInfo->minFrameDuration_ = -1;
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(INVALID_ARGUMENT, display_->rc);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CreateStreams
  * @tc.desc: CreateStreams, StreamInfo->minFrameDuration = 2147483647, fail.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0149)
{
    std::cout << "==========[test log] CreateStreams,";
    std::cout << "StreamInfo->minFrameDuration = 2147483647, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 0;
    display_->streamInfo->minFrameDuration_ = INVALID_VALUE_TEST;
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    std::cout << "streamOperator->CreateStreams's RetCode = " << display_->rc << std::endl;
    EXPECT_EQ(true, display_->rc == Camera::METHOD_NOT_SUPPORTED);
    if (display_->rc == Camera::METHOD_NOT_SUPPORTED) {
        std::cout << "==========[test log] CreateStreams fail." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams success, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: ReleaseStreams
  * @tc.desc: ReleaseStreams,streamID normal.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0160)
{
    std::cout << "==========[test log] ReleaseStreams,streamID normal." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(display_->streamInfo->streamId_);
    display_->rc = display_->streamOperator->ReleaseStreams(streamIds);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: ReleaseStreams
  * @tc.desc: ReleaseStreams-> streamID = -1, expected success.
  * @tc.level: Level2
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0161)
{
    std::cout << "==========[test log] ReleaseStreams-> streamID = -1, expected success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    // Distribution stream
    display_->rc = display_->streamOperator->CommitStreams(Camera::NORMAL, nullptr);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    // Get preview
    int captureId = 2001;
    std::shared_ptr<CaptureInfo> captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {DEFAULT_STREAM_ID};
    captureInfo->enableShutterCallback_ = false;
    display_->rc = display_->streamOperator->Capture(captureId, captureInfo, true);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    sleep(5); // waiting 5s, prepare for execute function CancelCapture
    display_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, display_->rc == NO_ERROR);

    // release stream
    display_->rc = display_->streamOperator->ReleaseStreams({-1});
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    std::cout << "streamOperator->ReleaseStreams's RetCode = " << display_->rc << std::endl;
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CommitStreams
  * @tc.desc: CommitStreams, input normal.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0170)
{
    std::cout << "==========[test log] CommitStreams, input normal." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }

    std::shared_ptr<CameraMetadata> modeSetting =
        std::make_shared<CameraMetadata>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
    // Distribution stream
    display_->rc = display_->streamOperator->CommitStreams(Camera::NORMAL, modeSetting);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CommitStreams fail, rc = " << display_->rc << std::endl;
    }
}

/**
  * @tc.name: CommitStreams
  * @tc.desc: CommitStreams, modeSetting is nullptr.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0171)
{
    std::cout << "==========[test log] CommitStreams, input normal." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::shared_ptr<CameraMetadata> modeSetting = nullptr;

    // Distribution stream
    display_->rc = display_->streamOperator->CommitStreams(Camera::NORMAL, modeSetting);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CommitStreams fail, rc = " << display_->rc << std::endl;
    }
    // Get preview
    int captureId = 2001;
    std::shared_ptr<CaptureInfo> captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {DEFAULT_STREAM_ID};
    captureInfo->enableShutterCallback_ = false;
    display_->rc = display_->streamOperator->Capture(captureId, captureInfo, true);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] Capture success." << std::endl;
    } else {
        std::cout << "==========[test log] Capture fail, rc = " << display_->rc << std::endl;
    }
    sleep(5); // waiting 5s, prepare for execute function CancelCapture
    display_->streamOperator->CancelCapture(captureId);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CancelCapture success." << std::endl;
    } else {
        std::cout << "==========[test log] CancelCapture fail, rc = " << display_->rc << std::endl;
    }
    // release stream
    display_->rc = display_->streamOperator->ReleaseStreams(captureInfo->streamIds_);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] ReleaseStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] ReleaseStreams fail, rc = " << display_->rc << std::endl;
    }
    // Turn off the device
    display_->cameraDevice->Close();
    std::cout << "==========[test log] cameraDevice->Close" << std::endl;
}

/**
  * @tc.name: GetStreamAttributes
  * @tc.desc: GetStreamAttributes, success.
  * @tc.level: Level1
  * @tc.size: MediumTest
  * @tc.type: Function
  */
TEST_F(UtestHdiIterTest, camera_hdi_0180)
{
    std::cout << "==========[test log] GetStreamAttributes, success." << std::endl;
    // Create and get streamOperator information
    display_->AchieveStreamOperator();
    // Create data stream
    std::shared_ptr<IBufferProducer> producer = IBufferProducer::CreateBufferQueue();
    producer->SetQueueSize(8); // 8:set bufferQueue size
    if (producer->GetQueueSize() != 8) { // 8:get bufferQueue size
        std::cout << "~~~~~~~" << std::endl;
    }
    auto callback = [this](std::shared_ptr<SurfaceBuffer> b) {
        display_->BufferCallback(b, display_->preview_mode);
        return;
    };
    producer->SetCallback(callback);
    std::vector<std::shared_ptr<StreamInfo>> streamInfos;
    display_->streamInfo = std::make_shared<StreamInfo>();
    display_->streamInfo->streamId_ = DEFAULT_STREAM_ID;
    display_->streamInfo->width_ = 640; // 640:picture width
    display_->streamInfo->height_ = 480; // 480:picture height
    display_->streamInfo->format_ = CAMERA_FORMAT_YUYV_422_PKG;
    display_->streamInfo->dataspace_ = 8; // 8:picture dataspace
    display_->streamInfo->intent_ = PREVIEW;
    display_->streamInfo->tunneledMode_ = 5; // 5:tunnel mode
    display_->streamInfo->bufferQueue_ = producer;
    streamInfos.push_back(display_->streamInfo);
    display_->rc = display_->streamOperator->CreateStreams(streamInfos);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CreateStreams fail, rc = " << display_->rc << std::endl;
    }
    std::shared_ptr<CameraMetadata> modeSetting = nullptr;

    // Distribution stream
    display_->rc = display_->streamOperator->CommitStreams(Camera::NORMAL, modeSetting);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log] CommitStreams fail, rc = " << display_->rc << std::endl;
    }

    std::vector<std::shared_ptr<OHOS::Camera::StreamAttribute>> attributes;
    display_->rc = display_->streamOperator->GetStreamAttributes(attributes);
    EXPECT_EQ(true, display_->rc == NO_ERROR);
    std::cout << "==========[test log] GetStreamAttributes, rc = " << display_->rc << std::endl;
    if (display_->rc == NO_ERROR) {
        std::cout << "==========[test log] GetStreamAttributes success." << std::endl;
    } else {
        std::cout << "==========[test log] GetStreamAttributes fail, rc = " << display_->rc << std::endl;
    }
}