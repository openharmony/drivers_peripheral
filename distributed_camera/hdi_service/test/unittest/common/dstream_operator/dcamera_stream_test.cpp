/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "dcamera_stream_test.h"

#include "dcamera_stream.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DCameraStreamTest::SetUpTestCase(void)
{
}

void DCameraStreamTest::TearDownTestCase(void)
{
}

void DCameraStreamTest::SetUp(void)
{
}

void DCameraStreamTest::TearDown(void)
{
}

/**
 * @tc.name: InitDCameraStream_001
 * @tc.desc: Verify InitDCameraStream
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, InitDCameraStream_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    StreamInfo info;
    info.streamId_ = -1;
    auto ret = dcStream->InitDCameraStream(info);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    info.streamId_ = 1;
    info.width_ = -1;
    ret = dcStream->InitDCameraStream(info);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    info.width_ = 1;
    info.height_ = -1;
    ret = dcStream->InitDCameraStream(info);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    info.height_ = 1;
    info.format_ = -1;
    ret = dcStream->InitDCameraStream(info);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    info.format_ = 1;
    info.dataspace_ = -1;
    ret = dcStream->InitDCameraStream(info);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: InitDCameraBufferManager_001
 * @tc.desc: Verify InitDCameraBufferManager
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, InitDCameraBufferManager_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->dcStreamInfo_ = nullptr;
    auto ret = dcStream->InitDCameraBufferManager();
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: GetDCameraStreamInfo_001
 * @tc.desc: Verify GetDCameraStreamInfo
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, GetDCameraStreamInfo_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    shared_ptr<StreamInfo> info = nullptr;
    dcStream->dcStreamInfo_ = nullptr;
    auto ret = dcStream->GetDCameraStreamInfo(info);
    EXPECT_EQ(ret, DCamRetCode::FAILED);

    dcStream->dcStreamInfo_ = std::make_shared<StreamInfo>();
    ret = dcStream->GetDCameraStreamInfo(info);
    EXPECT_EQ(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: ReleaseDCameraBufferQueue_001
 * @tc.desc: Verify ReleaseDCameraBufferQueue
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, ReleaseDCameraBufferQueue_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->dcStreamInfo_ = nullptr;
    auto ret = dcStream->ReleaseDCameraBufferQueue();
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: FinishCommitStream_001
 * @tc.desc: Verify FinishCommitStream
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, FinishCommitStream_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->isBufferMgrInited_ = true;
    auto ret = dcStream->FinishCommitStream();
    EXPECT_EQ(ret, DCamRetCode::SUCCESS);

    dcStream->isBufferMgrInited_ = false;
    dcStream->dcStreamProducer_ = nullptr;
    ret = dcStream->FinishCommitStream();
    EXPECT_EQ(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: CheckRequestParam_001
 * @tc.desc: Verify CheckRequestParam
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, CheckRequestParam_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->isBufferMgrInited_ = true;
    auto ret = dcStream->CheckRequestParam();
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    dcStream->isBufferMgrInited_ = false;
    dcStream->dcStreamInfo_ = nullptr;
    ret = dcStream->CheckRequestParam();
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    dcStream->dcStreamInfo_ = std::make_shared<StreamInfo>();
    dcStream->dcStreamProducer_ = nullptr;
    ret = dcStream->CheckRequestParam();
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: GetNextRequest_001
 * @tc.desc: Verify GetNextRequest
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, GetNextRequest_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->isBufferMgrInited_ = true;
    auto ret = dcStream->GetNextRequest();
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: SurfaceBufferToDImageBuffer_001
 * @tc.desc: Verify SurfaceBufferToDImageBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, SurfaceBufferToDImageBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    OHOS::sptr<OHOS::SyncFence> syncFence = nullptr;
    dcStream->dcStreamProducer_ = nullptr;
    auto ret = dcStream->SurfaceBufferToDImageBuffer(surfaceBuffer, syncFence);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: SurfaceBufferToDImageBuffer_002
 * @tc.desc: Verify SurfaceBufferToDImageBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, SurfaceBufferToDImageBuffer_002, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    OHOS::sptr<OHOS::IBufferProducer> producer = nullptr;
    dcStream->dcStreamProducer_ = OHOS::Surface::CreateSurfaceAsProducer(producer);
    dcStream->dcStreamInfo_ = std::make_shared<StreamInfo>();
    dcStream->dcStreamInfo_->streamId_ = 1;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = OHOS::SurfaceBuffer::Create();
    OHOS::sptr<OHOS::SyncFence> syncFence = nullptr;
    auto ret = dcStream->SurfaceBufferToDImageBuffer(surfaceBuffer, syncFence);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: SurfaceBufferToDImageBuffer_003
 * @tc.desc: Verify SurfaceBufferToDImageBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, SurfaceBufferToDImageBuffer_003, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    OHOS::sptr<OHOS::IBufferProducer> producer = nullptr;
    dcStream->dcStreamProducer_ = OHOS::Surface::CreateSurfaceAsProducer(producer);
    dcStream->dcStreamInfo_ = nullptr;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = OHOS::SurfaceBuffer::Create();
    OHOS::sptr<OHOS::SyncFence> syncFence = new OHOS::SyncFence(-1);
    auto ret = dcStream->SurfaceBufferToDImageBuffer(surfaceBuffer, syncFence);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: SurfaceBufferToDImageBuffer_004
 * @tc.desc: Verify SurfaceBufferToDImageBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, SurfaceBufferToDImageBuffer_004, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    OHOS::sptr<OHOS::IBufferProducer> producer = nullptr;
    dcStream->dcStreamProducer_ = OHOS::Surface::CreateSurfaceAsProducer(producer);
    dcStream->dcStreamInfo_ = std::make_shared<StreamInfo>();
    dcStream->dcStreamInfo_->streamId_ = 1;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = OHOS::SurfaceBuffer::Create();
    OHOS::sptr<OHOS::SyncFence> syncFence = new OHOS::SyncFence(-1);
    dcStream->dcStreamBufferMgr_ = nullptr;
    auto ret = dcStream->SurfaceBufferToDImageBuffer(surfaceBuffer, syncFence);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: GetDCameraBuffer_001
 * @tc.desc: Verify GetDCameraBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, GetDCameraBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    DCameraBuffer buffer;
    dcStream->isCancelBuffer_ = true;
    auto ret = dcStream->GetDCameraBuffer(buffer);
    EXPECT_EQ(ret, DCamRetCode::FAILED);

    dcStream->isCancelBuffer_ = false;
    dcStream->isCancelCapture_ = true;
    ret = dcStream->GetDCameraBuffer(buffer);
    EXPECT_EQ(ret, DCamRetCode::FAILED);

    dcStream->isCancelCapture_ = false;
    dcStream->isBufferMgrInited_ = false;
    ret = dcStream->GetDCameraBuffer(buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: FlushDCameraBuffer_001
 * @tc.desc: Verify FlushDCameraBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, FlushDCameraBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    DCameraBuffer buffer;
    dcStream->bufferConfigMap_.clear();
    auto ret = dcStream->FlushDCameraBuffer(buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: ReturnDCameraBuffer_001
 * @tc.desc: Verify ReturnDCameraBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, ReturnDCameraBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    DCameraBuffer buffer;
    dcStream->bufferConfigMap_.clear();
    auto ret = dcStream->ReturnDCameraBuffer(buffer);
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: SetSurfaceBuffer_001
 * @tc.desc: Verify SetSurfaceBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, SetSurfaceBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    DCameraBuffer buffer;
    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    dcStream->dcStreamInfo_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(dcStream->SetSurfaceBuffer(surfaceBuffer, buffer));

    dcStream->dcStreamInfo_ = std::make_shared<StreamInfo>();
    EXPECT_NO_FATAL_FAILURE(dcStream->SetSurfaceBuffer(surfaceBuffer, buffer));
}

/**
 * @tc.name: DoCapture_001
 * @tc.desc: Verify DoCapture
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, DoCapture_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->dcStreamInfo_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(dcStream->DoCapture());

    dcStream->dcStreamInfo_ = std::make_shared<StreamInfo>();
    EXPECT_NO_FATAL_FAILURE(dcStream->DoCapture());
}

/**
 * @tc.name: CancelCaptureWait_001
 * @tc.desc: Verify CancelCaptureWait
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, CancelCaptureWait_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->dcStreamInfo_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(dcStream->CancelCaptureWait());

    dcStream->dcStreamInfo_ = std::make_shared<StreamInfo>();
    dcStream->isCancelCapture_ = true;
    EXPECT_NO_FATAL_FAILURE(dcStream->CancelCaptureWait());

    dcStream->isCancelCapture_ = false;
    dcStream->captureBufferCount_ = 0;
    EXPECT_NO_FATAL_FAILURE(dcStream->CancelCaptureWait());
}

/**
 * @tc.name: CancelDCameraBuffer_001
 * @tc.desc: Verify CancelDCameraBuffer
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, CancelDCameraBuffer_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->dcStreamInfo_ = nullptr;
    auto ret = dcStream->CancelDCameraBuffer();
    EXPECT_EQ(ret, DCamRetCode::INVALID_ARGUMENT);

    dcStream->dcStreamInfo_ = std::make_shared<StreamInfo>();
    dcStream->dcStreamBufferMgr_ = nullptr;
    ret = dcStream->CancelDCameraBuffer();
    EXPECT_EQ(ret, DCamRetCode::SUCCESS);

    dcStream->dcStreamBufferMgr_ = std::make_shared<DBufferManager>();
    dcStream->dcStreamProducer_ = nullptr;
    ret = dcStream->CancelDCameraBuffer();
    EXPECT_EQ(ret, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: HasBufferQueue_001
 * @tc.desc: Verify HasBufferQueue
 * @tc.type: FUNC
 */
HWTEST_F(DCameraStreamTest, HasBufferQueue_001, TestSize.Level1)
{
    std::shared_ptr<DCameraStream> dcStream = std::make_shared<DCameraStream>();
    ASSERT_NE(nullptr, dcStream);
    dcStream->dcStreamProducer_ = nullptr;
    auto ret = dcStream->HasBufferQueue();
    EXPECT_EQ(ret, false);
}
}
}
