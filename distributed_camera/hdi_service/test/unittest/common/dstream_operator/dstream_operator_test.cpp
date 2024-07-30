/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "dstream_operator.h"
#include "distributed_hardware_log.h"
#include "mock_dstream_operator_callback.h"
#include "metadata_utils.h"
#include "stream_consumer.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class DStreamOperatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

    OHOS::sptr<DStreamOperator> dstreamOperator_ = nullptr;
};

constexpr const char* TEST_DEV_ID = "bb536a637105409e904d4da83790a4a7";
constexpr const char* TEST_CAM_ID = "camera_0";
constexpr const char* TEST_ABILITY_VALUE = R"({"CodecType": ["avenc_mpeg4"],
    "Position": "BACK",
    "ProtocolVer": "1.0",
    "MetaData": "",
    "Photo": {
        "OutputFormat": [2, 4],
        "Resolution": {
            "2": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
            "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"],
            "4": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
            "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"]
        }
    },
    "Preview": {
        "OutputFormat": [2, 3],
        "Resolution": {
            "2": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
                "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"],
            "3": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
                "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"]
        }
    },
    "Video": {
        "OutputFormat": [2, 3],
        "Resolution": {
            "2": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
                "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"],
            "3": ["1920*1080", "1504*720", "1440*1080", "1280*960", "1280*720", "1232*768", "1152*720", "960*720",
                "960*544", "880*720", "720*720", "720*480", "640*480", "352*288", "320*240"]
        }
    }})";
constexpr int TEST_STREAMID = 1001;
constexpr int TEST_HEIGHT = 480;
constexpr int TEST_WIDTH = 640;
constexpr int TEST_DATASPACE = 8;
constexpr int TEST_TUNNELEDMODE = 5;
constexpr int TEST_SLEEPTIME = 3;

void DStreamOperatorTest::SetUpTestCase(void)
{
}

void DStreamOperatorTest::TearDownTestCase(void)
{
}

void DStreamOperatorTest::SetUp(void)
{
    std::shared_ptr<DMetadataProcessor> dMetadataProcessor = std::make_shared<DMetadataProcessor>();
    dMetadataProcessor->InitDCameraAbility(TEST_ABILITY_VALUE);
    dstreamOperator_ = sptr<DStreamOperator>(new (std::nothrow) DStreamOperator(dMetadataProcessor));
}

void DStreamOperatorTest::TearDown(void)
{
}

/**
 * @tc.name: dstream_operator_test_001
 * @tc.desc: Verify InitOutputConfigurations
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_001, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    DHBase dhBase;
    dhBase.deviceId_ = TEST_DEV_ID;
    dhBase.dhId_ = TEST_CAM_ID;
    DCamRetCode rc = dstreamOperator_->InitOutputConfigurations(dhBase, TEST_ABILITY_VALUE, TEST_ABILITY_VALUE);
    EXPECT_EQ(rc, SUCCESS);
}

/**
 * @tc.name: dstream_operator_test_002
 * @tc.desc: Verify IsStreamsSupported
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_002, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    OperationMode mode = NORMAL;
    std::vector<uint8_t> modeSetting;
    // Configure stream information
    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_STREAMID;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
    streamInfo.encodeType_ = EncodeType::ENCODE_TYPE_H264;
    StreamSupportType pType;
    std::vector<StreamInfo> stre;
    stre.push_back(streamInfo);
    int32_t rc = dstreamOperator_->IsStreamsSupported(mode, modeSetting, stre, pType);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_003
 * @tc.desc: Verify CreateStreams
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_003, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_STREAMID;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    streamInfo.bufferQueue_ = nullptr;
    streamInfo.encodeType_ = EncodeType::ENCODE_TYPE_NULL;
    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(streamInfo);
    int32_t rc = dstreamOperator_->CreateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_004
 * @tc.desc: Verify ReleaseStreams
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_004, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_STREAMID;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    std::shared_ptr<StreamConsumer> streamConsumer = std::make_shared<StreamConsumer>();
    sptr<OHOS::IBufferProducer> producer = streamConsumer->CreateProducer();
    streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable(producer));
    streamInfo.bufferQueue_->producer_->SetQueueSize(TEST_DATASPACE);
    streamInfo.encodeType_ = EncodeType::ENCODE_TYPE_NULL;
    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(streamInfo);
    int32_t rc = dstreamOperator_->CreateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    rc = dstreamOperator_->ReleaseStreams(streamIds);
    EXPECT_NE(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_005
 * @tc.desc: Verify GetStreamAttributes
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_005, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_STREAMID;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    std::shared_ptr<StreamConsumer> streamConsumer = std::make_shared<StreamConsumer>();
    sptr<OHOS::IBufferProducer> producer = streamConsumer->CreateProducer();
    streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable(producer));
    streamInfo.bufferQueue_->producer_->SetQueueSize(TEST_DATASPACE);
    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(streamInfo);
    int32_t rc = dstreamOperator_->CreateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);

    std::vector<StreamAttribute> attributes;
    rc = dstreamOperator_->GetStreamAttributes(attributes);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    rc = dstreamOperator_->ReleaseStreams(streamIds);
    EXPECT_NE(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_006
 * @tc.desc: Verify AttachBufferQueue
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_006, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_STREAMID;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    streamInfo.bufferQueue_ = nullptr;
    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(streamInfo);
    int32_t rc = dstreamOperator_->CreateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);

    sptr<BufferProducerSequenceable> bufferProducer = nullptr;;
    rc = dstreamOperator_->AttachBufferQueue(streamInfo.streamId_, bufferProducer);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    rc = dstreamOperator_->ReleaseStreams(streamIds);
    EXPECT_NE(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_007
 * @tc.desc: Verify DetachBufferQueue
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_007, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_STREAMID;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    std::shared_ptr<StreamConsumer> streamConsumer = std::make_shared<StreamConsumer>();
    sptr<OHOS::IBufferProducer> producer = streamConsumer->CreateProducer();
    streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable(producer));
    streamInfo.bufferQueue_->producer_->SetQueueSize(TEST_DATASPACE);
    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(streamInfo);
    int32_t rc = dstreamOperator_->CreateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);

    sptr<BufferProducerSequenceable> bufferProducer(new BufferProducerSequenceable(producer));
    rc = dstreamOperator_->AttachBufferQueue(streamInfo.streamId_, bufferProducer);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);

    sleep(TEST_SLEEPTIME);
    rc = dstreamOperator_->DetachBufferQueue(streamInfo.streamId_);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    rc = dstreamOperator_->ReleaseStreams(streamIds);
    EXPECT_NE(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_008
 * @tc.desc: Verify ChangeToOfflineStream
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_008, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_STREAMID;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    std::shared_ptr<StreamConsumer> streamConsumer = std::make_shared<StreamConsumer>();
    sptr<OHOS::IBufferProducer> producer = streamConsumer->CreateProducer();
    streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable(producer));
    streamInfo.bufferQueue_->producer_->SetQueueSize(TEST_DATASPACE);
    std::vector<StreamInfo> streamInfos;
    streamInfos.push_back(streamInfo);
    int32_t rc = dstreamOperator_->CreateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);

    int32_t captureId = 1000;
    OHOS::sptr<IStreamOperatorCallback> offlineStreamOperatorCallback(new (std::nothrow) MockDStreamOperatorCallback());
    std::vector<int> offlineIds;
    offlineIds.push_back(captureId);
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
    rc = dstreamOperator_->ChangeToOfflineStream(offlineIds, offlineStreamOperatorCallback, offlineStreamOperator);
    EXPECT_EQ(true, offlineStreamOperator == nullptr);

    // release stream
    std::vector<int> streamIds;
    streamIds.push_back(streamInfo.streamId_);
    rc = dstreamOperator_->ReleaseStreams(streamIds);
    EXPECT_NE(rc, CamRetCode::NO_ERROR);
}
}
}