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

constexpr int TEST_NORMAL_MODE = 0;
constexpr int TEST_INVALID_MODE = 1;
constexpr int TEST_STREAMID = 1001;
constexpr int TEST_INVALID_STREAMID = -1;
constexpr int TEST_HEIGHT = 480;
constexpr int TEST_WIDTH = 640;
constexpr int TEST_DATASPACE = 8;
constexpr int TEST_TUNNELEDMODE = 5;
constexpr int TEST_SLEEPTIME = 3;
const uint32_t CAPACITY_MAX_SIZE = 5;

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

    // normal stream
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

/**
 * @tc.name: dstream_operator_test_009
 * @tc.desc: Verify IsStreamsSupported
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_009, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    // same streamId
    OperationMode mode = NORMAL;
    std::vector<uint8_t> modeSetting;
    // Configure stream information
    struct StreamInfo streamInfo1;
    streamInfo1.streamId_ = TEST_STREAMID;
    streamInfo1.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo1.height_ = TEST_HEIGHT;
    streamInfo1.width_ = TEST_WIDTH;
    streamInfo1.dataspace_ = TEST_DATASPACE;
    streamInfo1.intent_ = StreamIntent::PREVIEW;
    streamInfo1.tunneledMode_ = TEST_TUNNELEDMODE;
    streamInfo1.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
    streamInfo1.encodeType_ = EncodeType::ENCODE_TYPE_H264;

    struct StreamInfo streamInfo2;
    streamInfo2.streamId_ = TEST_STREAMID;
    streamInfo2.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo2.height_ = TEST_HEIGHT;
    streamInfo2.width_ = TEST_WIDTH;
    streamInfo2.dataspace_ = TEST_DATASPACE;
    streamInfo2.intent_ = StreamIntent::PREVIEW;
    streamInfo2.tunneledMode_ = TEST_TUNNELEDMODE;
    streamInfo2.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
    streamInfo2.encodeType_ = EncodeType::ENCODE_TYPE_H264;

    StreamSupportType pType;
    std::vector<StreamInfo> stre;
    stre.push_back(streamInfo1);
    stre.push_back(streamInfo2);
    int32_t rc = dstreamOperator_->IsStreamsSupported(mode, modeSetting, stre, pType);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_010
 * @tc.desc: Verify IsStreamsSupported
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_010, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    // invalid stream
    OperationMode mode = NORMAL;
    std::vector<uint8_t> modeSetting;
    StreamSupportType pType;
    std::vector<StreamInfo> stre;
    int32_t rc = dstreamOperator_->IsStreamsSupported(mode, modeSetting, stre, pType);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_011
 * @tc.desc: Verify IsStreamsSupported
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_011, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    // invalid mode
    OperationMode mode = static_cast<OperationMode>(TEST_INVALID_MODE);
    std::vector<uint8_t> modeSetting = {0x01, 0x02};
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
 * @tc.name: dstream_operator_test_012
 * @tc.desc: Verify IsStreamsSupported
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_012, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    // more streamId
    OperationMode mode = NORMAL;
    std::vector<uint8_t> modeSetting;
    // Configure stream information
    std::vector<StreamInfo> stre;
    for (int i = 0; i < 100; i++) {
        struct StreamInfo streamInfo;
        streamInfo.streamId_ = i;
        streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
        streamInfo.height_ = TEST_HEIGHT;
        streamInfo.width_ = TEST_WIDTH;
        streamInfo.dataspace_ = TEST_DATASPACE;
        streamInfo.intent_ = StreamIntent::PREVIEW;
        streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
        streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
        streamInfo.encodeType_ = EncodeType::ENCODE_TYPE_H264;
        stre.push_back(streamInfo);
    }
    StreamSupportType pType;
    int32_t rc = dstreamOperator_->IsStreamsSupported(mode, modeSetting, stre, pType);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_013
 * @tc.desc: Verify IsStreamsSupported_V1_1
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_013, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    // normal stream
    OperationMode_V1_1 mode = static_cast<OperationMode_V1_1>(TEST_NORMAL_MODE);
    std::vector<uint8_t> modeSetting;
    StreamInfo_V1_1 streamInfo_V1_1;
    std::vector<StreamInfo_V1_1> infos;
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
    streamInfo_V1_1.v1_0 = streamInfo;
    infos.push_back(streamInfo_V1_1);
    StreamSupportType pType;
    int32_t rc = dstreamOperator_->IsStreamsSupported_V1_1(mode, modeSetting, infos, pType);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_014
 * @tc.desc: Verify IsStreamsSupported_V1_1
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_014, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    // same streamId
    OperationMode_V1_1 mode = static_cast<OperationMode_V1_1>(TEST_NORMAL_MODE);
    std::vector<uint8_t> modeSetting;
    StreamInfo_V1_1 streamInfo_V1_1_a;
    StreamInfo_V1_1 streamInfo_V1_1_b;
    std::vector<StreamInfo_V1_1> infos;

    // Configure stream information
    struct StreamInfo streamInfo1;
    streamInfo1.streamId_ = TEST_STREAMID;
    streamInfo1.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo1.height_ = TEST_HEIGHT;
    streamInfo1.width_ = TEST_WIDTH;
    streamInfo1.dataspace_ = TEST_DATASPACE;
    streamInfo1.intent_ = StreamIntent::PREVIEW;
    streamInfo1.tunneledMode_ = TEST_TUNNELEDMODE;
    streamInfo1.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
    streamInfo1.encodeType_ = EncodeType::ENCODE_TYPE_H264;

    struct StreamInfo streamInfo2;
    streamInfo2.streamId_ = TEST_STREAMID;
    streamInfo2.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo2.height_ = TEST_HEIGHT;
    streamInfo2.width_ = TEST_WIDTH;
    streamInfo2.dataspace_ = TEST_DATASPACE;
    streamInfo2.intent_ = StreamIntent::PREVIEW;
    streamInfo2.tunneledMode_ = TEST_TUNNELEDMODE;
    streamInfo2.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
    streamInfo2.encodeType_ = EncodeType::ENCODE_TYPE_H264;

    streamInfo_V1_1_a.v1_0 = streamInfo1;
    streamInfo_V1_1_b.v1_0 = streamInfo2;
    infos.push_back(streamInfo_V1_1_a);
    infos.push_back(streamInfo_V1_1_b);
    StreamSupportType pType;
    int32_t rc = dstreamOperator_->IsStreamsSupported_V1_1(mode, modeSetting, infos, pType);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_015
 * @tc.desc: Verify IsStreamsSupported_V1_1
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_015, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    // invalid stream
    OperationMode_V1_1 mode = static_cast<OperationMode_V1_1>(TEST_NORMAL_MODE);
    std::vector<uint8_t> modeSetting;
    std::vector<StreamInfo_V1_1> infos;
    StreamSupportType pType;
    int32_t rc = dstreamOperator_->IsStreamsSupported_V1_1(mode, modeSetting, infos, pType);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_016
 * @tc.desc: Verify IsStreamsSupported_V1_1
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_016, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    // invalid mode
    OperationMode_V1_1 mode = static_cast<OperationMode_V1_1>(TEST_INVALID_MODE);
    std::vector<uint8_t> modeSetting = {0x01, 0x02};
    StreamInfo_V1_1 streamInfo_V1_1;
    std::vector<StreamInfo_V1_1> infos;
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
    streamInfo_V1_1.v1_0 = streamInfo;
    infos.push_back(streamInfo_V1_1);
    StreamSupportType pType;
    int32_t rc = dstreamOperator_->IsStreamsSupported_V1_1(mode, modeSetting, infos, pType);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_017
 * @tc.desc: Verify IsStreamsSupported_V1_1
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_017, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);

    // more streamId
    OperationMode_V1_1 mode = static_cast<OperationMode_V1_1>(TEST_NORMAL_MODE);
    std::vector<uint8_t> modeSetting;
    // Configure stream information
    StreamInfo_V1_1 streamInfo_V1_1;
    std::vector<StreamInfo> stre;
    for (int i = 0; i < 100; i++) {
        struct StreamInfo streamInfo;
        streamInfo.streamId_ = i;
        streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
        streamInfo.height_ = TEST_HEIGHT;
        streamInfo.width_ = TEST_WIDTH;
        streamInfo.dataspace_ = TEST_DATASPACE;
        streamInfo.intent_ = StreamIntent::PREVIEW;
        streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
        streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
        streamInfo.encodeType_ = EncodeType::ENCODE_TYPE_H264;
        stre.push_back(streamInfo);
    }

    std::vector<StreamInfo_V1_1> infos;
    for (int i = 0; i < 100; i++) {
        streamInfo_V1_1.v1_0 = stre[i];
        infos.push_back(streamInfo_V1_1);
    }
    StreamSupportType pType;
    int32_t rc = dstreamOperator_->IsStreamsSupported_V1_1(mode, modeSetting, infos, pType);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
    EXPECT_EQ(pType, DYNAMIC_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_018
 * @tc.desc: Verify ExtractStreamInfo
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_018, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    dstreamOperator_->dcStreamInfoMap_.clear();
    std::vector<DCStreamInfo> dCameraStreams;
    int32_t rc = dstreamOperator_->ExtractStreamInfo(dCameraStreams);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_019
 * @tc.desc: Verify ExtractStreamInfo
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_019, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    dstreamOperator_->dcStreamInfoMap_.clear();
    std::vector<DCStreamInfo> dCameraStreams;
    std::shared_ptr<DCStreamInfo> dstStreamInfo1 = std::make_shared<DCStreamInfo>();
    std::shared_ptr<DCStreamInfo> dstStreamInfo2 = std::make_shared<DCStreamInfo>();

    dstStreamInfo1->streamId_ = TEST_STREAMID;
    dstStreamInfo1->width_ = TEST_WIDTH;
    dstStreamInfo1->height_ = TEST_HEIGHT;
    dstStreamInfo1->stride_ = TEST_HEIGHT;
    dstStreamInfo1->format_ = PIXEL_FMT_YCRCB_420_SP;
    dstStreamInfo1->dataspace_ = TEST_DATASPACE;
    dstStreamInfo1->encodeType_ = DCEncodeType::ENCODE_TYPE_H264;
    dstStreamInfo1->type_ = DCStreamType::CONTINUOUS_FRAME;

    dstStreamInfo2->streamId_ = TEST_STREAMID;
    dstStreamInfo2->width_ = TEST_WIDTH;
    dstStreamInfo2->height_ = TEST_HEIGHT;
    dstStreamInfo2->stride_ = TEST_HEIGHT;
    dstStreamInfo2->format_ = PIXEL_FMT_YCRCB_420_SP;
    dstStreamInfo2->dataspace_ = TEST_DATASPACE;
    dstStreamInfo2->encodeType_ = DCEncodeType::ENCODE_TYPE_H264;
    dstStreamInfo2->type_ = DCStreamType::CONTINUOUS_FRAME;

    dstreamOperator_->dcStreamInfoMap_.insert(std::make_pair(1, dstStreamInfo1));
    dstreamOperator_->dcStreamInfoMap_.insert(std::make_pair(2, dstStreamInfo2));
    int32_t rc = dstreamOperator_->ExtractStreamInfo(dCameraStreams);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_020
 * @tc.desc: Verify ExtractStreamInfo
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_020, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    dstreamOperator_->dcStreamInfoMap_.clear();
    std::vector<DCStreamInfo> dCameraStreams;
    std::shared_ptr<DCStreamInfo> dstStreamInfo1 = nullptr;
    std::shared_ptr<DCStreamInfo> dstStreamInfo2 = std::make_shared<DCStreamInfo>();

    dstStreamInfo2->streamId_ = TEST_STREAMID;
    dstStreamInfo2->width_ = TEST_WIDTH;
    dstStreamInfo2->height_ = TEST_HEIGHT;
    dstStreamInfo2->stride_ = TEST_HEIGHT;
    dstStreamInfo2->format_ = PIXEL_FMT_YCRCB_420_SP;
    dstStreamInfo2->dataspace_ = TEST_DATASPACE;
    dstStreamInfo2->encodeType_ = DCEncodeType::ENCODE_TYPE_H264;
    dstStreamInfo2->type_ = DCStreamType::CONTINUOUS_FRAME;

    dstreamOperator_->dcStreamInfoMap_.insert(std::make_pair(1, dstStreamInfo1));
    dstreamOperator_->dcStreamInfoMap_.insert(std::make_pair(2, dstStreamInfo2));
    int32_t rc = dstreamOperator_->ExtractStreamInfo(dCameraStreams);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_021
 * @tc.desc: Verify ExtractStreamInfo
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_021, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    dstreamOperator_->dcStreamInfoMap_.clear();
    std::vector<DCStreamInfo> dCameraStreams;

    for (int i = 0; i < 10; i++) {
        std::shared_ptr<DCStreamInfo> dstStreamInfo = std::make_shared<DCStreamInfo>();
        dstStreamInfo->streamId_ = TEST_STREAMID + i;
        dstStreamInfo->width_ = TEST_WIDTH;
        dstStreamInfo->height_ = TEST_HEIGHT;
        dstStreamInfo->stride_ = TEST_HEIGHT;
        dstStreamInfo->format_ = PIXEL_FMT_YCRCB_420_SP;
        dstStreamInfo->dataspace_ = TEST_DATASPACE;
        dstStreamInfo->encodeType_ = DCEncodeType::ENCODE_TYPE_H264;
        dstStreamInfo->type_ = DCStreamType::CONTINUOUS_FRAME;
        dstreamOperator_->dcStreamInfoMap_.insert(std::make_pair(i, dstStreamInfo));
    }
    int32_t rc = dstreamOperator_->ExtractStreamInfo(dCameraStreams);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_022
 * @tc.desc: Verify UpdateStreams
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_022, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamInfo_V1_1> streamInfos;
    int32_t rc = dstreamOperator_->UpdateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_023
 * @tc.desc: Verify UpdateStreams
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_023, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamInfo_V1_1> streamInfos;
    StreamInfo_V1_1 streamInfo_V1_1;
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
    streamInfo_V1_1.v1_0 = streamInfo;
    streamInfos.push_back(streamInfo_V1_1);
    int32_t rc = dstreamOperator_->UpdateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_024
 * @tc.desc: Verify UpdateStreams
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_024, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamInfo_V1_1> streamInfos;
    // Configure stream information
    StreamInfo_V1_1 streamInfo_V1_1;
    std::vector<StreamInfo> stre;
    for (int i = 0; i < 100; i++) {
        struct StreamInfo streamInfo;
        streamInfo.streamId_ = i;
        streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
        streamInfo.height_ = TEST_HEIGHT;
        streamInfo.width_ = TEST_WIDTH;
        streamInfo.dataspace_ = TEST_DATASPACE;
        streamInfo.intent_ = StreamIntent::PREVIEW;
        streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
        streamInfo.bufferQueue_ = sptr<BufferProducerSequenceable>(new BufferProducerSequenceable());
        streamInfo.encodeType_ = EncodeType::ENCODE_TYPE_H264;
        stre.push_back(streamInfo);
    }

    for (int i = 0; i < 100; i++) {
        streamInfo_V1_1.v1_0 = stre[i];
        streamInfos.push_back(streamInfo_V1_1);
    }
    int32_t rc = dstreamOperator_->UpdateStreams(streamInfos);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_025
 * @tc.desc: Verify ConfirmCapture
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_025, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t cId = 0;
    int32_t rc = dstreamOperator_->ConfirmCapture(cId);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_026
 * @tc.desc: Verify CommitStreams_V1_1
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_026, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    OperationMode_V1_1 mode = static_cast<OperationMode_V1_1>(TEST_NORMAL_MODE);
    std::vector<uint8_t> modeSetting;
    int32_t rc = dstreamOperator_->CommitStreams_V1_1(mode, modeSetting);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_027
 * @tc.desc: Verify CommitStreams_V1_1
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_027, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    OperationMode_V1_1 mode = static_cast<OperationMode_V1_1>(TEST_NORMAL_MODE);
    std::vector<uint8_t> modeSetting;
    for (int i = 0; i <= METADATA_CAPACITY_MAX_SIZE; i++) {
        modeSetting.push_back(0x01);
    }
    int32_t rc = dstreamOperator_->CommitStreams_V1_1(mode, modeSetting);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_028
 * @tc.desc: Verify CommitStreams_V1_1
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_028, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    OperationMode_V1_1 mode = static_cast<OperationMode_V1_1>(TEST_NORMAL_MODE);
    std::vector<uint8_t> modeSetting;
    modeSetting.push_back(0x01);
    int32_t rc = dstreamOperator_->CommitStreams_V1_1(mode, modeSetting);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_029
 * @tc.desc: Verify HalStreamCommit
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_029, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    DCStreamInfo dstStreamInfo;
    int32_t rc = dstreamOperator_->HalStreamCommit(dstStreamInfo);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_030
 * @tc.desc: Verify HalStreamCommit
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_030, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    DCStreamInfo dstStreamInfo;
    dstStreamInfo.streamId_ = TEST_STREAMID;
    dstStreamInfo.width_ = TEST_WIDTH;
    dstStreamInfo.height_ = TEST_HEIGHT;
    dstStreamInfo.stride_ = TEST_HEIGHT;
    dstStreamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    dstStreamInfo.dataspace_ = TEST_DATASPACE;
    dstStreamInfo.encodeType_ = DCEncodeType::ENCODE_TYPE_H264;
    dstStreamInfo.type_ = DCStreamType::CONTINUOUS_FRAME;
    int32_t rc = dstreamOperator_->HalStreamCommit(dstStreamInfo);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_031
 * @tc.desc: Verify GetStreamAttributes
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_031, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamAttribute> attributes;
    int32_t rc = dstreamOperator_->GetStreamAttributes(attributes);
    EXPECT_EQ(rc, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_032
 * @tc.desc: Verify HalStreamCommit
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_032, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamAttribute> attributes;
    int32_t streamId = -1;
    sptr<BufferProducerSequenceable> bufferProducer = new BufferProducerSequenceable();
    int32_t rc = dstreamOperator_->AttachBufferQueue(streamId, bufferProducer);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_033
 * @tc.desc: Verify HalStreamCommit
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_033, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamAttribute> attributes;
    int32_t streamId = 0;
    sptr<BufferProducerSequenceable> bufferProducer = nullptr;
    int32_t rc = dstreamOperator_->AttachBufferQueue(streamId, bufferProducer);
    EXPECT_EQ(rc, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_034
 * @tc.desc: Verify IsStreamInfosInvalid
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_034, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamInfo> infos;
    bool res = dstreamOperator_->IsStreamInfosInvalid(infos);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: dstream_operator_test_035
 * @tc.desc: Verify IsStreamInfosInvalid
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_035, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamInfo> infos;
    for (int i = 0; i <= CAPACITY_MAX_SIZE; i++) {
        struct StreamInfo streamInfo;
        streamInfo.streamId_ = TEST_STREAMID;
        streamInfo.width_ = TEST_WIDTH;
        streamInfo.height_ = TEST_HEIGHT;
        streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
        streamInfo.dataspace_ = TEST_DATASPACE;
        streamInfo.intent_ = StreamIntent::PREVIEW;
        streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
        infos.push_back(streamInfo);
    }
    bool res = dstreamOperator_->IsStreamInfosInvalid(infos);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: dstream_operator_test_036
 * @tc.desc: Verify IsStreamInfosInvalid
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_036, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamInfo> infos;
    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_INVALID_STREAMID;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    infos.push_back(streamInfo);
    bool res = dstreamOperator_->IsStreamInfosInvalid(infos);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: dstream_operator_test_037
 * @tc.desc: Verify IsStreamInfosInvalid
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_037, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<StreamInfo> infos;
    struct StreamInfo streamInfo;
    streamInfo.streamId_ = TEST_INVALID_STREAMID;
    streamInfo.width_ = TEST_WIDTH;
    streamInfo.height_ = TEST_HEIGHT;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = TEST_DATASPACE;
    streamInfo.intent_ = StreamIntent::PREVIEW;
    streamInfo.tunneledMode_ = TEST_TUNNELEDMODE;
    infos.push_back(streamInfo);
    bool res = dstreamOperator_->IsStreamInfosInvalid(infos);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: dstream_operator_test_038
 * @tc.desc: Verify IsCaptureInfoInvalid
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_038, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    CaptureInfo info;
    bool res = dstreamOperator_->IsCaptureInfoInvalid(info);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: dstream_operator_test_039
 * @tc.desc: Verify Capture
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_039, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t captureId = -1;
    CaptureInfo info;
    bool isStreaming = true;
    int32_t res = dstreamOperator_->Capture(captureId, info, isStreaming);
    EXPECT_EQ(res, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_040
 * @tc.desc: Verify CancelCapture
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_040, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t captureId = -1;
    int32_t res = dstreamOperator_->CancelCapture(captureId);
    EXPECT_EQ(res, CamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_041
 * @tc.desc: Verify HasContinuousCaptureInfo
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_041, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t captureId = 0;
    dstreamOperator_->halCaptureInfoMap_.clear();
    bool res = dstreamOperator_->HasContinuousCaptureInfo(captureId);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: dstream_operator_test_042
 * @tc.desc: Verify ChangeToOfflineStream
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_042, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::vector<int32_t> streamIds;
    sptr<IStreamOperatorCallback> callbackObj = nullptr;
    sptr<IOfflineStreamOperator> offlineOperator = nullptr;
    int32_t res = dstreamOperator_->ChangeToOfflineStream(streamIds, callbackObj, offlineOperator);
    EXPECT_EQ(res, CamRetCode::METHOD_NOT_SUPPORTED);
}

/**
 * @tc.name: dstream_operator_test_043
 * @tc.desc: Verify EnableResult
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_043, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t streamId = 0;
    std::vector<uint8_t> results;
    int32_t res = dstreamOperator_->EnableResult(streamId, results);
    EXPECT_EQ(res, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_044
 * @tc.desc: Verify DisableResult
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_044, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t streamId = 0;
    std::vector<uint8_t> results;
    int32_t res = dstreamOperator_->DisableResult(streamId, results);
    EXPECT_EQ(res, CamRetCode::NO_ERROR);
}

/**
 * @tc.name: dstream_operator_test_045
 * @tc.desc: Verify GetFormatObj
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_045, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    std::string formatStr = "format";
    cJSON* result = dstreamOperator_->GetFormatObj("nonexist", root, formatStr);
    EXPECT_EQ(result, nullptr);
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_046
 * @tc.desc: Verify GetFormatObj
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_046, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "testNode", "invalid");
    std::string formatStr = "testFormat";
    cJSON* result = dstreamOperator_->GetFormatObj("testNode", root, formatStr);
    EXPECT_EQ(result, nullptr);
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_047
 * @tc.desc: Verify GetFormatObj
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_047, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    cJSON* testNode = cJSON_AddObjectToObject(root, "testNode");
    cJSON* resNode = cJSON_AddObjectToObject(testNode, "Resolution");
    cJSON* formatArray = cJSON_AddArrayToObject(resNode, "testFormat");
    cJSON_AddItemToArray(formatArray, cJSON_CreateNumber(0));
    cJSON_AddItemToArray(formatArray, cJSON_CreateNumber(1));
    std::string formatStr = "testFormat";
    auto result = dstreamOperator_->GetFormatObj("testNode", root, formatStr);
    ASSERT_NE(result, nullptr);
    EXPECT_TRUE(cJSON_IsArray(result));
    EXPECT_EQ(cJSON_GetArraySize(result), 2);
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_048
 * @tc.desc: Verify SetOutputVal
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_048, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    DHBase dhBase;
    dhBase.deviceId_ = "deviveId";
    dhBase.dhId_ = "dhId";
    std::string sinkAbilityInfo = "sinkAbilityInfo";
    std::string sourceCodecInfo = "sourceCodecInfo";
    DCamRetCode result = dstreamOperator_->SetOutputVal(dhBase, sinkAbilityInfo, sourceCodecInfo);
    EXPECT_EQ(result, DCamRetCode::SUCCESS);
}

/**
 * @tc.name: dstream_operator_test_049
 * @tc.desc: Verify InitOutputConfigurations
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_049, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    DHBase dhBase;
    dhBase.deviceId_ = "deviveId";
    dhBase.dhId_ = "dhId";
    std::string sinkAbilityInfo = "invalid_json";
    std::string sourceCodecInfo = "{}";
    DCamRetCode result = dstreamOperator_->InitOutputConfigurations(dhBase, sinkAbilityInfo, sourceCodecInfo);
    EXPECT_EQ(result, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_050
 * @tc.desc: Verify InitOutputConfigurations
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_050, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    DHBase dhBase;
    dhBase.deviceId_ = "deviveId";
    dhBase.dhId_ = "dhId";
    std::string sinkAbilityInfo = "[1,2,3]";
    std::string sourceCodecInfo = "{}";
    DCamRetCode result = dstreamOperator_->InitOutputConfigurations(dhBase, sinkAbilityInfo, sourceCodecInfo);
    EXPECT_EQ(result, DCamRetCode::INVALID_ARGUMENT);
}

/**
 * @tc.name: dstream_operator_test_051
 * @tc.desc: Verify CheckInputInfo
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_051, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    bool res = dstreamOperator_->CheckInputInfo();
    EXPECT_FALSE(res);
}

/**
 * @tc.name: dstream_operator_test_052
 * @tc.desc: Verify ParseEncoderTypes
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_052, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    auto res = dstreamOperator_->ParseEncoderTypes(root);
    EXPECT_TRUE(res.empty());
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_053
 * @tc.desc: Verify ParseEncoderTypes
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_053, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    cJSON_AddArrayToObject(root, "CodecType");
    auto res = dstreamOperator_->ParseEncoderTypes(root);
    EXPECT_TRUE(res.empty());
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_055
 * @tc.desc: Verify ParsePhotoFormats
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_055, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    auto res = dstreamOperator_->ParsePhotoFormats(root);
    EXPECT_EQ(res, DCamRetCode::INVALID_ARGUMENT);
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_056
 * @tc.desc: Verify ParsePhotoFormats
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_056, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "Photo", "invalid");
    auto res = dstreamOperator_->ParsePhotoFormats(root);
    EXPECT_EQ(res, DCamRetCode::INVALID_ARGUMENT);
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_057
 * @tc.desc: Verify ParsePhotoFormats
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_057, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    cJSON_AddObjectToObject(root, "Photo");
    auto res = dstreamOperator_->ParsePhotoFormats(root);
    EXPECT_EQ(res, DCamRetCode::INVALID_ARGUMENT);
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_058
 * @tc.desc: Verify ParsePhotoFormats
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_058, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    cJSON* root = cJSON_CreateObject();
    cJSON* photo = cJSON_AddObjectToObject(root, "Photo");
    cJSON* formatArray = cJSON_AddArrayToObject(photo, "OutputFormat");
    cJSON_AddItemToArray(formatArray, cJSON_CreateNumber(1));
    cJSON_AddItemToArray(formatArray, cJSON_CreateNumber(2));
    cJSON_AddItemToArray(formatArray, cJSON_CreateNumber(3));
    auto res = dstreamOperator_->ParsePhotoFormats(root);
    EXPECT_EQ(res, DCamRetCode::SUCCESS);
    cJSON_Delete(root);
}

/**
 * @tc.name: dstream_operator_test_059
 * @tc.desc: Verify FindStreamCaptureBufferNum
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_059, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::pair<int, int> streamPair = {1, 2};
    dstreamOperator_->acceptedBufferNum_[streamPair] = 5;
    int32_t result = dstreamOperator_->FindStreamCaptureBufferNum(streamPair);
    EXPECT_EQ(result, 5);
}

/**
 * @tc.name: dstream_operator_test_060
 * @tc.desc: Verify FindStreamCaptureBufferNum
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_060, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::pair<int, int> streamPair = {3, 4};
    int32_t result = dstreamOperator_->FindStreamCaptureBufferNum(streamPair);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: dstream_operator_test_061
 * @tc.desc: Verify AddStreamCaptureBufferNum
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_061, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::pair<int, int> streamPair = {1, 2};
    dstreamOperator_->acceptedBufferNum_[streamPair] = 5;
    dstreamOperator_->AddStreamCaptureBufferNum(streamPair);
    EXPECT_EQ(dstreamOperator_->acceptedBufferNum_[streamPair], 6);
}

/**
 * @tc.name: dstream_operator_test_062
 * @tc.desc: Verify AddStreamCaptureBufferNum
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_062, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::pair<int, int> streamPair = {3, 4};
    dstreamOperator_->AddStreamCaptureBufferNum(streamPair);
    EXPECT_EQ(dstreamOperator_->acceptedBufferNum_[streamPair], 1);
}

/**
 * @tc.name: dstream_operator_test_063
 * @tc.desc: Verify AddStreamCaptureBufferNum
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_063, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    std::pair<int, int> streamPair = {1, 2};
    dstreamOperator_->acceptedBufferNum_[streamPair] = 5;
    dstreamOperator_->EraseStreamCaptureBufferNum(streamPair);
    EXPECT_EQ(dstreamOperator_->acceptedBufferNum_.find(streamPair) == dstreamOperator_->acceptedBufferNum_.end(),
                true);
}

/**
 * @tc.name: dstream_operator_test_064
 * @tc.desc: Verify InsertNotifyCaptureMap
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_064, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t streamId = 1;
    dstreamOperator_->InsertNotifyCaptureMap(streamId);
    EXPECT_EQ(
        dstreamOperator_->notifyCaptureStartedMap_.find(streamId) != dstreamOperator_->notifyCaptureStartedMap_.end(),
                true);
    EXPECT_EQ(dstreamOperator_->notifyCaptureStartedMap_[streamId], false);
}

/**
 * @tc.name: dstream_operator_test_065
 * @tc.desc: Verify InsertNotifyCaptureMap
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_065, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t streamId = 1;
    dstreamOperator_->notifyCaptureStartedMap_[streamId] = true;
    dstreamOperator_->InsertNotifyCaptureMap(streamId);
    EXPECT_EQ(dstreamOperator_->notifyCaptureStartedMap_[streamId], true);
}

/**
 * @tc.name: dstream_operator_test_067
 * @tc.desc: Verify EraseNotifyCaptureMap
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_066, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t streamId = 1;
    dstreamOperator_->notifyCaptureStartedMap_[streamId] = true;
    dstreamOperator_->EraseNotifyCaptureMap(streamId);
    EXPECT_EQ(
        dstreamOperator_->notifyCaptureStartedMap_.find(streamId) == dstreamOperator_->notifyCaptureStartedMap_.end(),
        true);
}

/**
 * @tc.name: dstream_operator_test_068
 * @tc.desc: Verify EraseNotifyCaptureMap
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_067, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t streamId = 1;
    dstreamOperator_->EraseNotifyCaptureMap(streamId);
    EXPECT_EQ(dstreamOperator_->notifyCaptureStartedMap_.size(), 0);
}

/**
 * @tc.name: dstream_operator_test_069
 * @tc.desc: Verify FindCaptureInfoById
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_068, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t captureId = 1;
    auto captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_.push_back(1);
    dstreamOperator_->halCaptureInfoMap_[captureId] = captureInfo;
    auto result = dstreamOperator_->FindCaptureInfoById(captureId);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->streamIds_[0], 1);
}

/**
 * @tc.name: dstream_operator_test_070
 * @tc.desc: Verify FindCaptureInfoById
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DStreamOperatorTest, dstream_operator_test_069, TestSize.Level1)
{
    EXPECT_EQ(false, dstreamOperator_ == nullptr);
    int32_t captureId = 2;
    auto result = dstreamOperator_->FindCaptureInfoById(captureId);
    EXPECT_EQ(result, nullptr);
}
}
}