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

int64_t OHOS::Camera::Test::StreamConsumer::g_timestamp[2] = {0};
void CameraHdiUtTestV1_1::SetUpTestCase(void) {}
void CameraHdiUtTestV1_1::TearDownTestCase(void) {}
void CameraHdiUtTestV1_1::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_0); // assert inside
}

void CameraHdiUtTestV1_1::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: GetStreamOperator_V1_1
 * @tc.desc: GetStreamOperator_V1_1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_005, TestSize.Level1)
{
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
    int64_t timeStampCapture = 0;
    int64_t timeStampThumbnail = 0;

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
    timeStampThumbnail = OHOS::Camera::Test::StreamConsumer::g_timestamp[0];
    timeStampCapture = OHOS::Camera::Test::StreamConsumer::g_timestamp[1];
    EXPECT_EQ(true, timeStampThumbnail == timeStampCapture);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: GetStreamOperator_V1_1,defer_stream
 * @tc.desc: GetStreamOperator_V1_1,defer_stream
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_008, TestSize.Level1)
{
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);

    // Create stream
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Attach bufferqueue
    std::shared_ptr<OHOS::Camera::Test::StreamConsumer> consumer =
        std::make_shared<OHOS::Camera::Test::StreamConsumer>();
    OHOS::sptr<BufferProducerSequenceable> bufferQueue =
        consumer->CreateProducerSeq([this](void* addr, uint32_t size) {
            cameraTest->DumpImageFile(111, "yuv", addr, size);
    });
    EXPECT_NE(bufferQueue, nullptr);
    EXPECT_NE(bufferQueue->producer_, nullptr);
    bufferQueue->producer_->SetQueueSize(UT_DATA_SIZE);
    cameraTest->rc = cameraTest->streamOperator_V1_1->AttachBufferQueue(
        cameraTest->streamInfoV1_1->v1_0.streamId_, bufferQueue);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    // Capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    sleep(UT_SECOND_TIMES);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);

    // Release
    cameraTest->rc = cameraTest->streamOperator_V1_1->DetachBufferQueue(cameraTest->streamInfoV1_1->v1_0.streamId_);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    std::vector<int> streamIds = {cameraTest->streamInfoV1_1->v1_0.streamId_};
    cameraTest->rc = cameraTest->streamOperator_V1_1->ReleaseStreams(streamIds);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_1_009
 * @tc.desc: OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_009, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS> value start.");
        constexpr size_t step = 10; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGE("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS> value end.");
    }
}

/**
 * @tc.name: IsStreamsSupported_V1_1 and CommitStreams_V1_1, preview and capture
 * @tc.desc: IsStreamsSupported_V1_1 and CommitStreams_V1_1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_1, Camera_Device_Hdi_V1_1_010, TestSize.Level1)
{
    // Get Stream Operator
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
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

    // is streams supported V1_1
    std::shared_ptr<CameraMetadata> modeSetting = std::make_shared<CameraMetadata>(2, 128);
    int64_t expoTime = 0;
    modeSetting->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &expoTime, 1);
    int64_t colorGains[4] = {0};
    modeSetting->addEntry(OHOS_SENSOR_COLOR_CORRECTION_GAINS, &colorGains, 4);
    std::vector<uint8_t> modeSettingVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, modeSettingVec);
    StreamSupportType pType;
    cameraTest->rc = cameraTest->streamOperator_V1_1->IsStreamsSupported_V1_1(OHOS::HDI::Camera::V1_1::PORTRAIT,
        modeSettingVec, cameraTest->streamInfosV1_1, pType);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    // create and commitstreams
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(OHOS::HDI::Camera::V1_1::PORTRAIT,
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);

    // start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}
