/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "camera_hdi_test_v1_3.h"
#include <functional>

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
constexpr uint32_t ITEM_CAPACITY = 100;
constexpr uint32_t DATA_CAPACITY = 2000;
constexpr uint32_t DATA_COUNT = 1;
constexpr uint32_t FPS_COUNT = 2;
constexpr uint32_t EXPOSURE_COUNT = 4;
int64_t OHOS::Camera::Test::StreamConsumer::g_timestamp[2] = {0};
void CameraHdiTestV1_3::SetUpTestCase(void) {}
void CameraHdiTestV1_3::TearDownTestCase(void) {}
void CameraHdiTestV1_3::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_0); // assert inside
}

void CameraHdiTestV1_3::TearDown(void)
{
    cameraTest->Close();
}

bool g_IsTagValueExistsU8(std::shared_ptr<CameraMetadata> ability, uint32_t tag, uint8_t value)
{
    common_metadata_header_t* data = ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, tag, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (int i = 0; i < entry.count; i++) {
            if (entry.data.u8[i] == value) {
                return true;
            }
        }
    } else {
        printf("Find CameraMetadata fail!\n");
        CAMERA_LOGE("Find CameraMetadata fail!");
    }
    return false;
}

/**
 * @tc.name:SUB_Driver_Camera_Moon_0200
 * @tc.desc: Update moon ability setting
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiTestV1_3, SUB_Driver_Camera_Moon_0200, TestSize.Level1)
{
    int32_t rc;
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    rc = cameraTest->serviceV1_3->SetCallback_V1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(rc, 0);
    // Start OHOS_ABILITY_MOON_CAPTURE_BOOST ability query
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_MOON_CAPTURE_BOOST, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        constexpr float zoomRatio = 15;
        uint8_t stabControl = OHOS_CAMERA_MOON_CAPTURE_BOOST_ENABLE;
        meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, DATA_COUNT);
        meta->addEntry(OHOS_CONTROL_MOON_CAPTURE_BOOST, &stabControl, DATA_COUNT);
        // ability meta data serialization for updating
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        CAMERA_LOGD("MoonCaptureBoost mode is set enabled.");

        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartStream(cameraTest->intents);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);
        sleep(1);
        cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        sleep(UT_SECOND_TIMES);
        common_metadata_header_t* data = cameraTest->deviceCallback->resultMeta->get();
        EXPECT_NE(data, nullptr);
        camera_metadata_item_t entry;
        int ret = FindCameraMetadataItem(data, OHOS_STATUS_MOON_CAPTURE_DETECTION, &entry);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, ret);
        if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
            uint8_t value = entry.data.u8[0];
            // 查询到状态， 检测状态到 月亮模式可开启
            if (OHOS_CAMERA_MOON_CAPTURE_BOOST_ENABLE == value) {
                printf("Moon mode is set enabled.");
            } else {
                printf("Moon mode is not enabled.");
            }
        } else {
            GTEST_SKIP() << "skip this test, because OHOS_ABILITY_MOON_CAPTURE_BOOST not supported now" << std::endl;
        }
    }
}

/**
 * @tc.name:SUB_Driver_Camera_Moon_0300
 * @tc.desc: Update moon ability setting
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiTestV1_3, SUB_Driver_Camera_Moon_0300, TestSize.Level1)
{
    int32_t rc;
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    rc = cameraTest->serviceV1_3->SetCallback_V1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(rc, 0);
    // Start OHOS_ABILITY_MOON_CAPTURE_BOOST ability query
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_MOON_CAPTURE_BOOST, &entry);
    if (cameraTest->rc != 0) {
        GTEST_SKIP() << "skip this test, because OHOS_ABILITY_MOON_CAPTURE_BOOST not supported now" << std::endl;
        return;
    }

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        constexpr float zoomRatio = 15;
        uint8_t stabControl = OHOS_CAMERA_MOON_CAPTURE_BOOST_ENABLE;
        meta->addEntry(OHOS_CONTROL_ZOOM_RATIO, &zoomRatio, DATA_COUNT);
        meta->addEntry(OHOS_CONTROL_MOON_CAPTURE_BOOST, &stabControl, DATA_COUNT);
        // ability meta data serialization for updating
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        CAMERA_LOGD("MoonCaptureBoost mode is set enabled.");

        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartStream(cameraTest->intents);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);
        sleep(1);
        cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
}

/**
 * @tc.name: SUB_Driver_Camera_SlowMotion_0300
 * @tc.desc: CommitStreams_V1_1 for HIGH_FRAME_RATE, preview and video, fps is 120
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiTestV1_3, SUB_Driver_Camera_SlowMotion_0300, TestSize.Level1)
{
    if (!g_IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE)) {
        GTEST_SKIP() << "skip this test, because HIGH_FRAME_RATE not in OHOS_ABILITY_CAMERA_MODES" << std::endl;
        return;
    }
    cameraTest->CreateAndCommitStreamsForHighFrameRate(cameraTest);
    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t highFrameRate[2] = {120, 120};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &highFrameRate, FPS_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    sleep(DATA_COUNT);
    cameraTest->streamInfosV1_1.clear();
}

/**
 * @tc.name: SUB_Driver_Camera_SlowMotion_0400
 * @tc.desc: CommitStreams_V1_1 for HIGH_FRAME_RATE, preview and video, fps is 240
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiTestV1_3, SUB_Driver_Camera_SlowMotion_0400, TestSize.Level1)
{
    if (!g_IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE)) {
        GTEST_SKIP() << "skip this test, because HIGH_FRAME_RATE not in OHOS_ABILITY_CAMERA_MODES" << std::endl;
        return;
    }
    cameraTest->CreateAndCommitStreamsForHighFrameRate(cameraTest);

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t highFrameRate[2] = {240, 240};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &highFrameRate, FPS_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    sleep(DATA_COUNT);
    cameraTest->streamInfosV1_1.clear();
}


/**
 * @tc.name: SUB_Driver_Camera_SuperSlowMotion_0400
 * @tc.desc: CommitStreams_V1_1 for SLOW_MOTION, preview and video, fps is 960
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiTestV1_3, SUB_Driver_Camera_SuperSlowMotion_0400, TestSize.Level1)
{
    if (!g_IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_2::SLOW_MOTION)) {
        GTEST_SKIP() << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << std::endl;
        return;
    }
    cameraTest->CreateAndCommitStreamsForSlowMotion(cameraTest);

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t slowMotionValue[2] = {240, 240};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &slowMotionValue, FPS_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    sleep(DATA_COUNT);
    cameraTest->streamInfosV1_1.clear();
}

/**
 * @tc.name: SUB_Driver_Camera_SuperSlowMotion_0200
 * @tc.desc: OHOS_ABILITY_MOTION_DETECTION_SUPPORT, OHOS_CAMERA_MOTION_DETECTION_SUPPORTED
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiTestV1_3, SUB_Driver_Camera_SuperSlowMotion_0200, TestSize.Level1)
{
    if (!g_IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_2::SLOW_MOTION)) {
        GTEST_SKIP() << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << std::endl;
        return;
    }
    // Set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    cameraTest->rc = cameraTest->serviceV1_3->SetCallback_V1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_MOTION_DETECTION_SUPPORT, &entry);
    if (cameraTest->rc!= 0) {
        GTEST_SKIP() << "skip this test, because OHOS_ABILITY_MOTION_DETECTION_SUPPORT not found" << std::endl;
        return;
    }
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        if (entry.data.u8[0] == OHOS_CAMERA_MOTION_DETECTION_SUPPORTED) {
            cameraTest->CreateAndCommitStreamsForSlowMotion(cameraTest);
            cameraTest->UpdateSettingsForSlowMotionMode(cameraTest);
            cameraTest->SuperSlowMotionStatusCallback(cameraTest);
        }
    }
}