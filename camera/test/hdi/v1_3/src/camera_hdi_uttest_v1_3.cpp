/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "camera_hdi_uttest_v1_3.h"
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
constexpr uint32_t CHECK_AREA_COUNT = 4;
constexpr uint32_t STREAMINFO_WIDTH = 1920;
constexpr uint32_t STREAMINFO_HEIGHT = 1080;
constexpr uint32_t HIGH_RESOLUTION_PHOTO_WIDTH = 8192;
constexpr uint32_t HIGH_RESOLUTION_PHOTO_HEIGHT = 6144;
int64_t OHOS::Camera::Test::StreamConsumer::g_timestamp[2] = {0};
void CameraHdiUtTestV1_3::SetUpTestCase(void) {}
void CameraHdiUtTestV1_3::TearDownTestCase(void) {}
void CameraHdiUtTestV1_3::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_0); // assert inside
}

void CameraHdiUtTestV1_3::TearDown(void)
{
    cameraTest->Close();
}

bool IsTagValueExistsU8(std::shared_ptr<CameraMetadata> ability, uint32_t tag, uint8_t value)
{
    common_metadata_header_t* data = ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, tag, &entry);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(entry.count, 0);
    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == value) {
            return true;
        }
    }
    return false;
}

void PrintAllTagDataU8(std::shared_ptr<CameraMetadata> ability, uint32_t tag)
{
    common_metadata_header_t* data = ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, tag, &entry);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(entry.count, 0);
    cout << "----tag = " << tag << "count = " << entry.count << endl;
    for (int i = 0; i < entry.count; i++) {
        int v = entry.data.u8[i];
        cout << "tag[" << tag << "][" << i << "] = " << v << endl;
    }
    cout << "--------------------------------" << endl;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_001
 * @tc.desc: Get and Print all data in OHOS_ABILITY_CAMERA_MODES
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_001, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    (void)ITEM_CAPACITY;
    (void)DATA_CAPACITY;
    (void)DATA_COUNT;
    (void)FPS_COUNT;
    (void)EXPOSURE_COUNT;
    (void)CHECK_AREA_COUNT;
    (void)STREAMINFO_WIDTH;
    (void)STREAMINFO_HEIGHT;
    (void)HIGH_RESOLUTION_PHOTO_WIDTH;
    (void)HIGH_RESOLUTION_PHOTO_HEIGHT;
    PrintAllTagDataU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES);
}

static void CreateAndCommitStreamsForHighFrameRate(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    // Get stream operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // Preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfoPre->v1_0.width_ = STREAMINFO_WIDTH;
    cameraTest->streamInfoPre->v1_0.height_ = STREAMINFO_HEIGHT;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // Video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfoVideo->v1_0.width_ = STREAMINFO_WIDTH;
    cameraTest->streamInfoVideo->v1_0.height_ = STREAMINFO_HEIGHT;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
    // Create and commitStream
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_002
 * @tc.desc: Determine whether the HIGH_FRAME_RATE mode is supported
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_002, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        for (size_t i = 0; i < entry.count; i++ ) {
            uint8_t value = entry.data.u8[i];
            if (value == OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE) {
                CAMERA_LOGI("HIGH_FRAME_RATE mode is supported");
            }
        }
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_003
 * @tc.desc: CommitStreams_V1_1 for HIGH_FRAME_RATE, preview and video, fps is 120
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_003, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE)) {
        cout << "skip this test, because HIGH_FRAME_RATE not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    CreateAndCommitStreamsForHighFrameRate(cameraTest);

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
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_004
 * @tc.desc: CommitStreams_V1_1 for HIGH_FRAME_RATE, preview and video, fps is 240
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_004, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE)) {
        cout << "skip this test, because HIGH_FRAME_RATE not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    CreateAndCommitStreamsForHighFrameRate(cameraTest);

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
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

static void CreateAndCommitStreamsForSlowMotion(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    // Get stream operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // Preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfoPre->v1_0.width_ = STREAMINFO_WIDTH;
    cameraTest->streamInfoPre->v1_0.height_ = STREAMINFO_HEIGHT;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // Video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfoVideo->v1_0.width_ = STREAMINFO_WIDTH;
    cameraTest->streamInfoVideo->v1_0.height_ = STREAMINFO_HEIGHT;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
    // Create and commitStream
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::SLOW_MOTION),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

static void UpdateSettingsForSlowMotionMode(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t valueInvalid[2] = {240, 240};
    float motionCheckArea[4] = {1, 1, 1, 1};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &valueInvalid, FPS_COUNT);
    meta->addEntry(OHOS_CONTROL_MOTION_DETECTION_CHECK_AREA, &motionCheckArea, CHECK_AREA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    int32_t slowMotionControl = OHOS_CAMERA_MOTION_DETECTION_ENABLE;
    meta->addEntry(OHOS_CONTROL_MOTION_DETECTION, &slowMotionControl, DATA_COUNT);
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    // Start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

static void SuperSlowMotionStatusCallback(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    if (cameraTest->deviceCallback->resultMeta == nullptr) {
        CAMERA_LOGI("callback not triggered");
        return;
    }
    common_metadata_header_t* data = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_STATUS_SLOW_MOTION_DETECTION, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        uint8_t value = entry.data.u8[0];
        // Detect the state of super slow motion
        if (value == OHOS_CONTROL_SLOW_MOTION_STATUS_DISABLE) {
            CAMERA_LOGI("slow motion status is disabled");
        } else if (value == OHOS_CONTROL_SLOW_MOTION_STATUS_READY) {
            CAMERA_LOGI("slow motion status is ready");
        } else if (value == OHOS_CONTROL_SLOW_MOTION_STATUS_START) {
            CAMERA_LOGI("slow motion status is started");
        } else if (value == OHOS_CONTROL_SLOW_MOTION_STATUS_RECORDING) {
            CAMERA_LOGI("slow motion status is recording");
        } else if (value == OHOS_CONTROL_SLOW_MOTION_STATUS_FINISH) {
            CAMERA_LOGI("slow motion status is finished");
        }
    }
}
/**
 * @tc.name: Camera_Device_Hdi_V1_3_005
 * @tc.desc: Determine whether the SLOW_MOTION mode is supported
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_005, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        for (size_t i = 0; i < entry.count; i++ ) {
            uint8_t value = entry.data.u8[i];
            if (value == OHOS::HDI::Camera::V1_2::SLOW_MOTION) {
                CAMERA_LOGI("SLOW_MOTION mode is supported");
            }
        }
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_006
 * @tc.desc: CommitStreams_V1_1 for SLOW_MOTION, preview and video, fps is 960
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_006, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_2::SLOW_MOTION)) {
        cout << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    CreateAndCommitStreamsForSlowMotion(cameraTest);

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
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_007
 * @tc.desc: OHOS_ABILITY_MOTION_DETECTION_SUPPORT, OHOS_CAMERA_MOTION_DETECTION_SUPPORTED
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_007, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_2::SLOW_MOTION)) {
        cout << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << endl;
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
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        if (entry.data.u8[0] == OHOS_CAMERA_MOTION_DETECTION_SUPPORTED) {
            CreateAndCommitStreamsForSlowMotion(cameraTest);
            UpdateSettingsForSlowMotionMode(cameraTest);
            SuperSlowMotionStatusCallback(cameraTest);
        }
    }
}

void CaptureByColorSpacesWithUpdateStreams(std::vector<int32_t> captureColorSpaces,
    std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    printf("Enter CaptureByColorSpacesWithUpdateStreams function!\n");
    if (!captureColorSpaces.empty()) {
        // Clear infos
        cameraTest->streamInfosV1_1.clear();
        // Preview streamInfo
        cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
        cameraTest->streamInfoV1_1->v1_0.dataspace_ = captureColorSpaces[0];
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
        // Capture streamInfo
        cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
        cameraTest->streamInfoCapture->v1_0.dataspace_ = captureColorSpaces[0];
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

        // StreamInfosV1_1 should not be empty
        cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
            OHOS::HDI::Camera::V1_1::OperationMode_V1_1::NORMAL, cameraTest->abilityVec);
        // Start without colorspace setting
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);

        for (int32_t colorSpaces : captureColorSpaces) {
            printf("capture colorSpaces value %d\n", colorSpaces);
            // CancelCapture
            cameraTest->streamOperator_V1_3->CancelCapture(cameraTest->captureIdPreview);
            // Clear infos
            cameraTest->streamInfosV1_1.clear();
            // Preview streamInfo
            cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
            cameraTest->streamInfoV1_1->v1_0.dataspace_ = colorSpaces;
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
            // Capture streamInfo
            cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
            cameraTest->streamInfoCapture->v1_0.dataspace_ = colorSpaces;
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
            // UpdateStreams
            cameraTest->rc = cameraTest->streamOperator_V1_3->UpdateStreams(cameraTest->streamInfosV1_1);
            // Capture
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
            cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
            sleep(UT_SECOND_TIMES);
        }

        // StopStream
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_088
 * @tc.desc: requirement hdr vivid ut
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_008, TestSize.Level1)
{
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(
        cameraTest->streamOperatorCallbackV1_3, cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &entry);
    printf("OHOS_ABILITY_AVAILABLE_COLOR_SPACES value count %d\n", entry.count);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        std::vector<int32_t> captureColorSpaces;
        int32_t operatorMode = -2;
        for (size_t i = 0; i < entry.count - 1; i++) {
            if (operatorMode == -2 && (entry.data.i32[i] == HDI::Camera::V1_2::OperationMode_V1_2::CAPTURE
                || entry.data.i32[i] == HDI::Camera::V1_2::OperationMode_V1_2::VIDEO
                || entry.data.i32[i] == HDI::Camera::V1_2::OperationMode_V1_2::SUPER_STAB)) {
                operatorMode = entry.data.i32[i];
            } else if (entry.data.i32[i] == -1 && operatorMode != -2 && entry.data.i32[i + 1] == -1) {
                operatorMode = -2;
            } else if (entry.data.i32[i] == -1 && operatorMode != -2 && entry.data.i32[i + 1] != -1) {
                operatorMode = -1;
            } else if (operatorMode == HDI::Camera::V1_2::OperationMode_V1_2::CAPTURE) {
                captureColorSpaces.push_back(entry.data.i32[i]);
            } else if (operatorMode == HDI::Camera::V1_2::OperationMode_V1_2::VIDEO ||
                operatorMode == HDI::Camera::V1_2::OperationMode_V1_2::SUPER_STAB) {
                continue;
            } else if (operatorMode == -2 && entry.data.i32[i] > 0) {
                operatorMode = -1;
            }
        }
        CaptureByColorSpacesWithUpdateStreams(captureColorSpaces, cameraTest);
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_008
 * @tc.desc: OHOS_ABILITY_MOVING_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_009, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;

    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_MOVING_PHOTO, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("OHOS_ABILITY_MOVING_PHOTO is not support");
        return;
    }
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_MOVING_PHOTO> i32 value start.");
        printf("OHOS_ABILITY_MOVING_PHOTO i32 value count %d\n", entry.count);
        constexpr size_t step = 10;
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_MOVING_PHOTO %s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_MOVING_PHOTO> i32 value end.");
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_011
 * @tc.desc:CAPTURE_DURATION
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_011, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAPTURE_DURATION_SUPPORTED, &entry);
    if (cameraTest->rc != 0 || entry.data.u8[0] != 1) {
        cout << "skip this test, because OHOS_ABILITY_CAPTURE_DURATION_SUPPORTED not supported now" << endl;
        return;
    }

    // Start stream
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartStream(cameraTest->intents);

    // Fill capture setting
    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t muteMode = static_cast<uint8_t>(OHOS_CAMERA_MUTE_MODE_OFF);
    modeSetting->addEntry(OHOS_CONTROL_MUTE_MODE, &muteMode, DATA_COUNT);
    uint8_t deferredImage = OHOS::HDI::Camera::V1_2::STILL_IMAGE;
    modeSetting->addEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredImage, DATA_COUNT);
    std::vector<uint8_t> controlVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, controlVec);
    cameraTest->abilityVec = controlVec;

    // Start preview and capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, true, true);
    // OncaptureReady trigger
    for (uint8_t i = 0; i < 2; i++) {
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    }

    // Release stream
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);

    sleep(UT_SECOND_TIMES);
    common_metadata_header_t* callbackData = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(callbackData, nullptr);
    camera_metadata_item_t callbackEntry;
    cameraTest->rc = FindCameraMetadataItem(callbackData, OHOS_CAMERA_CUSTOM_SNAPSHOT_DURATION, &callbackEntry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    printf("currentSnapshotDuration = %d\n", callbackEntry.data.ui32[0]);
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_012
 * @tc.desc:OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_012, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        CAMERA_LOGE("print tag<OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS> value start.");
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
        CAMERA_LOGE("print tag<OHOS_ABILITY_STREAM_AVAILABLE_EXTEND_CONFIGURATIONS> value end.");
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_013
 * @tc.desc: OHOS_CONTROL_MOVING_PHOTO OHOS_CAMERA_MOVING_PHOTO_OFF
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_013, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_3_013 start.");
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(
        cameraTest->streamOperatorCallbackV1_3, cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);

    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t movingPhoto = static_cast<uint8_t>(OHOS_CAMERA_MOVING_PHOTO_OFF);
    modeSetting->addEntry(OHOS_CONTROL_MOVING_PHOTO, &movingPhoto, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, metaVec);
    cameraTest->cameraDeviceV1_3->UpdateSettings(metaVec);

    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_014
 * @tc.desc: OHOS_CONTROL_MOVING_PHOTO OHOS_CAMERA_MOVING_PHOTO_ON
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_014, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_3_014 start.");
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(
        cameraTest->streamOperatorCallbackV1_3, cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);

    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t movingPhoto = static_cast<uint8_t>(OHOS_CAMERA_MOVING_PHOTO_ON);
    modeSetting->addEntry(OHOS_CONTROL_MOVING_PHOTO, &movingPhoto, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, metaVec);
    cameraTest->cameraDeviceV1_3->UpdateSettings(metaVec);

    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_015
 * @tc.desc:OHOS_ABILITY_EQUIVALENT_FOCUS
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_015, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_EQUIVALENT_FOCUS, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("OHOS_ABILITY_EQUIVALENT_FOCUS can not be find");
        return;
    }
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR) {
        EXPECT_NE(entry.data.i32, nullptr);
        EXPECT_EQ(entry.count > 0, true);
        CAMERA_LOGI("print tag<OHOS_ABILITY_EQUIVALENT_FOCUS> value start.");
        constexpr size_t step = 10; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_EQUIVALENT_FOCUS> value end.");
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_016
 * @tc.desc:Determine whether the HIGH_RESOLUTION_PHOTO mode is supported
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_016, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("OHOS_ABILITY_CAMERA_MODES is can not be found");
        return;
    }
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR) {
        EXPECT_NE(entry.data.u8, nullptr);
        EXPECT_EQ(entry.count > 0, true);
        for (size_t i = 0; i < entry.count; i++ ) {
            uint8_t value = entry.data.u8[i];
            if (value == OHOS::HDI::Camera::V1_3::HIGH_RESOLUTION_PHOTO) {
                CAMERA_LOGI("HIGH_RESOLUTION_PHOTO mode is supported");
            }
        }
    }
}

static void startStreamForHighResolutionPhoto(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    // Get stream operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);

    // Capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfoCapture->v1_0.width_ = HIGH_RESOLUTION_PHOTO_WIDTH;
    cameraTest->streamInfoCapture->v1_0.height_ = HIGH_RESOLUTION_PHOTO_HEIGHT;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    // Create and commit streams
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::HIGH_RESOLUTION_PHOTO),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_017
 * @tc.desc: CommitStreams_V1_1 for HIGH_RESOLUTION_PHOTO, preview and capture
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_017, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability,
        OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_RESOLUTION_PHOTO)) {
        cout << "skip this test, because HIGH_RESOLUTION_PHOTO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAPTURE_EXPECT_TIME, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR) {
        EXPECT_NE(entry.data.ui32, nullptr);
        EXPECT_EQ(entry.count > 1, true);
        CAMERA_LOGI("mode is %{public}u and captureExpectTime is %{public}u", entry.data.ui32[0], entry.data.ui32[1]);
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    startStreamForHighResolutionPhoto(cameraTest);

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t aeExposureCompensation = EXPOSURE_COUNT;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &aeExposureCompensation, DATA_COUNT);
    uint8_t focusMode = OHOS_CAMERA_FOCUS_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_FOCUS_MODE, &focusMode, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_018
 * @tc.desc: Determine whether the CAPTURE_MACRO mode is supported
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_018, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("OHOS_ABILITY_CAMERA_MODES can not be found");
        return;
    }
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR) {
        EXPECT_NE(entry.data.u8, nullptr);
        EXPECT_EQ(entry.count > 0, true);
        for (size_t i = 0; i < entry.count; i++ ) {
            uint8_t value = entry.data.u8[i];
            if (value == OHOS::HDI::Camera::V1_2::CAPTURE_MACRO) {
                CAMERA_LOGI("CAPTURE_MACRO mode is supported");
            }
        }
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_019
 * @tc.desc: CommitStreams_V1_1 for CAPTURE_MACRO, preview and capture
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_019, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::CAPTURE_MACRO)) {
        cout << "skip this test, because CAPTURE_MACRO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    // Get stream operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // Preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // Capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::CAPTURE_MACRO),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float lensFocusDistance = DATA_COUNT;
    meta->addEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &lensFocusDistance, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);

    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_020
 * @tc.desc: Determine whether the VIDEO_MACRO mode is supported
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_020, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("OHOS_ABILITY_CAMERA_MODES can not be find");
        return;
    }
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR) {
        EXPECT_NE(entry.data.u8, nullptr);
        EXPECT_EQ(entry.count > 0, true);
        for (size_t i = 0; i < entry.count; i++ ) {
            uint8_t value = entry.data.u8[i];
            if (value == OHOS::HDI::Camera::V1_2::VIDEO_MACRO) {
                CAMERA_LOGI("VIDEO_MACRO mode is supported");
            }
        }
    }
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_021
 * @tc.desc: CommitStreams_V1_1 for VIDEO_MACRO, preview and capture
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_021, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::VIDEO_MACRO)) {
        cout << "skip this test, because VIDEO_MACRO not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    // Get stream operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // Preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // Capture streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
    // Create and commit streams
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::VIDEO_MACRO),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    float lensFocusDistance = DATA_COUNT;
    meta->addEntry(OHOS_CONTROL_LENS_FOCUS_DISTANCE, &lensFocusDistance, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_025
 * @tc.desc:Dynamic FPS configuration, range setting, streams fps constrain
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_025, TestSize.Level1)
{
    // PREVIEW and VIDEO stream
    cameraTest->intents = {PREVIEW, VIDEO};

    // This requirement only in VIDEO mode
    cameraTest->StartStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::OperationMode::VIDEO);

    // Bind fps range with preview stream and video stream
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_CONTROL_FPS_RANGES, &entry);
    // The FPS only valid in current release, non backward compatibility
    int32_t fpsRanges[] = {1, 30};
    bool result;
    if (cameraTest->rc != CAM_META_SUCCESS) {
        std::cout << "Not found TAG[OHOS_CONTROL_FPS_RANGES], insert one" << std::endl;
        result = cameraTest->ability->addEntry(OHOS_CONTROL_FPS_RANGES,
            fpsRanges, sizeof(fpsRanges) / sizeof(int32_t));
        EXPECT_EQ(true, result);
    } else {
        std::cout << "Found TAG[OHOS_CONTROL_FPS_RANGES], Update it" << std::endl;
        result = cameraTest->ability->updateEntry(OHOS_CONTROL_FPS_RANGES,
            fpsRanges, sizeof(fpsRanges) / sizeof(int32_t));
        EXPECT_EQ(true, result);
    }
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraTest->ability, cameraTest->abilityVec);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    // Release stream
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
+ * @tc.name:Camera_Device_Hdi_V1_3_026
+ * @tc.desc:Dynamic FPS configuration, fixed fps setting, streams fps constrain
+ * @tc.size:MediumTest
+ * @tc.type:Function
+*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_026, TestSize.Level1)
{
    // PREVIEW and VIDEO stream
    cameraTest->intents = {PREVIEW, VIDEO};

    // This requirement only in VIDEO mode
    cameraTest->StartStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::OperationMode::VIDEO);

    // Bind fixed fps with preview stream and video stream, constraint
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_CONTROL_FPS_RANGES, &entry);

    // The FPS only valid in current release, non backward compatibility
    int32_t previewFixedFps[] = {30, 30};
    bool result;
    if (cameraTest->rc != CAM_META_SUCCESS) {
        std::cout << "Not found TAG[OHOS_CONTROL_FPS_RANGES], insert one" << std::endl;
        result = cameraTest->ability->addEntry(OHOS_CONTROL_FPS_RANGES,
            previewFixedFps, sizeof(previewFixedFps) / sizeof(int32_t));
        EXPECT_EQ(true, result);
    } else {
        std::cout << "Found TAG[OHOS_CONTROL_FPS_RANGES], Update it" << std::endl;
        result = cameraTest->ability->updateEntry(OHOS_CONTROL_FPS_RANGES,
            previewFixedFps, sizeof(previewFixedFps) / sizeof(int32_t));
        EXPECT_EQ(true, result);
    }
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraTest->ability, cameraTest->abilityVec);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);

    // Update video fixed fps, constraint relationship
    int32_t videoFixedFps[] = {60, 60};
    std::cout << "Update fixed fps for video capture" << std::endl;
    result = cameraTest->ability->updateEntry(OHOS_CONTROL_FPS_RANGES,
        videoFixedFps, sizeof(videoFixedFps) / sizeof(int32_t));
    EXPECT_EQ(true, result);
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraTest->ability, cameraTest->abilityVec);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    // Release stream
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};

    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_027
 * @tc.desc: OHOS_ABILITY_HIGH_QUALITY_SUPPORT
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_027, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_HIGH_QUALITY_SUPPORT, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("OHOS_ABILITY_HIGH_QUALITY_SUPPORT is not support");
        return;
    }
    PrintAllTagDataU8(cameraTest->ability, OHOS_ABILITY_HIGH_QUALITY_SUPPORT);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_028
 * @tc.desc: OHOS_CONTROL_HIGH_QUALITY_MODE OHOS_CONTROL_HIGH_QUALITY_MODE_OFF
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_028, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_3_028 start.");
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(
        cameraTest->streamOperatorCallbackV1_3, cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);

    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t movingPhoto = static_cast<uint8_t>(OHOS_CONTROL_HIGH_QUALITY_MODE_OFF);
    modeSetting->addEntry(OHOS_CONTROL_HIGH_QUALITY_MODE, &movingPhoto, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, metaVec);
    cameraTest->cameraDeviceV1_3->UpdateSettings(metaVec);

    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_029
 * @tc.desc: OHOS_CONTROL_HIGH_QUALITY_MODE OHOS_CONTROL_HIGH_QUALITY_MODE_ON
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_029, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Device_Hdi_V1_3_029 start.");
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(
        cameraTest->streamOperatorCallbackV1_3, cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);

    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t movingPhoto = static_cast<uint8_t>(OHOS_CONTROL_HIGH_QUALITY_MODE_ON);
    modeSetting->addEntry(OHOS_CONTROL_HIGH_QUALITY_MODE, &movingPhoto, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, metaVec);
    cameraTest->cameraDeviceV1_3->UpdateSettings(metaVec);

    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams(OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_032
 * @tc.desc: Get and Print all data in OHOS_ABILITY_CAMERA_MODES for all cameras
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_032, TestSize.Level1)
{
    cameraTest->serviceV1_3->GetCameraIds(cameraTest->cameraIds);
    EXPECT_NE(cameraTest->cameraIds.size(), 0);

    for (auto &cameraId : cameraTest->cameraIds) {
        cameraTest->Close();
        cameraTest->serviceV1_3->GetCameraAbility(cameraId, cameraTest->abilityVec);
        MetadataUtils::ConvertVecToMetadata(cameraTest->abilityVec, cameraTest->ability);
        cameraTest->deviceCallback = new OHOS::Camera::Test::DemoCameraDeviceCallback();
        cameraTest->rc = cameraTest->serviceV1_3->OpenCamera_V1_3(cameraId,
            cameraTest->deviceCallback, cameraTest->cameraDeviceV1_3);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

        common_metadata_header_t* data = cameraTest->ability->get();

        std::string metaString = cameraTest->ability->FormatCameraMetadataToString(data);

        std::cout << "============= camera id: " << cameraId << " =============" << std::endl;
        std::cout << metaString << std::endl;
        std::cout << "==========================" << std::endl;
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_033
 * @tc.desc:OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_033, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL is not support");
        return;
    }
    CAMERA_LOGI("print tag<OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL> value start.");
    constexpr size_t step = 20; // print step
    std::stringstream ss;
    for (size_t i = 0; i < entry.count; i++) {
        ss << entry.data.i32[i] << " ";
        if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
            CAMERA_LOGI("%{public}s\n", ss.str().c_str());
            ss.clear();
            ss.str("");
        }
    }
    CAMERA_LOGI("print tag<OHOS_ABILITY_AVAILABLE_PROFILE_LEVEL> value end.");
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_034
 * @tc.desc:OHOS_ABILITY_AVAILABLE_CONFIGURATIONS
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_034, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_AVAILABLE_CONFIGURATIONS, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("OHOS_ABILITY_AVAILABLE_CONFIGURATIONS is not support");
        return;
    }
    CAMERA_LOGI("print tag<OHOS_ABILITY_AVAILABLE_CONFIGURATIONS> value start.");
    constexpr size_t step = 20; // print step
    std::stringstream ss;
    for (size_t i = 0; i < entry.count; i++) {
        ss << entry.data.i32[i] << " ";
        if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
            CAMERA_LOGI("%{public}s\n", ss.str().c_str());
            ss.clear();
            ss.str("");
        }
    }
    CAMERA_LOGI("print tag<OHOS_ABILITY_AVAILABLE_CONFIGURATIONS> value end.");
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_035
 * @tc.desc:OHOS_ABILITY_CONFLICT_CONFIGURATIONS
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_035, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CONFLICT_CONFIGURATIONS, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("OHOS_ABILITY_CONFLICT_CONFIGURATIONS is not support");
        return;
    }
    CAMERA_LOGI("print tag<OHOS_ABILITY_CONFLICT_CONFIGURATIONS> value start.");
    constexpr size_t step = 20; // print step
    std::stringstream ss;
    for (size_t i = 0; i < entry.count; i++) {
        ss << entry.data.i32[i] << " ";
        if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
            CAMERA_LOGI("%{public}s\n", ss.str().c_str());
            ss.clear();
            ss.str("");
        }
    }
    CAMERA_LOGI("print tag<OHOS_ABILITY_CONFLICT_CONFIGURATIONS> value end.");
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_036
 * @tc.desc:LIGHT_PAINTING mode
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_036, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR) {
        EXPECT_NE(entry.data.u8, nullptr);
        EXPECT_EQ(entry.count > 0, true);
        for (size_t i = 0; i < entry.count; i++ ) {
            uint8_t value = entry.data.u8[i];
            if (value == OHOS::HDI::Camera::V1_3::LIGHT_PAINTING) {
                CAMERA_LOGI("LIGHT_PAINTING mode is supported");
            }
        }
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_037
 * @tc.desc:Configure light painting, OHOS_CONTROL_LIGHT_PAINTING_TYPE
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_037, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability,
        OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::LIGHT_PAINTING)) {
        cout << "skip this test, because LIGHT_PAINTING not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }

    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_LIGHT_PAINTING_TYPE, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    for (uint8_t i = 0; i < entry.count; i++) {
        cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
        cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(
            cameraTest->streamOperatorCallbackV1_3, cameraTest->streamOperator_V1_3);
        EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);

        cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->streamInfoPre->v1_0.width_ = captureWidth;
        cameraTest->streamInfoPre->v1_0.height_ = captureHeight;
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

        cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

        cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
            static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::LIGHT_PAINTING),
            cameraTest->abilityVec);
        EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

        std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t lightPainting = entry.data.u8[i];
        if (lightPainting == OHOS_CAMERA_LIGHT_PAINTING_LIGHT) {
            uint8_t lightFlush = 1;
            modeSetting->addEntry(OHOS_CONTROL_LIGHT_PAINTING_FLASH, &lightFlush, 1);
            CAMERA_LOGI("Light painting supports lighting,the type is %{public}d", lightPainting);
        } else {
            CAMERA_LOGI("Light painting can not support lighting);
        }
        modeSetting->addEntry(OHOS_CONTROL_LIGHT_PAINTING_TYPE, &lightPainting, 1);
        std::vector<uint8_t> metaVec;
        MetadataUtils::ConvertMetadataToVec(modeSetting, metaVec);
        cameraTest->cameraDeviceV1_3->UpdateSettings(metaVec);

        cameraTest->imageDataSaveSwitch = SWITCH_ON;
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        cameraTest->imageDataSaveSwitch = SWITCH_OFF;
    }
}

/**
 * @tc.name:Camera_Device_Hdi_V1_3_038
 * @tc.desc:LIGHT_PAINTING and confirmCapture
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_038, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability,
        OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::LIGHT_PAINTING)) {
        cout << "skip this test, because LIGHT_PAINTING not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    CAMERA_LOGI("test Camera_Device_Hdi_V1_3_038 start.");
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_LIGHT_PAINTING_TYPE, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(
        cameraTest->streamOperatorCallbackV1_3, cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);

    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoPre->v1_0.width_ = captureWidth;
    cameraTest->streamInfoPre->v1_0.height_ = captureHeight;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::LIGHT_PAINTING),
        cameraTest->abilityVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);

    sleep(UT_SLEEP_TIME);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    cameraTest->streamOperator_V1_3->ConfirmCapture(cameraTest->streamIdCapture);
    sleep(UT_SLEEP_TIME);

    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_039
 * @tc.desc: Configure light painting, OHOS_CAMERA_FOCUS_MODE_AUTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_039, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability,
        OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::LIGHT_PAINTING)) {
        cout << "skip this test, because LIGHT_PAINTING not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    // Get stream operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // Preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoPre->v1_0.width_ = captureWidth;
    cameraTest->streamInfoPre->v1_0.height_ = captureHeight;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // Video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoVideo->v1_0.width_ = captureWidth;
    cameraTest->streamInfoVideo->v1_0.height_ = captureHeight;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
    // Create and commitStream
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::LIGHT_PAINTING),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t focusMode = OHOS_CAMERA_FOCUS_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_FOCUS_MODE, &focusMode, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Device_Hdi_V1_3_040
 * @tc.desc: Configure light painting, CAMERA_CUSTOM_COLOR_NORMAL
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_040, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability,
        OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::LIGHT_PAINTING)) {
        cout << "skip this test, because LIGHT_PAINTING not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    CAMERA_LOGI("test Camera_Device_Hdi_V1_3_040 start.");
    EXPCET_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_CONTROL_SUPPORTED_COLOR_MODES, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    for (uint8_t i = 0; i < entry.count; i++) {
        // Get stream operator
        cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
        cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
            cameraTest->streamOperator_V1_3);
        EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        // Preview streamInfo
        cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->streamInfoPre->v1_0.width_ = captureWidth;
        cameraTest->streamInfoPre->v1_0.height_ = captureHeight;
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
        // Video streamInfo
        cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->streamInfoVideo->v1_0.width_ = captureWidth;
        cameraTest->streamInfoVideo->v1_0.height_ = captureHeight;
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
        // Create and commitStream
        cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
            static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_3::LIGHT_PAINTING),
            cameraTest->abilityVec);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

        // Update settings
        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t xmageMode = entry.data.u8[i];
        meta->addEntry(OHOS_CONTROL_SUPPORTED_COLOR_MODES, &xmageMode, 1);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
        cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}