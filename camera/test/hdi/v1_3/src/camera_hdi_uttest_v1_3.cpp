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
constexpr uint32_t CHECK_AREA_COUNT = 4;
constexpr uint32_t STREAMINFO_WIDTH = 1920;
constexpr uint32_t STREAMINFO_HEIGHT = 1080;
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
    PrintAllTagDataU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES);
}

static void CreateAndCommitStreamsForHighFrameRate(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    // Get Stream Operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoPre->v1_0.width_ = STREAMINFO_WIDTH;
    cameraTest->streamInfoPre->v1_0.height_ = STREAMINFO_HEIGHT;
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoVideo->v1_0.width_ = STREAMINFO_WIDTH;
    cameraTest->streamInfoVideo->v1_0.height_ = STREAMINFO_HEIGHT;
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
    // create and commitStream
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
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        for (size_t i = 0; i < entry.count; i++ ) {
            float value = entry.data.u8[i];
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
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_2_003, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE)) {
        cout << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    CreateAndCommitStreamsForHighFrameRate(cameraTest);

    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t highFrameRate[2] = {120, 120};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &highFrameRate, 2);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // start capture
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
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_2_004, TestSize.Level1)
{
    if (!IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE)) {
        cout << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    CreateAndCommitStreamsForHighFrameRate(cameraTest);

    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t highFrameRate[2] = {240, 240};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &highFrameRate, 2);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // start capture
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
    // Get Stream Operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    // preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoPre->v1_0.width_ = STREAMINFO_WIDTH;
    cameraTest->streamInfoPre->v1_0.height_ = STREAMINFO_HEIGHT;
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoVideo->v1_0.width_ = STREAMINFO_WIDTH;
    cameraTest->streamInfoVideo->v1_0.height_ = STREAMINFO_HEIGHT;
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);
    // create and commitStream
    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::SLOW_MOTION),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

static void UpdateSettingsForSlowMotionMode(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t valueInvalid[2] = {960, 960};
    float motionCheckArea[4] = {1, 1, 1, 1};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &valueInvalid, FPS_COUNT);
    meta->addEntry(OHOS_CONTROL_MOTION_DETECTION_CHECK_AREA, &motionCheckArea, CHECK_AREA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    int32_t slowMotionControl = OHOS_CAMERA_MOTION_DETECTION_ENABLE;
    meta->addEntry(OHOS_CONTROL_MOTION_DETECTION, &slowMotionControl, DATA_CAPACITY);
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    // start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

static void SuperSlowMotionStatusCallback(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    common_metadata_header_t* data = cameraTest->deviceCallback->resultMeta->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_STATUS_SLOW_MOTION_DETECTION, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        uint8_t value = entry.data.u8[0];
        // 检测到超级慢动作的状态
        if (OHOS_CONTROL_SLOW_MOTION_STATUS_DISABLE == value) {
            printf("slow motion status is disabled");
        } else if (OHOS_CONTROL_SLOW_MOTION_STATUS_READY == value) {
            printf("slow motion status is ready");
        } else if (OHOS_CONTROL_SLOW_MOTION_STATUS_START == value) {
            printf("slow motion status is started");
        } else if (OHOS_CONTROL_SLOW_MOTION_STATUS_RECORDING == value) {
            printf("slow motion status is recording");
        } else if (OHOS_CONTROL_SLOW_MOTION_STATUS_FINISH == value) {
            printf("slow motion status is finished");
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
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        EXPECT_TRUE(entry.data.u8 != nullptr);
        for (size_t i = 0; i < entry.count; i++ ) {
            float value = entry.data.u8[i];
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
    // Get Stream Operator
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::Test::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(cameraTest->streamOperatorCallbackV1_3,
        cameraTest->streamOperator_V1_3);
    EXPECT_NE(cameraTest->streamOperator_V1_3, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    CreateAndCommitStreamsForSlowMotion(cameraTest);

    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t slowMotionValue[2] = {960, 960};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &slowMotionValue, 2);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // start capture
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
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    cameraTest->rc = cameraTest->serviceV1_3->SetCallback_V1_2(cameraTest->hostCallbackV1_2);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_MOTION_DETECTION_SUPPORT, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
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
        // clear infos
        cameraTest->streamInfosV1_1.clear();
        // preview streamInfo
        cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
        cameraTest->streamInfoV1_1->v1_0.dataspace_ = captureColorSpaces[0];
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
        // capture streamInfo
        cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
        cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
        cameraTest->streamInfoCapture->v1_0.dataspace_ = captureColorSpaces[0];
        cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

        // streamInfosV1_1 should not be empty
        cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
        EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams_V1_1(
            OHOS::HDI::Camera::V1_1::OperationMode_V1_1::NORMAL, cameraTest->abilityVec);
        // start without colorspace setting
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);

        for (int32_t colorSpaces : captureColorSpaces) {
            printf("capture colorSpaces value %d\n", colorSpaces);
            // CancelCapture
            cameraTest->streamOperator_V1_3->CancelCapture(cameraTest->captureIdPreview);
            // clear infos
            cameraTest->streamInfosV1_1.clear();
            // preview streamInfo
            cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
            cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
            cameraTest->streamInfoV1_1->v1_0.dataspace_ = colorSpaces;
            cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
            // capture streamInfo
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
 * @tc.name: Camera_Device_Hdi_V1_3_009
 * @tc.desc: OHOS_CONTROL_MOVING_PHOTO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiUtTestV1_3, Camera_Device_Hdi_V1_3_010, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;

    cameraTest->rc = FindCameraMetadataItem(data, OHOS_CONTROL_MOVING_PHOTO, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("OHOS_CONTROL_MOVING_PHOTO is not support");
    } else if (entry.data.u8 != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_CONTROL_MOVING_PHOTO> u8 value start.");
        printf("OHOS_CONTROL_MOVING_PHOTO u8 value count %d\n", entry.count);
        for (size_t i = 0; i < entry.count; i++) {
            if (entry.data.u8[i] == OHOS_CAMERA_MOVING_PHOTO_OFF) {
                printf("OHOS_CONTROL_MOVING_PHOTO mode OHOS_CAMERA_MOVING_PHOTO_OFF");
            } else if (entry.data.u8[i] == OHOS_CAMERA_MOVING_PHOTO_ON) {
                printf("OHOS_CONTROL_MOVING_PHOTO mode OHOS_CAMERA_MOVING_PHOTO_ON");
            }
        }
        CAMERA_LOGI("print tag<OHOS_CONTROL_MOVING_PHOTO> u8 value end.");
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

    cameraTest->rc = FindCameraMetadataItem(data, OHOS_CAMERA_CUSTOM_SNAPSHOT_DURATION, &entry);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    //start stream
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartStream(cameraTest->intents);

    //start preview and capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    //OncaptureReady trigger
    for (uint8_t i = 0; i < 2; i++) {
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    }

    //release stream
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}
