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
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc)
    // preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoPre->v1_0.width_ = 1920;
    cameraTest->streamInfoPre->v1_0.height_ = 1080;
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoVideo->v1_0.width_ = 1920;
    cameraTest->streamInfoVideo->v1_0.height_ = 1080;
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo)
    // create and commitStream
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
    static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::HIGH_FRAME_RATE),
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
    if (!IsTagValueExistsU8(cameraTest->ability,OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE)) {
        cout << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    CreateAndCommitStreamsForHighFrameRate(cameraTest);

    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t highFrameRate[2] = {120,120};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &highFrameRate, 2);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
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
    if (!IsTagValueExistsU8(cameraTest->ability,OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_3::HIGH_FRAME_RATE)) {
        cout << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    CreateAndCommitStreamsForHighFrameRate(cameraTest);

    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t highFrameRate[2] = {240,240};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &highFrameRate, 2);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
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
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc)
    // preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoPre->v1_0.width_ = 1920;
    cameraTest->streamInfoPre->v1_0.height_ = 1080;
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    // video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->streamInfoVideo->v1_0.width_ = 1920;
    cameraTest->streamInfoVideo->v1_0.height_ = 1080;
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo)
    // create and commitStream
    cameraTest->rc = cameraTest->streamOperator_V1_1->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_1->CommitStreams_V1_1(
    static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::SLOW_MOTION),
    cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
}

static void UpdateSettingsForSlowMotionMode(std::shared_ptr<OHOS::Camera::Test> cameraTest)
{
    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t valueInvalid[2] = {960,960};
    float motionCheckArea[4] = {1, 1, 1, 1};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &valueInvalid, 2);
    meta->addEntry(OHOS_CONTROL_MOTION_DETECTION_CHECK_AREA, &motionCheckArea, 4);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc)
    int32_t slowMotionControl = OHOS_CAMERA_MOTION_DETECTION_ENABLE;
    meta->addEntry(OHOS_CONTROL_MOTION_DETECTION, &slowMotionControl, DATA_CAPACITY);
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    // start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true)
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdVideo};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
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
    if (!IsTagValueExistsU8(cameraTest->ability,OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_2::SLOW_MOTION)) {
        cout << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    // Get Stream Operator
    cameraTest->streamOperatorCallback = new OHOS::Camera::Test::TestStreamOperatorCallback();
    cameraTest->rc = cameraTest->cameraDeviceV1_1->GetStreamOperator_V1_1(cameraTest->streamOperatorCallback,
        cameraTest->streamOperator_V1_1);
    EXPECT_NE(cameraTest->streamOperator_V1_1, nullptr);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    CreateAndCommitStreamsForSlowMotion(cameraTest);

    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t slowMotionValue[2] = {960,960};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &slowMotionValue, 2);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
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
    if (!IsTagValueExistsU8(cameraTest->ability,OHOS_ABILITY_CAMERA_MODES, OHOS::HDI::Camera::V1_2::SLOW_MOTION)) {
        cout << "skip this test, because SLOW_MOTION not in OHOS_ABILITY_CAMERA_MODES" << endl;
        return;
    }
    int32_t rc;
    // step 2: set callback object
    cameraTest->hostCallbackV1_2 = new OHOS::Camera::Test::TestCameraHostCallbackV1_2();
    rc = cameraTest->serviceV1_2->SetCallback_V1_2(cameraTest->hostCallbackV1_2);
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
            common_metadata_header_t* data = cameraTest->deviceCallback->resultMeta->get();
            EXPECT_NE(data, nullptr);
            camera_metadata_item_t entry;
            cameraTest->rc = FindCameraMetadataItem(data, OHOS_STATUS_SLOW_MOTION_DETECTION, &entry);
            EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
            if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
                uint8_t value = entry.data.u8[0];
                // 检测到超级慢动作的状态
                if (OHOS_CONTROL_SLOW_MOTION_STATUS_DISABLE == value){
                    printf("slow motion status is disabled");
                }else if (OHOS_CONTROL_SLOW_MOTION_STATUS_READY == value){
                    printf("slow motion status is ready");
                }else if (OHOS_CONTROL_SLOW_MOTION_STATUS_START == value){
                    printf("slow motion status is started");
                }else if (OHOS_CONTROL_SLOW_MOTION_STATUS_RECORDING == value){
                    printf("slow motion status is recording");
                }else if (OHOS_CONTROL_SLOW_MOTION_STATUS_FINISH == value){
                    printf("slow motion status is finished");
                }

            }
        }
    }
}