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
#include "camera_stream_uttest_v1_2.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

constexpr uint32_t ITEM_CAPACITY = 100;
constexpr uint32_t DATA_CAPACITY = 2000;
constexpr uint32_t DATA_COUNT = 1;
void CameraStreamUtTestV1_2::SetUpTestCase(void) {}
void CameraStreamUtTestV1_2::TearDownTestCase(void) {}
void CameraStreamUtTestV1_2::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::HdiCommonV1_2>();
    cameraTest->Init(); // assert inside
    cameraTest->OpenCameraV1_2(DEVICE_0); // assert inside
}

void CameraStreamUtTestV1_2::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name:Camera_Device_Hdi_V1_2_036
 * @tc.desc: updateColorSpace by updateStreams
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraStreamUtTestV1_2, Camera_Stream_Hdi_V1_2_036, TestSize.Level1)
{
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::HdiCommonV1_2::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    EXPECT_NE(cameraTest->streamOperator_V1_2, nullptr);
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = OHOS_CAMERA_SRGB_FULL;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);
    // capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfoCapture->v1_0.dataspace_ = OHOS_CAMERA_SRGB_FULL;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
    cameraTest->rc = cameraTest->streamOperator_V1_2->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_2->CommitStreams(
        OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    sleep(UT_SECOND_TIMES);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->streamOperator_V1_2->CancelCapture(cameraTest->captureIdPreview);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = OHOS_CAMERA_P3_FULL;
    cameraTest->streamInfoCapture->v1_0.dataspace_ = OHOS_CAMERA_P3_FULL;
    cameraTest->rc = cameraTest->streamOperator_V1_2->UpdateStreams(cameraTest->streamInfosV1_1);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name:Camera_Stream_Hdi_V1_2_053
 * @tc.desc:auto exposure
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraStreamUtTestV1_2, Camera_Stream_Hdi_V1_2_053, TestSize.Level1)
{
    //Get Stream Operator
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::HdiCommonV1_2::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    EXPECT_NE(cameraTest->streamOperator_V1_2, nullptr);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    
    //preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    
    //capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
    
    //create and commit stream
    cameraTest->rc = cameraTest->streamOperator_V1_2->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_2->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::NIGHT),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    //start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    
    //wait for auto exposuring end
    sleep(10);
    
    //stop stream
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name:Camera_Stream_Hdi_V1_2_054
 * @tc.desc:manual exposure
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraStreamUtTestV1_2, Camera_Stream_Hdi_V1_2_054, TestSize.Level1)
{
    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t manualExposureTime = 8000;
    meta->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &manualExposureTime, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_2::CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    //Get Stream Operator
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::HdiCommonV1_2::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    EXPECT_NE(cameraTest->streamOperator_V1_2, nullptr);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    
    //preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    
    //capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
    
    //create and commit stream
    cameraTest->rc = cameraTest->streamOperator_V1_2->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_2->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::NIGHT),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    //start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    
    //wait for manual exposuring end
    sleep(10);
    
    //stop stream
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name:Camera_Stream_Hdi_V1_2_055
 * @tc.desc:manual exposure and then confirmCapture
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraStreamUtTestV1_2, Camera_Stream_Hdi_V1_2_055, TestSize.Level1)
{
    //update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t manualExposureTime = 8000;
    meta->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, &manualExposureTime, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_2::CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    //Get Stream Operator
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::HdiCommonV1_2::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    EXPECT_NE(cameraTest->streamOperator_V1_2, nullptr);
    cameraTest->imageDataSaveSwitch = SWITCH_ON;
    
    //preview streamInfo
    cameraTest->streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoPre);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoPre);
    
    //capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);
    
    //create and commit stream
    cameraTest->rc = cameraTest->streamOperator_V1_2->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_2->CommitStreams_V1_1(
        static_cast<OHOS::HDI::Camera::V1_1::OperationMode_V1_1>(OHOS::HDI::Camera::V1_2::NIGHT),
        cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    
    //start capture
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    
    //wait for manual exposuring end confirmCapture
    sleep(UT_SLEEP_TIME);
    EXPECT_NE(cameraTest->streamOperator_V1_2, nullptr);
    cameraTest->streamOperator_V1_2->ConfirmCapture(cameraTest->streamIdCapture);
    sleep(UT_SLEEP_TIME);
    
    //stop stream
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->imageDataSaveSwitch = SWITCH_OFF;
}

/**
 * @tc.name: Camera_Stream_Hdi_V1_2_056
 * @tc.desc: SMOOTH ZOOM
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraStreamUtTestV1_2, Camera_Stream_Hdi_V1_2_056, TestSize.Level1)
{
    cameraTest->streamOperatorCallbackV1_2 = new OHOS::Camera::HdiCommonV1_2::TestStreamOperatorCallbackV1_2();
    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStreamOperator_V1_2(cameraTest->streamOperatorCallbackV1_2,
        cameraTest->streamOperator_V1_2);
    EXPECT_NE(cameraTest->streamOperator_V1_2, nullptr);
    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfoV1_1->v1_0.dataspace_ = OHOS_CAMERA_SRGB_FULL;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    // capture streamInfo
    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfoCapture->v1_0.dataspace_ = OHOS_CAMERA_SRGB_FULL;
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    // video streamInfo
    cameraTest->streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosVideo(cameraTest->streamInfoVideo);

    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoVideo);

    // start stream
    cameraTest->rc = cameraTest->streamOperator_V1_2->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_2->CommitStreams(
        OperationMode::NORMAL, cameraTest->abilityVec);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, true);
    cameraTest->StartCapture(cameraTest->streamIdVideo, cameraTest->captureIdVideo, false, true);

    /*****************************************************************************************/

    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    // cover tag OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE, &entry);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // cover OHOS_CONTROL_PREPARE_ZOOM and its values
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);

    // cover OHOS_CAMERA_ZOOMSMOOTH_PREPARE_ENABLE
    uint8_t pre_zoom_value = OHOS_CAMERA_ZOOMSMOOTH_PREPARE_ENABLE;
    meta->addEntry(OHOS_CONTROL_PREPARE_ZOOM, &pre_zoom_value, DATA_COUNT);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_2::CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // cover OHOS_CONTROL_SMOOTH_ZOOM_RATIOS,  values type: uint32_t array
    uint32_t values[] = { 10, 300, 20, 400, 30, 500 };
    meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    meta->addEntry(OHOS_CONTROL_SMOOTH_ZOOM_RATIOS, values, sizeof(values) / sizeof(uint32_t));

    setting.clear();
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_2::CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // cover GetStatus(), OHOS_STATUS_CAMERA_CURRENT_FPS and  OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO
    std::shared_ptr<CameraSetting> metaIn = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    // no sense
    uint32_t current_fps = 0;
    uint32_t current_zoom_ratio = 0;
    metaIn->addEntry(OHOS_STATUS_CAMERA_CURRENT_FPS, &current_fps, DATA_COUNT);
    metaIn->addEntry(OHOS_STATUS_CAMERA_CURRENT_ZOOM_RATIO, &current_zoom_ratio, DATA_COUNT);

    std::vector<uint8_t> settingIn, settingOut;
    MetadataUtils::ConvertMetadataToVec(metaIn, settingIn);

    cameraTest->rc = cameraTest->cameraDeviceV1_2->GetStatus(settingIn, settingOut);

    if (HDI::Camera::V1_0::NO_ERROR == cameraTest->rc) {
        std::cout << "GetStatus execute success." << std::endl;
    }

    meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    // cover OHOS_CAMERA_ZOOMSMOOTH_PREPARE_DISABLE
    pre_zoom_value = OHOS_CAMERA_ZOOMSMOOTH_PREPARE_DISABLE ;
    meta->addEntry(OHOS_CONTROL_PREPARE_ZOOM, &pre_zoom_value, DATA_COUNT);
    setting.clear();
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_2::CamRetCode)cameraTest->cameraDevice->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    // /*****************************************************************************************/
    // 后处理
    cameraTest->captureIds = {cameraTest->captureIdPreview, cameraTest->captureIdCapture, cameraTest->captureIdVideo};

    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture, cameraTest->streamIdVideo};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}