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
#include "camera_3a_uttest.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void Camera3AUtTest::SetUpTestCase(void) {}
void Camera3AUtTest::TearDownTestCase(void) {}
void Camera3AUtTest::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::HdiCommon>();
    cameraTest->Init();
    cameraTest->Open();
}

void Camera3AUtTest::TearDown(void)
{
    cameraTest->Close();
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_001, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_AUTO, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_002, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_INCANDESCENT, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_003, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_INCANDESCENT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_FLUORESENT, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_004, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_FLUORESCENT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_DAYLIGHT, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_005, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_DAYLIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_006, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_CLOUDY_DAYLIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_TWILIGHT, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_007, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_TWILIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_SHADE, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_008, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_SHADE;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_OFF, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_009, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_OFF;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview, updateSetting OHOS_CAMERA_AWB_MODE_OFF, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_010, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t awbMode = OHOS_CAMERA_AE_MODE_ON_ALWAYS_FLASH;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(1);
    cameraTest->GetCameraMetadata();
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview set 3A, then close device, and preview, 3A is reset
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_011, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    cameraTest->cameraDevice->Close();
    cameraTest->consumerMap_.clear();
    cameraTest = std::make_shared<OHOS::Camera::HdiCommon>();
    cameraTest->Init();
    cameraTest->Open();
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}


/**
 * @tc.name: updateSetting AE
 * @tc.desc: preview , updatesetting different 3A params together
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_012, TestSize.Level1)
{
    cameraTest->intents = {PREVIEW};
    cameraTest->StartStream(cameraTest->intents);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    std::shared_ptr<CameraMetadata> meta = std::make_shared<CameraSetting>(100, 200);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    uint8_t awbMode = OHOS_CAMERA_AWB_MODE_TWILIGHT;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->cameraDevice->UpdateSettings(metaVec);
    sleep(3); // sleep for 3 seconds
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: updateSetting AE without preview
 * @tc.desc: updatesetting OHOS_CAMERA_AE_EXMPENSATION, without preview, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_013, TestSize.Level1)
{
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 2000);
    int32_t expo = 0xa0;
    meta->addEntry(OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &expo, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: updateSetting AE without preview
 * @tc.desc: updatesetting OHOS_CAMERA_AE_EXMPENSATION, without preview, success
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(Camera3AUtTest, Camera_3a_014, TestSize.Level1)
{
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 2000);
    int32_t awbMode = OHOS_CAMERA_AWB_MODE_AUTO;
    meta->addEntry(OHOS_CONTROL_AWB_MODE, &awbMode, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
}