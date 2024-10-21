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
#include "camera_front_uttest_v1_3.h"
#include <functional>

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
using namespace OHOS::HDI::Camera;
constexpr uint32_t DATA_COUNT = 1;
constexpr uint32_t ITEM_CAPACITY = 100;
constexpr uint32_t DATA_CAPACITY = 2000;
void CameraFrontUtTestV1_3::SetUpTestCase(void) {}
void CameraFrontUtTestV1_3::TearDownTestCase(void) {}
void CameraFrontUtTestV1_3::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::HdiCommonV1_3>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_1); // assert inside
}

void CameraFrontUtTestV1_3::TearDown(void)
{
    cameraTest->Close();
}

void FillFrontCaptureSetting(std::shared_ptr<OHOS::Camera::HdiCommonV1_3> cameraTest)
{
    // Fill capture setting
    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t muteMode = static_cast<uint8_t>(OHOS_CAMERA_MUTE_MODE_OFF);
    modeSetting->addEntry(OHOS_CONTROL_MUTE_MODE, &muteMode, DATA_COUNT);
    uint8_t deferredImage = OHOS::HDI::Camera::V1_2::STILL_IMAGE;
    modeSetting->addEntry(OHOS_CONTROL_DEFERRED_IMAGE_DELIVERY, &deferredImage, DATA_COUNT);
    std::vector<uint8_t> controlVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, controlVec);
    cameraTest->abilityVec = controlVec;
}

/**
 * @tc.name: Camera_Front_Hdi_V1_3_001
 * @tc.desc: OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraFrontUtTestV1_3, Camera_Front_Hdi_V1_3_001, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (size_t i = 0; i < entry.count; i++) {
            uint8_t captureMirror = entry.data.u8[i];
            if (captureMirror == OHOS_CAMERA_MIRROR_CAPTURE) {
                CAMERA_LOGI("Capture mirror is supported, mirror capture tag is: %{public}d", captureMirror);

                cameraTest->intents = {PREVIEW, STILL_CAPTURE};
                cameraTest->StartStream(cameraTest->intents);
                uint8_t cameraMirrorControl = OHOS_CAMERA_MIRROR_ON;
                cameraTest->ability->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &cameraMirrorControl, DATA_COUNT);
                std::vector<uint8_t> metaVec;
                OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraTest->ability, metaVec);
                cameraTest->abilityVec = metaVec;

                cameraTest->imageDataSaveSwitch = SWITCH_ON;
                cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
                cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);

                cameraTest->captureIds = {cameraTest->captureIdPreview};
                cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
                cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
                cameraTest->imageDataSaveSwitch = SWITCH_OFF;
            } else if (captureMirror == OHOS_CAMERA_MIRROR_CAPTURE_VIDEO) {
                CAMERA_LOGI("Capture mirror is supported, mirror capture video tag is: %{public}d", captureMirror);
            } else if (captureMirror == OHOS_CAMERA_MIRROR_NOT_SUPPORT) {
                CAMERA_LOGI("Capture Mirror is not supported, tag is: %{public}d", captureMirror);
            }
        }
    }
}

/**
+ * @tc.name:Camera_Front_Hdi_V1_3_002
+ * @tc.desc:Dynamic capture mirror configuration, fixed capture mirror setting, streams capture mirror constrain
+ * @tc.size:MediumTest
+ * @tc.type:Function
+*/
HWTEST_F(CameraFrontUtTestV1_3, Camera_Front_Hdi_V1_3_002, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_CAPTURE_MIRROR_SUPPORTED, &entry);

    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        for (size_t i = 0; i < entry.count; i++) {
            uint8_t captureMirror = entry.data.u8[i];
            if (captureMirror == OHOS_CAMERA_MIRROR_CAPTURE) {
                CAMERA_LOGI("Capture mirror is supported, mirror capture tag is: %{public}d", captureMirror);

                cameraTest->intents = {PREVIEW, STILL_CAPTURE};
                cameraTest->StartStream(cameraTest->intents);
                uint8_t cameraMirrorControl = OHOS_CAMERA_MIRROR_OFF;
                cameraTest->ability->addEntry(OHOS_CONTROL_CAPTURE_MIRROR, &cameraMirrorControl, DATA_COUNT);
                std::vector<uint8_t> metaVec;
                OHOS::Camera::MetadataUtils::ConvertMetadataToVec(cameraTest->ability, metaVec);
                cameraTest->abilityVec = metaVec;

                cameraTest->imageDataSaveSwitch = SWITCH_ON;
                cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
                cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);

                cameraTest->captureIds = {cameraTest->captureIdPreview};
                cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
                cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
                cameraTest->imageDataSaveSwitch = SWITCH_OFF;

            } else if (captureMirror == OHOS_CAMERA_MIRROR_CAPTURE_VIDEO) {
                CAMERA_LOGI("Capture mirror is supported, mirror capture video tag is: %{public}d", captureMirror);
            } else if (captureMirror == OHOS_CAMERA_MIRROR_NOT_SUPPORT) {
                CAMERA_LOGI("Capture Mirror is not supported, tag is: %{public}d", captureMirror);
            }
        }
    }
}

/**
 * @tc.name: Camera_Front_Hdi_V1_3_003
 * @tc.desc: OHOS_ABILITY_DEPTH_DATA_PROFILES
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraFrontUtTestV1_3, Camera_Front_Hdi_V1_3_003, TestSize.Level1)
{
    ASSERT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    ASSERT_NE(data, nullptr);
    camera_metadata_item_t entry;

    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_DEPTH_DATA_PROFILES, &entry);
    if (cameraTest->rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("OHOS_ABILITY_DEPTH_DATA_PROFILES is not support.");
        return;
    }
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_DEPTH_DATA_PROFILES> i32 value start.");
        constexpr size_t step = 10;
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_DEPTH_DATA_PROFILES %s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_DEPTH_DATA_PROFILES> i32 value end.");
    }
}

/**
 * @tc.name: Camera_Front_Hdi_V1_3_004
 * @tc.desc: OHOS_CONTROL_DEPTH_DATA_ACCURACY
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraFrontUtTestV1_3, Camera_Front_Hdi_V1_3_004, TestSize.Level1)
{
    CAMERA_LOGI("test Camera_Front_Hdi_V1_3_004 start.");
    cameraTest->streamOperatorCallbackV1_3 = new OHOS::Camera::HdiCommonV1_3::TestStreamOperatorCallbackV1_3();
    cameraTest->rc = cameraTest->cameraDeviceV1_3->GetStreamOperator_V1_3(
        cameraTest->streamOperatorCallbackV1_3, cameraTest->streamOperator_V1_3);
    ASSERT_NE(cameraTest->streamOperator_V1_3, nullptr);

    cameraTest->streamInfoV1_1 = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosPreview(cameraTest->streamInfoV1_1);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoV1_1);

    cameraTest->streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    cameraTest->DefaultInfosCapture(cameraTest->streamInfoCapture);
    cameraTest->streamInfosV1_1.push_back(*cameraTest->streamInfoCapture);

    FillFrontCaptureSetting(cameraTest);
    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t depthDataAccuracy = static_cast<uint8_t>(OHOS_DEPTH_DATA_ACCURACY_RELATIVE);
    modeSetting->addEntry(OHOS_CONTROL_DEPTH_DATA_ACCURACY, &depthDataAccuracy, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, metaVec);
    cameraTest->cameraDeviceV1_3->UpdateSettings(metaVec);

    cameraTest->rc = cameraTest->streamOperator_V1_3->CreateStreams_V1_1(cameraTest->streamInfosV1_1);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
    cameraTest->rc = cameraTest->streamOperator_V1_3->CommitStreams(
        OHOS::HDI::Camera::V1_0::OperationMode::NORMAL, cameraTest->abilityVec);
    ASSERT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);

    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}

/**
 * @tc.name: Camera_Front_Hdi_V1_3_005
 * @tc.desc: OHOS_ABILITY_LCD_FLASH OHOS_CONTROL_LCD_FLASH_DETECTION OHOS_STATUS_LCD_FLASH_STATUS OHOS_CONTROL_LCD_FLASH
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraFrontUtTestV1_3, Camera_Front_Hdi_V1_3_005, TestSize.Level1)
{
    // 查询是否支持环形补光
    ASSERT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    ASSERT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_LCD_FLASH, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        if (entry.data.i32[0] != 1) return;
        FillFrontCaptureSetting(cameraTest);
        cameraTest->intents = {PREVIEW, STILL_CAPTURE};
        cameraTest->StartStream(cameraTest->intents, OHOS::HDI::Camera::V1_3::CAPTURE);
        // 开启预览流
        cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
        // 使能环形补光
        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
        uint8_t lcdFlashDetection = 1;
        meta->addEntry(OHOS_CONTROL_LCD_FLASH_DETECTION, &lcdFlashDetection, DATA_COUNT);
        std::vector<uint8_t> setting;
        MetadataUtils::ConvertMetadataToVec(meta, setting);
        cameraTest->rc = (OHOS::HDI::Camera::V1_0::CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
        ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        sleep(3);
        if (cameraTest->deviceCallback->resultMeta == nullptr) {
            CAMERA_LOGI("Camera_Device_Hdi_V1_3_049 onresult not be invoked.");
            return;
        }
        // 返回结果是否需要环形补光
        common_metadata_header_t* data = cameraTest->deviceCallback->resultMeta->get();
        if (data == nullptr) {
            CAMERA_LOGI("Camera_Device_Hdi_V1_3_049 onresult be invoked but data was nullptr.");
            return;
        }
        camera_metadata_item_t entry;
        cameraTest->rc = FindCameraMetadataItem(data, OHOS_STATUS_LCD_FLASH_STATUS, &entry);
        if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
            if (!entry.data.i32[0]) return;
            // 使能环形补光
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            uint8_t lcdFlash = 1;
            meta->addEntry(OHOS_CONTROL_LCD_FLASH, &lcdFlash, DATA_COUNT);
            std::vector<uint8_t> setting;
            MetadataUtils::ConvertMetadataToVec(meta, setting);
            cameraTest->rc = (OHOS::HDI::Camera::V1_0::CamRetCode)cameraTest->
                cameraDeviceV1_3->UpdateSettings(setting);
            ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);
        }
        // 进行拍照
        cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
        cameraTest->captureIds = {cameraTest->captureIdPreview};
        cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
        cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
    }
}