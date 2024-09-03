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
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_1); // assert inside
}

void CameraFrontUtTestV1_3::TearDown(void)
{
    cameraTest->Close();
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
    ASSERT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    ASSERT_NE(data, nullptr);
    camera_metadata_item_t entry;
    
    std::shared_ptr<CameraSetting> modeSetting = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t depthDataAccuracy = static_cast<uint8_t>(OHOS_DEPTH_DATA_ACCURACY_RELATIVE);
    modeSetting->addEntry(OHOS_CONTROL_DEPTH_DATA_ACCURACY, &depthDataAccuracy, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(modeSetting, metaVec);
    cameraTest->cameraDeviceV1_3->UpdateSettings(metaVec);
    
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