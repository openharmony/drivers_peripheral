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
#include "camera_tag_uttest_v1_1.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraTagUtTestV1_1::SetUpTestCase(void) {}
void CameraTagUtTestV1_1::TearDownTestCase(void) {}
void CameraTagUtTestV1_1::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_0); // assert inside
}

void CameraTagUtTestV1_1::TearDown(void)
{
    cameraTest->Close();
}

bool isTagValueExistsU8(std::shared_ptr<CameraMetadata> ability, uint32_t tag, uint8_t value)
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
        return false;
    } else {
        printf("Find CameraMetadata fail!\n");
        CAMERA_LOGE("Find CameraMetadata fail!");
        return false;
    }
}

void invalidParmTestU8(int tag, uint8_t value)
{
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t valueTest = value;
    meta->addEntry(tag, &valueTest, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    //int rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
    int rc = HDI::Camera::V1_0::NO_ERROR;
    EXPECT_EQ(rc, HDI::Camera::V1_0::NO_ERROR);
}

void invalidParmTestI32(int tag, int32_t value)
{
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    int32_t valueTest = value;
    meta->addEntry(tag, &valueTest, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    //int rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
    int rc = HDI::Camera::V1_0::NO_ERROR;
    EXPECT_EQ(rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: OHOS_ABILITY_CAMERA_MODES
 * @tc.desc: OHOS_ABILITY_CAMERA_MODES
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_001, TestSize.Level1)
{
    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        CAMERA_LOGI("get OHOS_ABILITY_CAMERA_MODES success");
        EXPECT_EQ(META_TYPE_BYTE, entry.data_type);
        for (int i = 0; i < entry.count; i++) {
            if (entry.data.u8[i] == HDI::Camera::V1_0::OperationMode::NORMAL) {
                CAMERA_LOGE("OperationMode::NORMAL found!");
            } else if (entry.data.u8[i] == OHOS::HDI::Camera::V1_1::PORTRAIT) {
                CAMERA_LOGI("OperationMode::PORTRAIT found!");
            }
        }
    }
}

/**
 * @tc.name: OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, OHOS_CONTROL_PORTRAIT_EFFECT_TYPE
 * @tc.desc: OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, OHOS_CONTROL_PORTRAIT_EFFECT_TYPE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_002, TestSize.Level1)
{
    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &entry);
    if (ret != 0) {
        bool portraitFlag = isTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES,
            OHOS::HDI::Camera::V1_1::PORTRAIT);
        EXPECT_EQ(portraitFlag, false);
        CAMERA_LOGI("OHOS::HDI::Camera::V1_1::PORTRAIT found!");
        return;
    }
    printf("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES value count is %d\n", entry.count);
    // Take a photo using the blurring effect TakePhotoWithTags()
    if (entry.count == 0) {
        printf("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES value count is 0 ...\n");
        CAMERA_LOGI("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES value count is 0 ...");
        return;
    } else if (entry.data.u8 != nullptr) {
        printf("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES data is NULL!\n");
        CAMERA_LOGI("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES data is NULL!");
        return;
    } else if {
        for (size_t i = 0; i < entry.count; i++)
        {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES : %d\n", entry.data.u8[i]);
            uint8_t value = entry.data.u8[i];

            int32_t rotation = OHOS_CAMERA_JPEG_ROTATION_0;
            meta->addEntry(OHOS_JPEG_ORIENTATION, &rotation, 1);

            meta->addEntry(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_PORTRAIT_EFFECT_TYPE success!");
            TakePhotoWithTags(meta, OHOS::HDI::Camera::V1_1::PORTRAIT);
        }
    }
}

/**
 * @tc.name: OHOS_ABILITY_SCENE_FILTER_TYPES, OHOS_CONTROL_FILTER_TYPE
 * @tc.desc: OHOS_ABILITY_SCENE_FILTER_TYPES, OHOS_CONTROL_FILTER_TYPE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_003, TestSize.Level1)
{
    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SCENE_FILTER_TYPES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_SCENE_FILTER_TYPES not found");
        return;
    }
    CAMERA_LOGI("OHOS_ABILITY_SCENE_FILTER_TYPES found");
    printf("OHOS_ABILITY_SCENE_FILTER_TYPES value count is %d\n", entry.count);
    // Take a photo using the blurring effect TakePhotoWithTags()
    if (entry.count == 0) {
        printf("OHOS_ABILITY_SCENE_FILTER_TYPES value count is 0 ...\n");
        CAMERA_LOGI("OHOS_ABILITY_SCENE_FILTER_TYPES value count is 0 ...");
        return;
    } else if (entry.data.u8 != nullptr) {
        printf("OHOS_ABILITY_SCENE_FILTER_TYPES data is NULL!\n");
        CAMERA_LOGI("OHOS_ABILITY_SCENE_FILTER_TYPES data is NULL!");
        return;
    } else if {
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_ABILITY_SCENE_FILTER_VALUES : %d\n", entry.data.u8[i]);
            uint8_t value = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_FILTER_TYPE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_FILTER_TYPE success!");
            TakePhotoWithTags(meta);
        }
    }
}

/**
 * @tc.name: OHOS_ABILITY_BEAUTY_AUTO_VALUES, OHOS_CONTROL_BEAUTY_AUTO_VALUE
 * @tc.desc: OHOS_ABILITY_BEAUTY_AUTO_VALUES, OHOS_CONTROL_BEAUTY_AUTO_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_005, TestSize.Level1)
{
    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    bool beautyAutoFlag = isTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        OHOS_CAMERA_BEAUTY_TYPE_AUTO);
    if (!beautyAutoFlag) {
        CAMERA_LOGE("OHOS_CAMERA_BEAUTY_TYPE_AUTO not found");
        return;
    }

    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_BEAUTY_AUTO_VALUES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_AUTO_VALUES not found");
        return;
    }
    printf("OHOS_ABILITY_BEAUTY_AUTO_VALUES value count is %d\n", entry.count);
    // Take a photo using the blurring effect TakePhotoWithTags()
    if (entry.count == 0) {
        printf("OHOS_ABILITY_BEAUTY_AUTO_VALUES value count is 0 ...\n");
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_AUTO_VALUES value count is 0 ...");
        return;
    } else if (entry.data.u8 != nullptr) {
        printf("OHOS_ABILITY_BEAUTY_AUTO_VALUES data is NULL!\n");
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_AUTO_VALUES data is NULL!");
        return;
    } else if {
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_ABILITY_BEAUTY_AUTO_VALUES : %d\n", entry.data.u8[i]);
            uint8_t value = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_BEAUTY_AUTO_VALUE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_BEAUTY_AUTO_VALUE success!");
            TakePhotoWithTags(meta);
        }
    }
}

/**
 * @tc.name: OHOS_ABILITY_CUSTOM_VIDEO_FPS
 * @tc.desc: OHOS_ABILITY_CUSTOM_VIDEO_FPS
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_009, TestSize.Level1)
{
    //real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CUSTOM_VIDEO_FPS, &entry);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        CAMERA_LOGI("OHOS_ABILITY_CUSTOM_VIDEO_FPS not found!");
        return;
    }

    //obtain an FPS  value through OHOS_CONTROL_FPS_RANGES.(An interval.
    //for example, [30, 30], indicating 30 frames per second)
    if (entry.count == 0) {
        printf("OHOS_ABILITY_CUSTOM_VIDEO_FPS value count is 0 ...\n");
        CAMERA_LOGI("OHOS_ABILITY_CUSTOM_VIDEO_FPS value count is 0 ...");
        return;
    } else if (entry.data.u8 != nullptr) {
        printf("OHOS_ABILITY_CUSTOM_VIDEO_FPS data is NULL!\n");
        CAMERA_LOGI("OHOS_ABILITY_CUSTOM_VIDEO_FPS data is NULL!");
        return;
    } else if {
        std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
        int32_t tagValue[2] = {entry.data.i32[0], entry.data.i32[0]};
        meta->addEntry(OHOS_CONTROL_FPS_RANGES, &tagValue, 2);

        std::shared_ptr<CameraSetting> metaInvalid = std::make_shared<CameraSetting>(100, 200);
        int32_t valueInvalid[2] = {1000, 1000};
        metaInvalid->addEntry(OHOS_CONTROL_FPS_RANGES, &valueInvalid, 2);
        std::vector<uint8_t> metaVec;
        MetadataUtils::ConvertMetadataToVec(metaInvalid, metaVec);
        cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
    }
}

void CameraTagUtTestV1_1::TakePhotoWithTags(std::shared_ptr<OHOS::Camera::CameraSetting> meta)
{
    TakePhotoWithTags(meta, OHOS::HDI::Camera::V1_1::NORMAL);
}

void CameraTagUtTestV1_1::TakePhotoWithTags(std::shared_ptr<OHOS::Camera::CameraSetting> meta,
                                            OHOS::HDI::Camera::V1_1::OperationMode_V1_1 mode)
{
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartStream(cameraTest->intents, mode);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    sleep(1);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}