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
#include "front_camera_tag_uttest_v1_1.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void FrontCameraTagUtTestV1_1::SetUpTestCase(void) {}
void FrontCameraTagUtTestV1_1::TearDownTestCase(void) {}
void FrontCameraTagUtTestV1_1::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::HdiCommonV1_1>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_1); // assert inside
}

void FrontCameraTagUtTestV1_1::TearDown(void)
{
    cameraTest->Close();
}

bool g_isFrontTagValueExistsU8(std::shared_ptr<CameraMetadata> ability, uint32_t tag, uint8_t value)
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
 * @tc.name: OHOS_ABILITY_SCENE_BEAUTY_TYPES, OHOS_CONTROL_BEAUTY_TYPE
 * @tc.desc: OHOS_ABILITY_SCENE_BEAUTY_TYPES, OHOS_CONTROL_BEAUTY_TYPE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(FrontCameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_004, TestSize.Level1)
{
    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SCENE_BEAUTY_TYPES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_SCENE_BEAUTY_TYPES not found");
        return;
    }
    CAMERA_LOGI("OHOS_ABILITY_SCENE_BEAUTY_TYPES found");
    printf("OHOS_ABILITY_SCENE_BEAUTY_TYPES value count is %d\n", entry.count);
    // Take a photo using the blurring effect TakePhotoWithTags()
    if (entry.count == 0) {
        printf("OHOS_ABILITY_SCENE_BEAUTY_TYPES value count is 0\n");
        CAMERA_LOGI("OHOS_ABILITY_SCENE_BEAUTY_TYPES value count is 0");
        return;
    } else if (entry.data.u8 == nullptr) {
        printf("OHOS_ABILITY_SCENE_BEAUTY_TYPES data is NULL!\n");
        CAMERA_LOGI("OHOS_ABILITY_SCENE_BEAUTY_TYPES data is NULL!");
        return;
    } else {
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_ABILITY_SCENE_BEAUTY_VALUES : %d\n", entry.data.u8[i]);
            uint8_t value = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_BEAUTY_TYPE success!");
        }
    }
}

/**
 * @tc.name: OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE
 * @tc.desc: OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(FrontCameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_006, TestSize.Level1)
{
    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    bool beautyFaceSlenderFlag = g_isFrontTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER);
    if (!beautyFaceSlenderFlag) {
        CAMERA_LOGE("OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER not found");
        return;
    }

    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES not found");
        return;
    }
    printf("OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES value count is %d\n", entry.count);
    // Take a photo using the blurring effect TakePhotoWithTags()
    if (entry.count == 0) {
        printf("OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES value count is 0\n");
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES value count is 0");
        return;
    } else if (entry.data.u8 == nullptr) {
        printf("OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES data is NULL!\n");
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES data is NULL!");
        return;
    } else {
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES : %d\n", entry.data.u8[i]);
            uint8_t value = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE success!");
            TakePhotoWithTags(meta);
        }
    }
}

/**
 * @tc.name: OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES, OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE
 * @tc.desc: OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES, OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(FrontCameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_007, TestSize.Level1)
{
    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    bool beautyFaceSlenderFlag = g_isFrontTagValueExistsU8(cameraTest->ability,
        OHOS_ABILITY_SCENE_BEAUTY_TYPES, OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE);
    if (!beautyFaceSlenderFlag) {
        CAMERA_LOGE("OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE not found");
        return;
    }

    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES not found");
        return;
    }
    printf("OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES value count is %d\n", entry.count);
    // Take a photo using the blurring effect TakePhotoWithTags()
    if (entry.count == 0) {
        printf("OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES value count is 0\n");
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES value count is 0");
        return;
    } else if (entry.data.i32 == nullptr) {
        printf("OHOS_ABILITY_SCENE_BEAUTY_TYPES data is NULL!\n");
        CAMERA_LOGI("OHOS_ABILITY_SCENE_BEAUTY_TYPES data is NULL!");
        return;
    } else {
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES : %d\n", entry.data.i32[i]);
            int32_t value = entry.data.i32[i];
            meta->addEntry(OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE success!");
            TakePhotoWithTags(meta);
        }
    }
}

/**
 * @tc.name: OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES, OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE
 * @tc.desc: OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES, OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(FrontCameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_008, TestSize.Level1)
{
    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    bool beautyFaceSlenderFlag = g_isFrontTagValueExistsU8(cameraTest->ability,
        OHOS_ABILITY_SCENE_BEAUTY_TYPES, OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH);
    if (!beautyFaceSlenderFlag) {
        CAMERA_LOGE("OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, not found");
        return;
    }

    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES not found");
        return;
    }
    printf("OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES value count is %d\n", entry.count);
    // Take a photo using the blurring effect TakePhotoWithTags()
    if (entry.count == 0) {
        printf("OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES value count is 0\n");
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES value count is 0");
        return;
    } else if (entry.data.u8 == nullptr) {
        printf("OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES data is NULL!\n");
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES data is NULL!");
        return;
    } else {
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
            printf("OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES : %d\n", entry.data.u8[i]);
            uint8_t value = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE success!");
            TakePhotoWithTags(meta);
        }
    }
}

void FrontCameraTagUtTestV1_1::TakePhotoWithTags(std::shared_ptr<OHOS::Camera::CameraSetting> meta)
{
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    cameraTest->intents = {PREVIEW, STILL_CAPTURE};
    cameraTest->StartStream(cameraTest->intents);
    EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
    cameraTest->StartCapture(cameraTest->streamIdPreview, cameraTest->captureIdPreview, false, true);
    sleep(1);
    cameraTest->StartCapture(cameraTest->streamIdCapture, cameraTest->captureIdCapture, false, false);
    cameraTest->captureIds = {cameraTest->captureIdPreview};
    cameraTest->streamIds = {cameraTest->streamIdPreview, cameraTest->streamIdCapture};
    cameraTest->StopStream(cameraTest->captureIds, cameraTest->streamIds);
}
