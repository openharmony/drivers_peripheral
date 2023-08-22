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
    cameraTest->Open(); // assert inside
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
    EXPECT_EQ(ret, 0);
    EXPECT_NE(entry.count, 0);
    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == value) {
            return true;
        }
    }
    return false;
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
    // stub codes
    std::vector<uint8_t> cameraModesVector;
    cameraModesVector.push_back(OHOS::HDI::Camera::V1_1::NORMAL);
    cameraModesVector.push_back(OHOS::HDI::Camera::V1_1::PORTRAIT);
    cameraTest->ability->addEntry(OHOS_ABILITY_CAMERA_MODES,
        cameraModesVector.data(), cameraModesVector.size());

    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    EXPECT_EQ(ret, 0);
    CAMERA_LOGI("get OHOS_ABILITY_CAMERA_MODES success");
    EXPECT_EQ(META_TYPE_BYTE, entry.data_type);
    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == HDI::Camera::V1_0::OperationMode::NORMAL) {
            CAMERA_LOGI("OperationMode::NORMAL found!");
        } else if (entry.data.u8[i] == OHOS::HDI::Camera::V1_1::PORTRAIT) {
            CAMERA_LOGI("OperationMode::PORTRAIT found!");
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
    // stub codes
    std::vector<uint8_t> cameraModesVector;
    cameraModesVector.push_back(OHOS::HDI::Camera::V1_1::PORTRAIT);
    cameraTest->ability->addEntry(OHOS_ABILITY_CAMERA_MODES,
        cameraModesVector.data(), cameraModesVector.size());
    std::vector<uint8_t> portraitEffectVector;
    portraitEffectVector.push_back(OHOS_CAMERA_PORTRAIT_CIRCLES);
    cameraTest->ability->addEntry(OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES,
        portraitEffectVector.data(), portraitEffectVector.size());

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

    // Take a photo using the blurring effect TakePhotoWithTags()
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t value = OHOS_CAMERA_PORTRAIT_CIRCLES;
    meta->addEntry(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &value, 1);
    TakePhotoWithTags(meta);

    // Abnormal input parameter validation: The standard behavior is not determined
    uint8_t inValidValue = 100;
    invalidParmTestU8(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, inValidValue);
}

/**
 * @tc.name: OHOS_ABILITY_SCENE_FILTER_TYPES, OHOS_CONTROL_FILTER_TYPE
 * @tc.desc: OHOS_ABILITY_SCENE_FILTER_TYPES, OHOS_CONTROL_FILTER_TYPE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_003, TestSize.Level1)
{
    // stub codes
    std::vector<uint8_t> filterTypesVector;
    filterTypesVector.push_back(OHOS_CAMERA_FILTER_TYPE_CLASSIC);
    cameraTest->ability->addEntry(OHOS_ABILITY_SCENE_FILTER_TYPES,
        filterTypesVector.data(), filterTypesVector.size());

    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SCENE_FILTER_TYPES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_SCENE_FILTER_TYPES not found");
        return;
    }
    CAMERA_LOGI("OHOS_ABILITY_SCENE_FILTER_TYPES found");

    // Take a photo using the blurring effect TakePhotoWithTags()
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t value = OHOS_CAMERA_FILTER_TYPE_CLASSIC;
    meta->addEntry(OHOS_CONTROL_FILTER_TYPE, &value, 1);
    TakePhotoWithTags(meta);

    // Abnormal input parameter validation: The standard behavior is not determined
    uint8_t inValidValue = 100;
    invalidParmTestU8(OHOS_CONTROL_FILTER_TYPE, inValidValue);
}
/**
 * @tc.name: OHOS_ABILITY_SCENE_BEAUTY_TYPES, OHOS_CONTROL_BEAUTY_TYPE
 * @tc.desc: OHOS_ABILITY_SCENE_BEAUTY_TYPES, OHOS_CONTROL_BEAUTY_TYPE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_004, TestSize.Level1)
{
    std::vector<uint8_t> beautyTypesVector;
    beautyTypesVector.push_back(OHOS_CAMERA_BEAUTY_TYPE_OFF);
    cameraTest->ability->addEntry(OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        beautyTypesVector.data(), beautyTypesVector.size());

    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SCENE_BEAUTY_TYPES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_SCENE_BEAUTY_TYPES not found");
        return;
    }
    CAMERA_LOGI("OHOS_ABILITY_SCENE_BEAUTY_TYPES found");

    // Take a photo using the blurring effect TakePhotoWithTags()
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t value = OHOS_CAMERA_BEAUTY_TYPE_OFF;
    meta->addEntry(OHOS_CONTROL_BEAUTY_TYPE, &value, 1);
    TakePhotoWithTags(meta);

    // Abnormal input parameter validation: The standard behavior is not determined
    uint8_t inValidValue = 100;
    invalidParmTestU8(OHOS_CONTROL_BEAUTY_TYPE, inValidValue);
}

/**
 * @tc.name: OHOS_ABILITY_BEAUTY_AUTO_VALUES, OHOS_CONTROL_BEAUTY_AUTO_VALUE
 * @tc.desc: OHOS_ABILITY_BEAUTY_AUTO_VALUES, OHOS_CONTROL_BEAUTY_AUTO_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_005, TestSize.Level1)
{
    // stub codes
    std::vector<uint8_t> beautyTypesVector;
    beautyTypesVector.push_back(OHOS_CAMERA_BEAUTY_TYPE_AUTO);
    cameraTest->ability->addEntry(OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        beautyTypesVector.data(), beautyTypesVector.size());
    std::vector<uint8_t> beautyAutoVector;
    uint8_t beautyAutoValue = 0;
    beautyAutoVector.push_back(beautyAutoValue);
    cameraTest->ability->addEntry(OHOS_ABILITY_BEAUTY_AUTO_VALUES,
        beautyAutoVector.data(), beautyAutoVector.size());

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

    // Take a photo using the blurring effect TakePhotoWithTags()
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t value = entry.data.u8[0];
    meta->addEntry(OHOS_CONTROL_BEAUTY_AUTO_VALUE, &value, 1);
    TakePhotoWithTags(meta);

    // Abnormal input parameter validation: The standard behavior is not determined
    uint8_t inValidValue = 100;
    invalidParmTestU8(OHOS_CONTROL_BEAUTY_AUTO_VALUE, inValidValue);
}

/**
 * @tc.name: OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE
 * @tc.desc: OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES, OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_006, TestSize.Level1)
{
    // stub codes
    std::vector<uint8_t> beautyTypesVector;
    beautyTypesVector.push_back(OHOS_CAMERA_BEAUTY_TYPE_FACE_SLENDER);
    cameraTest->ability->addEntry(OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        beautyTypesVector.data(), beautyTypesVector.size());
    std::vector<uint8_t> beautyFaceSlenderVector;
    uint8_t beautyFaceSlenderValue = 0;
    beautyFaceSlenderVector.push_back(beautyFaceSlenderValue);
    cameraTest->ability->addEntry(OHOS_ABILITY_BEAUTY_FACE_SLENDER_VALUES,
        beautyFaceSlenderVector.data(), beautyFaceSlenderVector.size());

    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    bool beautyFaceSlenderFlag = isTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_SCENE_BEAUTY_TYPES,
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

    // Take a photo using the blurring effect TakePhotoWithTags()
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t value = entry.data.u8[0];
    meta->addEntry(OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, &value, 1);
    TakePhotoWithTags(meta);

    // Abnormal input parameter validation: The standard behavior is not determined
    uint8_t inValidValue = 100;
    invalidParmTestU8(OHOS_CONTROL_BEAUTY_FACE_SLENDER_VALUE, inValidValue);
}

/**
 * @tc.name: OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES, OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE
 * @tc.desc: OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES, OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_007, TestSize.Level1)
{
    // stub codes
    std::vector<uint8_t> beautyTypesVector;
    beautyTypesVector.push_back(OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE);
    cameraTest->ability->addEntry(OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        beautyTypesVector.data(), beautyTypesVector.size());
    std::vector<int32_t> beautySkinToneVector;
    int32_t skinToneValue = 0xBF986C;
    beautySkinToneVector.push_back(skinToneValue);
    cameraTest->ability->addEntry(OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES,
        beautySkinToneVector.data(), beautySkinToneVector.size());

    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    bool beautyFaceSlenderFlag = isTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE);
    if (!beautyFaceSlenderFlag) {
        CAMERA_LOGE("OHOS_CAMERA_BEAUTY_TYPE_SKIN_TONE not found");
        return;
    }

    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_SKIN_TONE_VALUES not found");
        return;
    }

    // Take a photo using the blurring effect TakePhotoWithTags()
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    int32_t value = entry.data.i32[0];
    meta->addEntry(OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, &value, 1);
    TakePhotoWithTags(meta);

    // Abnormal input parameter validation: The standard behavior is not determined
    int32_t inValidValue = 0xFFFFFF;
    invalidParmTestU8(OHOS_CONTROL_BEAUTY_SKIN_TONE_VALUE, inValidValue);
}

/**
 * @tc.name: OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES, OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE
 * @tc.desc: OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES, OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_008, TestSize.Level1)
{
    // stub codes
    std::vector<uint8_t> beautyTypesVector;
    beautyTypesVector.push_back(OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH);
    cameraTest->ability->addEntry(OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        beautyTypesVector.data(), beautyTypesVector.size());
    std::vector<uint8_t> beautySkinSmoothVector;
    beautySkinSmoothVector.push_back(0);
    cameraTest->ability->addEntry(OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES,
        beautySkinSmoothVector.data(), beautySkinSmoothVector.size());

    // real test
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    bool beautyFaceSlenderFlag = isTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH);
    if (!beautyFaceSlenderFlag) {
        CAMERA_LOGE("OHOS_CAMERA_BEAUTY_TYPE_SKIN_SMOOTH, not found");
        return;
    }

    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES, &entry);
    if (ret != 0) {
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_SKIN_SMOOTH_VALUES not found");
        return;
    }

    // Take a photo using the blurring effect TakePhotoWithTags()
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    uint8_t value = entry.data.u8[0];
    meta->addEntry(OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, &value, 1);
    TakePhotoWithTags(meta);

    // Abnormal input parameter validation: The standard behavior is not determined
    uint8_t inVavalueTest = 100;
    invalidParmTestU8(OHOS_CONTROL_BEAUTY_SKIN_SMOOTH_VALUE, inVavalueTest);
}

/**
 * @tc.name: OHOS_ABILITY_CUSTOM_VIDEO_FPS
 * @tc.desc: OHOS_ABILITY_CUSTOM_VIDEO_FPS
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagUtTestV1_1, Camera_Tag_Hdi_V1_1_009, TestSize.Level1)
{
    //stub codes
    std::vector<uint8_t> cameraModesVector;
    cameraModesVector.push_back(OHOS::HDI::Camera::V1_1::PORTRAIT);
    cameraTest->ability->addEntry(OHOS_ABILITY_CAMERA_MODES, cameraModesVector.data(),
        cameraModesVector.size());

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
    EXPECT_NE(0, entry.count);
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(100, 200);
    int32_t tagValue[2] = {entry.data.i32[0], entry.data.i32[0]};
    meta->addEntry(OHOS_CONTROL_FPS_RANGES, &tagValue, 2);
    TakePhotoWithTags(meta);

    std::shared_ptr<CameraSetting> metaInvalid = std::make_shared<CameraSetting>(100, 200);
    int32_t valueInvalid[2] = {1000, 1000};
    metaInvalid->addEntry(OHOS_CONTROL_FPS_RANGES, &valueInvalid, 2);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(metaInvalid, metaVec);
    cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
}

void CameraTagUtTestV1_1::TakePhotoWithTags(std::shared_ptr<OHOS::Camera::CameraSetting> meta)
{
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    //int rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
    
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
