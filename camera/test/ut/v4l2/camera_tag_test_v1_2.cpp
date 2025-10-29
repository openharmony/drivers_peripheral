/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "camera_tag_test_v1_2.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
constexpr uint32_t ITEM_CAPACITY = 100;
constexpr uint32_t DATA_CAPACITY = 2000;
void CameraTagTestV1_2::SetUpTestCase(void) {}
void CameraTagTestV1_2::TearDownTestCase(void) {}
void CameraTagTestV1_2::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_0); // assert inside
}

void CameraTagTestV1_2::TearDown(void)
{
    cameraTest->Close();
}

void invalidParmTestU8(int tag, uint8_t value)
{
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    uint8_t valueTest = value;
    meta->addEntry(tag, &valueTest, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    int rc = HDI::Camera::V1_0::NO_ERROR;
    EXPECT_EQ(rc, HDI::Camera::V1_0::NO_ERROR);
}

void invalidParmTestI32(int tag, int32_t value)
{
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    int32_t valueTest = value;
    meta->addEntry(tag, &valueTest, 1);
    std::vector<uint8_t> metaVec;
    MetadataUtils::ConvertMetadataToVec(meta, metaVec);
    int rc = HDI::Camera::V1_0::NO_ERROR;
    EXPECT_EQ(rc, HDI::Camera::V1_0::NO_ERROR);
}

/**
 * @tc.name: SUB_Driver_Camera_Modes_0020
 * @tc.desc: OHOS_ABILITY_CAMERA_MODES
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_Modes_0020, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MODES, &entry);
    if (ret !=0) {
        GTEST_SKIP() << "OHOS_ABILITY_CAMERA_MODES NOT FOUND" << std::endl;
    }
    CAMERA_LOGI("get OHOS_ABILITY_CAMERA_MODES success");
    if (entry.data_type != META_TYPE_BYTE) {
        GTEST_SKIP() << "META_TYPE_BYTE NOT FOUND" << std::  endl;
    }
    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == HDI::Camera::V1_0::OperationMode::NORMAL) {
            CAMERA_LOGI("OperationMode::NORMAL found!");
        } else if (entry.data.u8[i] == OHOS::HDI::Camera::V1_1::PORTRAIT) {
            CAMERA_LOGI("OperationMode::PORTRAIT found!");
        }
    }
}

/**
 * @tc.name: SUB_Driver_Camera_Modes_0030
 * @tc.desc: OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, OHOS_CONTROL_PORTRAIT_EFFECT_TYPE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_Modes_0030, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES, &entry);
    if (ret != 0) {
        bool portraitFlag = cameraTest->IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_CAMERA_MODES,
            OHOS::HDI::Camera::V1_1::PORTRAIT);
        if (!portraitFlag) {
            GTEST_SKIP() << "PORTRAIT NOT FOUND" << std::endl;
        }
        return;
    }
    printf("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES value count is %d\n", entry.count);
    if (entry.count == 0) {
        CAMERA_LOGI("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES value count is 0");
        return;
    } else {
        for (size_t i = 0; i < entry.count; i++)
        {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            printf("OHOS_ABILITY_SCENE_PORTRAIT_EFFECT_TYPES : %d\n", entry.data.u8[i]);
            uint8_t value = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_PORTRAIT_EFFECT_TYPE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_PORTRAIT_EFFECT_TYPE success!");
            cameraTest->TakePhotoWithTags(meta);
        }
    }
}

/**
 * @tc.name: SUB_Driver_Camera_Modes_0060
 * @tc.desc: OHOS_ABILITY_BEAUTY_AUTO_VALUES, OHOS_CONTROL_BEAUTY_AUTO_VALUE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_Modes_0060, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    camera_metadata_item_t entry;
    bool beautyAutoFlag = cameraTest->IsTagValueExistsU8(cameraTest->ability, OHOS_ABILITY_SCENE_BEAUTY_TYPES,
        OHOS_CAMERA_BEAUTY_TYPE_AUTO);
    if (!beautyAutoFlag) {
        CAMERA_LOGE("OHOS_CAMERA_BEAUTY_TYPE_AUTO not found");
        return;
    }

    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_BEAUTY_AUTO_VALUES, &entry);
    if (ret != 0) {
        GTEST_SKIP() << "OHOS_ABILITY_BEAUTY_AUTO_VALUES not found"<< std::endl;
        return;
    }
    printf("OHOS_ABILITY_BEAUTY_AUTO_VALUES value count is %d\n", entry.count);
    if (entry.count == 0) {
        CAMERA_LOGI("OHOS_ABILITY_BEAUTY_AUTO_VALUES value count is 0");
        return;
    } else {
        for (size_t i = 0; i < entry.count; i++) {
            std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
            printf("OHOS_ABILITY_BEAUTY_AUTO_VALUES : %d\n", entry.data.u8[i]);
            uint8_t value = entry.data.u8[i];
            meta->addEntry(OHOS_CONTROL_BEAUTY_AUTO_VALUE, &value, 1);
            std::vector<uint8_t> metaVec;
            MetadataUtils::ConvertMetadataToVec(meta, metaVec);
            cameraTest->rc = cameraTest->cameraDevice->UpdateSettings(metaVec);
            EXPECT_EQ(cameraTest->rc, HDI::Camera::V1_0::NO_ERROR);
            CAMERA_LOGI("addEntry for OHOS_CONTROL_BEAUTY_AUTO_VALUE success!");
            cameraTest->TakePhotoWithTags(meta);
        }
    }
}

/**
 * @tc.name: SUB_Driver_Camera_DefferredImage_0100
 * @tc.desc: OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_DefferredImage_0100, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        std::stringstream ss;
        for (size_t i = 1; i <= entry.count; i++) {
            ss << static_cast<int>(entry.data.u8[i-1]) << " ";
            if (i == entry.count || i % 2 == 0) {
                printf("OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY %s\n", ss.str().c_str());
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY> f value end.");
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_DEFERRED_IMAGE_DELIVERY NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name: SUB_Driver_Camera_XMAGE_0100
 * @tc.desc: OHOS_ABILITY_AVAILABLE_COLOR_SPACES
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_XMAGE_0100, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if (i == entry.count -1) {
                printf("OHOS_ABILITY_AVAILABLE_COLOR_SPACES %s\n", ss.str().c_str());
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_AVAILABLE_COLOR_SPACES> f value end.");
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_AVAILABLE_COLOR_SPACES NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name: SUB_Driver_Camera_NightMode_0100
 * @tc.desc: OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_NightMode_0100, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if (i == entry.count -1) {
                printf("OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME %s\n", ss.str().c_str());
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME> f value end.");
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_NIGHT_MODE_SUPPORTED_EXPOSURE_TIME NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name: SUB_Driver_Camera_APERTURE_0100
 * @tc.desc: OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_APERTURE_0100, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE, &entry);
    
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        printf("OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE f value count %d\n", entry.count);
        constexpr size_t step = 4; //print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count -1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE%s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name: SUB_Driver_Camera_APERTURE_0200
 * @tc.desc: OHOS_ABILITY_CAMERA_VIRTUAL_APERTURE_RANGE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_APERTURE_0200, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE, &entry);\
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        printf("OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE f value count %d\n", entry.count);
        constexpr size_t step = 4; //print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE%s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_CAMERA_PHYSICAL_APERTURE_RANGE NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name: SUB_Driver_Camera_SmoothZoom_0100
 * @tc.desc: OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_SmoothZoom_0100, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE, &entry);
    if (cameraTest->rc == HDI::Camera::V1_0::NO_ERROR && entry.data.ui32 != nullptr && entry.count > 0) {
        printf("OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE f value count %d\n", entry.count);
        constexpr size_t step = 4; //print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.ui32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE%s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_CAMERA_ZOOM_PERFORMANCE NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name: SUB_Driver_Camera_Colorspace_0100
 * @tc.desc: OHOS_ABILITY_AVAILABLE_COLOR_SPACES
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_Colorspace_0100, TestSize.Level1)
{
    CAMERA_LOGI("CameraHdiTestV1_2 Camera_Device_Hdi_V1_2_032 start ...");
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_AVAILABLE_COLOR_SPACES, &entry);
    printf("OHOS_ABILITY_AVAILABLE_COLOR_SPACES value count %d\n", entry.count);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if (i == entry.count - 1) {
                printf("OHOS_ABILITY_AVAILABLE_COLOR_SPACES: %s\n", ss.str().c_str());
                ss.clear();
            }
        }
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_AVAILABLE_COLOR_SPACES NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name:SUB_Driver_Camera_Stabilization_0100
 * @tc.desc:OHOS_ABILITY_VIDEO_STABILIZATION_MODES
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_Stabilization_0100, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_VIDEO_STABILIZATION_MODES, &entry);
    printf("OHOS_ABILITY_VIDEO_STABILIZATION_MODES value count %d\n", entry.count);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << static_cast<int>(entry.data.u8[i]) << " ";
            if (i == entry.count - 1) {
                printf("OHOS_ABILITY_VIDEO_STABILIZATION_MODES: %s\n", ss.str().c_str());
                ss.clear();
            }
        }
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_VIDEO_STABILIZATION_MODES NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name:SUB_Driver_Camera_Macro_0100
 * @tc.desc:Whether macro ability support
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_Macro_0100, TestSize.Level1)
{
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_CAMERA_MACRO_SUPPORTED, &entry);
    printf("OHOS_ABILITY_CAMERA_MACRO_SUPPORTED value count %d\n", entry.count);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << static_cast<int>(entry.data.u8[i]) << " ";
            if (i == entry.count - 1) {
                printf("OHOS_ABILITY_CAMERA_MACRO_SUPPORTED: %s\n", ss.str().c_str());
                ss.clear();
            }
        }
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_CAMERA_MACRO_SUPPORTED NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name: SUB_Driver_Camera_Sketch_0100
 * @tc.desc: OHOS_ABILITY_SKETCH_ENABLE_RATIO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_Sketch_0100, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SKETCH_ENABLE_RATIO, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_ENABLE_RATIO> f value start.");
        printf("OHOS_ABILITY_SKETCH_ENABLE_RATIO f value count %d\n", entry.count);
        constexpr size_t step = 4; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_SKETCH_ENABLE_RATIO %s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_ENABLE_RATIO> f value end.");
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_SKETCH_ENABLE_RATIO NOT FOUND" << std::endl;
    }
}

/**
 * @tc.name: SUB_Driver_Camera_Sketch_0200
 * @tc.desc: OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraTagTestV1_2, SUB_Driver_Camera_Sketch_0200, TestSize.Level1)
{
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.f != nullptr && entry.count > 0) {
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO> f value start.");
        printf("OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO f value count %d\n", entry.count);
        constexpr size_t step = 4; // print step
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.f[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                printf("OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO %s\n", ss.str().c_str());
                CAMERA_LOGI("%{public}s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
        CAMERA_LOGI("print tag<OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO> f value end.");
    } else {
        GTEST_SKIP() << "OHOS_ABILITY_SKETCH_REFERENCE_FOV_RATIO NOT FOUND" << std::endl;
    }
}