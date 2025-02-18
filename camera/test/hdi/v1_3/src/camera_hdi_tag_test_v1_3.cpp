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
#include "camera_hdi_tag_test_v1_3.h"
#include <functional>

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;
constexpr uint32_t DATA_COUNT = 1;
constexpr uint32_t ITEM_CAPACITY = 100;
constexpr uint32_t DATA_CAPACITY = 2000;

void CameraHdiTagTestV1_3::SetUpTestCase(void) {}
void CameraHdiTagTestV1_3::TearDownTestCase(void) {}
void CameraHdiTagTestV1_3::SetUp(void)
{
    cameraTest = std::make_shared<OHOS::Camera::Test>();
    cameraTest->Init(); // assert inside
    cameraTest->Open(DEVICE_0); // assert inside
}

void CameraHdiTagTestV1_3::TearDown(void)
{
    cameraTest->Close();
}

bool CameraHdiTagTestV1_3::IsTagValueExistsU8(
    std::shared_ptr<OHOS::Camera::CameraMetadata> ability, uint32_t tag, uint8_t value)
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
    }
    return false;
}

void CameraHdiTagTestV1_3::PrintAllTagDataU8(std::shared_ptr<OHOS::Camera::CameraMetadata> ability, uint32_t tag)
{
    common_metadata_header_t* data = ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, tag, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.u8 != nullptr && entry.count > 0) {
        cout << "----tag = " << tag << "count = " << entry.count << endl;
        for (int i = 0; i < entry.count; i++) {
            int v = entry.data.u8[i];
            cout << "tag[" << tag << "][" << i << "] = " << v << endl;
        }
        cout << "--------------------------------" << endl;
    }
}

/**
 * @tc.name: Camera_Hdi_TAG_TEST_V1_3_001
 * @tc.desc: report camera support detect type OHOS_ABILITY_STATISTICS_DETECT_TYPE
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiTagTestV1_3, Camera_Hdi_TAG_TEST_V1_3_001, TestSize.Level1)
{
    CAMERA_LOGI("CameraHdiTagTestV1_3 Camera_Hdi_TAG_TEST_V1_3_001 start ...");
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    PrintAllTagDataU8(cameraTest->ability, OHOS_ABILITY_STATISTICS_DETECT_TYPE);
}

/**
 * @tc.name: Camera_Hdi_TAG_TEST_V1_3_002
 * @tc.desc: report camera support tripod detect OHOS_ABILITY_TRIPOD_DETECTION
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraHdiTagTestV1_3, Camera_Hdi_TAG_TEST_V1_3_002, TestSize.Level1)
{
    CAMERA_LOGI("CameraHdiTagTestV1_3 Camera_Hdi_TAG_TEST_V1_3_002 start ...");
    EXPECT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    EXPECT_NE(data, nullptr);
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_ABILITY_TRIPOD_DETECTION, &entry);
    if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
        constexpr size_t step = 10;
        std::stringstream ss;
        for (size_t i = 0; i < entry.count; i++) {
            ss << entry.data.i32[i] << " ";
            if ((i != 0) && (i % step == 0 || i == entry.count - 1)) {
                CAMERA_LOGI("OHOS_ABILITY_TRIPOD_DETECTION %{public}s\n", ss.str().c_str());
                printf("OHOS_ABILITY_TRIPOD_DETECTION %s\n", ss.str().c_str());
                ss.clear();
                ss.str("");
            }
        }
    } else {
        CAMERA_LOGI("Camera_Hdi_TAG_TEST_V1_3_002 not support OHOS_ABILITY_TRIPOD_DETECTION");
        printf("Camera_Hdi_TAG_TEST_V1_3_002 not support OHOS_ABILITY_TRIPOD_DETECTION\n");
    }
}

/**
 * @tc.name:Camera_Hdi_TAG_TEST_V1_3_003
 * @tc.desc: report camera support focus range type OHOS_CONTROL_FOCUS_RANGE_TYPE
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiTagTestV1_3, Camera_Hdi_TAG_TEST_V1_3_003, TestSize.Level1)
{
    cameraTest->Close();
    cameraTest->Open(DEVICE_1);
    ASSERT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    ASSERT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_FOCUS_RANGE_TYPES, &entry);
    if (cameraTest->rc != CAM_META_SUCCESS || entry.count == 0) {
        cout << "skip this test, because OHOS_ABILITY_FOCUS_RANGE_TYPES not supported now" << endl;
        return;
    }

    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_RANGE_NEAR) {
            CAMERA_LOGI("focus range type OHOS_CAMERA_FOCUS_RANGE_NEAR is supported");
        } else if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_RANGE_AUTO) {
            CAMERA_LOGI("focus range type OHOS_CAMERA_FOCUS_RANGE_AUTO is supported");
        } else {
            CAMERA_LOGI("supported focus range type is null");
            return;
        }
    }

    camera_metadata_item_t item;
    bool status = false;
    uint8_t metaFocusRangeType = static_cast<uint8_t>(OHOS_CAMERA_FOCUS_RANGE_NEAR);
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_RANGE_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = cameraTest->ability->addEntry(OHOS_CONTROL_FOCUS_RANGE_TYPE, &metaFocusRangeType, DATA_COUNT);
    } else if (ret == CAM_META_SUCCESS) {
        status = cameraTest->ability->updateEntry(OHOS_CONTROL_FOCUS_RANGE_TYPE, &metaFocusRangeType, DATA_COUNT);
    }

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_0::CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_RANGE_TYPE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_TRUE(item.data.u8[0] == OHOS_CAMERA_FOCUS_RANGE_NEAR);

    metaFocusRangeType = static_cast<uint8_t>(OHOS_CAMERA_FOCUS_RANGE_AUTO);
    ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_RANGE_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = cameraTest->ability->addEntry(OHOS_CONTROL_FOCUS_RANGE_TYPE, &metaFocusRangeType, DATA_COUNT);
    } else if (ret == CAM_META_SUCCESS) {
        status = cameraTest->ability->updateEntry(OHOS_CONTROL_FOCUS_RANGE_TYPE, &metaFocusRangeType, DATA_COUNT);
    }

    // Update settings
    meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_0::CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_RANGE_TYPE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_TRUE(item.data.u8[0] == OHOS_CAMERA_FOCUS_RANGE_AUTO);
}

/**
 * @tc.name:Camera_Hdi_TAG_TEST_V1_3_004
 * @tc.desc: report camera support focus driven type OHOS_CONTROL_FOCUS_DRIVEN_TYPE
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiTagTestV1_3, Camera_Hdi_TAG_TEST_V1_3_004, TestSize.Level1)
{
    ASSERT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    ASSERT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_FOCUS_DRIVEN_TYPES, &entry);
    if (cameraTest->rc != CAM_META_SUCCESS || entry.count == 0) {
        cout << "skip this test, because OHOS_ABILITY_FOCUS_DRIVEN_TYPES not supported now" << endl;
        return;
    }

    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_DRIVEN_AUTO) {
            CAMERA_LOGI("focus driven type OHOS_CAMERA_FOCUS_DRIVEN_AUTO is supported");
        } else if (entry.data.u8[i] == OHOS_CAMERA_FOCUS_DRIVEN_FACE) {
            CAMERA_LOGI("focus driven type OHOS_CAMERA_FOCUS_DRIVEN_FACE is supported");
        } else {
            CAMERA_LOGI("supported focus driven type is null");
            return;
        }
    }

    camera_metadata_item_t item;
    bool status = false;
    uint8_t metaFocusRangeType = static_cast<uint8_t>(OHOS_CAMERA_FOCUS_DRIVEN_FACE);
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = cameraTest->ability->addEntry(OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &metaFocusRangeType, DATA_COUNT);
    } else if (ret == CAM_META_SUCCESS) {
        status = cameraTest->ability->updateEntry(OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &metaFocusRangeType, DATA_COUNT);
    }

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_0::CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_TRUE(item.data.u8[0] == OHOS_CAMERA_FOCUS_DRIVEN_FACE);

    metaFocusRangeType = static_cast<uint8_t>(OHOS_CAMERA_FOCUS_DRIVEN_AUTO);
    ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = cameraTest->ability->addEntry(OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &metaFocusRangeType, DATA_COUNT);
    } else if (ret == CAM_META_SUCCESS) {
        status = cameraTest->ability->updateEntry(OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &metaFocusRangeType, DATA_COUNT);
    }

    // Update settings
    meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_0::CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_DRIVEN_TYPE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_TRUE(item.data.u8[0] == OHOS_CAMERA_FOCUS_DRIVEN_AUTO);
}

/**
 * @tc.name:Camera_Hdi_TAG_TEST_V1_3_005
 * @tc.desc: report camera support color reservation type OHOS_CONTROL_COLOR_RESERVATION_TYPE
 * @tc.size:MediumTest
 * @tc.type:Function
*/
HWTEST_F(CameraHdiTagTestV1_3, Camera_Hdi_TAG_TEST_V1_3_005, TestSize.Level1)
{
    ASSERT_NE(cameraTest->ability, nullptr);
    common_metadata_header_t* data = cameraTest->ability->get();
    ASSERT_NE(data, nullptr);
    camera_metadata_item_t entry;
    cameraTest->rc = FindCameraMetadataItem(data, OHOS_ABILITY_COLOR_RESERVATION_TYPES, &entry);
    if (cameraTest->rc != CAM_META_SUCCESS || entry.count == 0) {
        cout << "skip this test, because OHOS_ABILITY_COLOR_RESERVATION_TYPES not supported now" << endl;
        return;
    }

    for (int i = 0; i < entry.count; i++) {
        if (entry.data.u8[i] == OHOS_CAMERA_COLOR_RESERVATION_NONE) {
            CAMERA_LOGI("color reservation type OHOS_CAMERA_COLOR_RESERVATION_NONE is supported");
        } else if (entry.data.u8[i] == OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT) {
            CAMERA_LOGI("color reservation type OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT is supported");
        } else {
            CAMERA_LOGI("supported color reservation type is null");
            return;
        }
    }

    camera_metadata_item_t item;
    bool status = false;
    uint8_t metaFocusRangeType = static_cast<uint8_t>(OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT);
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_COLOR_RESERVATION_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = cameraTest->ability->addEntry(OHOS_CONTROL_COLOR_RESERVATION_TYPE, &metaFocusRangeType, DATA_COUNT);
    } else if (ret == CAM_META_SUCCESS) {
        status = cameraTest->ability->updateEntry(OHOS_CONTROL_COLOR_RESERVATION_TYPE, &metaFocusRangeType, DATA_COUNT);
    }

    // Update settings
    std::shared_ptr<CameraSetting> meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    std::vector<uint8_t> setting;
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_0::CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    ret = FindCameraMetadataItem(data, OHOS_CONTROL_COLOR_RESERVATION_TYPE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_TRUE(item.data.u8[0] == OHOS_CAMERA_COLOR_RESERVATION_PORTRAIT);

    metaFocusRangeType = static_cast<uint8_t>(OHOS_CAMERA_COLOR_RESERVATION_NONE);
    ret = FindCameraMetadataItem(data, OHOS_CONTROL_COLOR_RESERVATION_TYPE, &item);
    if (ret == CAM_META_ITEM_NOT_FOUND) {
        status = cameraTest->ability->addEntry(OHOS_CONTROL_COLOR_RESERVATION_TYPE, &metaFocusRangeType, DATA_COUNT);
    } else if (ret == CAM_META_SUCCESS) {
        status = cameraTest->ability->updateEntry(OHOS_CONTROL_COLOR_RESERVATION_TYPE, &metaFocusRangeType, DATA_COUNT);
    }

    // Update settings
    meta = std::make_shared<CameraSetting>(ITEM_CAPACITY, DATA_CAPACITY);
    MetadataUtils::ConvertMetadataToVec(meta, setting);
    cameraTest->rc = (OHOS::HDI::Camera::V1_0::CamRetCode)cameraTest->cameraDeviceV1_3->UpdateSettings(setting);
    EXPECT_EQ(HDI::Camera::V1_0::NO_ERROR, cameraTest->rc);

    ret = FindCameraMetadataItem(data, OHOS_CONTROL_COLOR_RESERVATION_TYPE, &item);
    EXPECT_EQ(ret, CAM_META_SUCCESS);
    EXPECT_TRUE(item.data.u8[0] == OHOS_CAMERA_COLOR_RESERVATION_NONE);
}