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
#include "camera_metadata_operator_uttest.h"
#include "camera_metadata_info.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraMetadataOperatorTest::SetUpTestCase(void) {}
void CameraMetadataOperatorTest::TearDownTestCase(void) {}
void CameraMetadataOperatorTest::SetUp(void)
{
    printf("CameraMetadataOperatorTest start\r\n");
}

void CameraMetadataOperatorTest::TearDown(void)
{
    printf("CameraMetadataOperatorTest end\r\n");
}

/**
 * @tc.name: Camera_metedate_opertor_001
 * @tc.desc: metadataHeader is nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_001, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_001 start...\n");
    uint8_t *ret = GetMetadataData(nullptr);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: Camera_metedate_opertor_002
 * @tc.desc: buffer is nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_002, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_002 start...\n");
    common_metadata_header_t *ret = FillCameraMetadata(nullptr, 0, 0, 0);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: Camera_metedate_opertor_003
 * @tc.desc: itemSection = -1
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_003, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_003 start...\n");
    int32_t ret = GetMetadataSection(1000000000, 0);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Camera_metedate_opertor_004
 * @tc.desc: itemSection = 16384
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_004, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_004 start...\n");
    uint32_t section = 10;
    int32_t ret = GetMetadataSection(16384, &section);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: Camera_metedate_opertor_005
 * @tc.desc: itemSection = 20480
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_005, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_005 start...\n");
    uint32_t section = 10;
    int32_t ret = GetMetadataSection(20480, &section);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: Camera_metedate_opertor_006
 * @tc.desc: itemSection = OHOS_XMAGE_COLOR_ABILITY
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_006, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_006 start...\n");
    uint32_t section = 10;
    int32_t ret = GetMetadataSection(1, &section);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: Camera_metedate_opertor_007
 * @tc.desc: dataType = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_007, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_007 start...\n");
    int32_t ret = GetCameraMetadataItemType(0, nullptr);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_008
 * @tc.desc: item = 131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_008, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_008 start...\n");
    uint32_t data = 0;
    int32_t ret = GetCameraMetadataItemType(131071, &data);
    printf("Camera_metedate_opertor_008 ret %d\n", ret);
    ASSERT_EQ(ret, -1);
}

/**
 * @tc.name: Camera_metedate_opertor_009
 * @tc.desc: item = -131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_009, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_009 start...\n");
    const char *ret = GetCameraMetadataItemName(131071);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: Camera_metedate_opertor_010
 * @tc.desc: type = -131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_010, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_010 start...\n");
    int32_t ret = CalculateCameraMetadataItemDataSize(8, 0);
    int32_t exp = -1;
    EXPECT_EQ(ret, exp);
}

/**
 * @tc.name: Camera_metedate_opertor_011
 * @tc.desc: type = -131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_011, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_011 start...\n");
    int ret = AddCameraMetadataItem(nullptr, 131071, nullptr, 0);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_012
 * @tc.desc: type = -131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_012, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_012 start...\n");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->data_count = 1;
    int ret = AddCameraMetadataItem(dst, 131071, nullptr, 0);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_013
 * @tc.desc: src = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_013, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_013 start...\n");
    int ret = GetCameraMetadataItem(nullptr, 0, nullptr);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_014
 * @tc.desc: src = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_014, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_014 start...\n");
    int ret = FindCameraMetadataItemIndex(nullptr, 0, 0);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_015
 * @tc.desc: item  = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_015, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_015 start...\n");
    int ret = MetadataExpandItemMem(nullptr, nullptr, 0);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_016
 * @tc.desc: dst  = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_016, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_016 start...\n");
    int ret = UpdateCameraMetadataItemByIndex(nullptr, 0, nullptr, 0, nullptr);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_017
 * @tc.desc: item  = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_017, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_017 start...\n");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->item_count = 1;
    int ret = UpdateCameraMetadataItemByIndex(dst, 0, nullptr, 0, nullptr);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_018
 * @tc.desc: item  = -131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_018, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_018 start...\n");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->item_count = 1;
    int ret = UpdateCameraMetadataItem(dst, -131071, nullptr, 0, nullptr);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_019
 * @tc.desc: dst  = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_019, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_019 start...\n");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->item_count = 1;
    int ret = DeleteCameraMetadataItemByIndex(nullptr, 0);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_020
 * @tc.desc: dst  = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_020, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_020 start...\n");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->item_count = 1;
    int ret = DeleteCameraMetadataItemByIndex(dst, 2);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_021
 * @tc.desc: dst  = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_021, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_021 start...\n");
    int ret = DeleteCameraMetadataItem(nullptr, -131071);
    printf("Camera_metedate_opertor_021 ret %d\n", ret);
    ASSERT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_022
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_022, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_022 start...\n");
    uint32_t ret = GetCameraMetadataItemCount(nullptr);
    printf("Camera_metedate_opertor_022 ret %d\n", ret);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: Camera_metedate_opertor_023
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_023, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_023 start...\n");
    uint32_t ret = GetCameraMetadataItemCapacity(nullptr);
    printf("Camera_metedate_opertor_022 ret %d\n", ret);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: Camera_metedate_opertor_024
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_024, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_024 start...\n");
    uint32_t ret = GetCameraMetadataDataSize(nullptr);
    printf("Camera_metedate_opertor_022 ret %d\n", ret);
    ASSERT_EQ(ret, 0);
}

/**
 * @tc.name: Camera_metedate_opertor_025
 * @tc.desc: newMetadata == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_025, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_025 start...\n");
    int32_t ret = CopyCameraMetadataItems(nullptr, nullptr);
    printf("Camera_metedate_opertor_022 ret %d\n", ret);
    ASSERT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_metedate_opertor_026
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_026, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_026 start...\n");
    std::string ret = FormatCameraMetadataToString(nullptr);
    ASSERT_EQ(true, ret.empty());
}

/**
 * @tc.name: Camera_metedate_opertor_026
 * @tc.desc: FormatCameraMetadataToString
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_FormatCameraMetadataToString, TestSize.Level1)
{
    int ret = 0;
    auto metaData = make_shared<CameraMetadata>(1000, 2000);
    int8_t cameraType[10] = {0};
    int32_t cameraFpsRange[10] = {0};
    uint32_t cameraMesureExposureTime[10] = {0};
    int64_t sensorExposeTime[10] = {0};
    float sensorInfoPhysicalSize[] = {0};
    float jpegGpsCoordinates[10] = {0};

    camera_rational_t controlAeCompenstationStep[10] = {{0}};
    ret = metaData->addEntry(OHOS_ABILITY_CAMERA_TYPE, cameraType, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_ABILITY_FPS_RANGES, cameraFpsRange, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, cameraMesureExposureTime, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_SENSOR_EXPOSURE_TIME, sensorExposeTime, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_SENSOR_INFO_PHYSICAL_SIZE, sensorInfoPhysicalSize, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_JPEG_GPS_COORDINATES, jpegGpsCoordinates, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, controlAeCompenstationStep, 10);
    EXPECT_EQ(ret, true);
    string metaStr = FormatCameraMetadataToString(metaData->get());
    cout << metaStr << endl;
    EXPECT_NE(metaStr, "");
}

/**
 * @tc.name: Camera_metedate_opertor_026
 * @tc.desc: DeleteCameraMetadataItemByIndex
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_DeleteCameraMetadataItemByIndex, TestSize.Level1)
{
    int ret = 0;
    auto metaData = make_shared<CameraMetadata>(1000, 2000);
    int8_t cameraType[10] = {0};
    int32_t cameraFpsRange[10] = {0};
    uint32_t cameraMesureExposureTime[10] = {0};
    int64_t sensorExposeTime[10] = {0};
    float sensorInfoPhysicalSize[] = {0};
    float jpegGpsCoordinates[10] = {0};

    camera_rational_t controlAeCompenstationStep[10] = {{0}};
    ret = metaData->addEntry(OHOS_ABILITY_CAMERA_TYPE, cameraType, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_ABILITY_FPS_RANGES, cameraFpsRange, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_CONTROL_MANUAL_EXPOSURE_TIME, cameraMesureExposureTime, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_SENSOR_EXPOSURE_TIME, sensorExposeTime, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_SENSOR_INFO_PHYSICAL_SIZE, sensorInfoPhysicalSize, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_JPEG_GPS_COORDINATES, jpegGpsCoordinates, 10);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_CONTROL_AE_COMPENSATION_STEP, controlAeCompenstationStep, 10);
    EXPECT_EQ(ret, true);

    ret = DeleteCameraMetadataItemByIndex(metaData->get(), OHOS_CONTROL_AE_COMPENSATION_STEP);
    EXPECT_GE(ret, 0);
    ret = DeleteCameraMetadataItemByIndex(metaData->get(), OHOS_JPEG_GPS_COORDINATES);
    EXPECT_GE(ret, 0);
    ret = DeleteCameraMetadataItemByIndex(metaData->get(), 0);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: Camera_metedate_opertor_027
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_027, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_027 start...\n");
    std::vector<vendorTag_t>tagVec;
    int32_t ret = GetAllVendorTags(tagVec);
    printf("Camera_metedate_opertor_022 ret %d\n", ret);
    ASSERT_EQ(ret, -1);
}

/**
 * @tc.name: Camera_metedate_opertor_028
 * @tc.desc: item  = 0, metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_028, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_028 start...\n");
    int ret = IsCameraMetadataItemExist(nullptr, 0);
    EXPECT_EQ(ret, false);
}