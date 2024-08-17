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
#include "camera_metadata_info_uttest.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraMetadataInfoTest::SetUpTestCase(void) {}
void CameraMetadataInfoTest::TearDownTestCase(void) {}
void CameraMetadataInfoTest::SetUp(void)
{
    printf("CameraMetadataInfoTest start\r\n");
}

void CameraMetadataInfoTest::TearDown(void)
{
    printf("CameraMetadataInfoTest end\r\n");
}

/**
 * @tc.name: Camera_Metedate_Info_001
 * @tc.desc: normal test
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_001, TestSize.Level1)
{
    int32_t ret;
    auto metaData = make_shared<CameraMetadata>(100, 200);
    int8_t cameraType[] = {10, 30};
    int32_t cameraFpsRange[] = {10, 30};
    int32_t cameraFpsRange2[] = {10, 30, 20, 40};

    ret = metaData->addEntry(OHOS_ABILITY_CAMERA_TYPE, cameraType, 2);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_ABILITY_FPS_RANGES, cameraFpsRange, 2);
    EXPECT_EQ(ret, true);
    ret = metaData->updateEntry(OHOS_ABILITY_FPS_RANGES, cameraFpsRange2,\
        sizeof(cameraFpsRange2) / sizeof(cameraFpsRange2[0]));
    EXPECT_EQ(ret, true);
    ret = metaData->isValid();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: Camera_Metedate_Info_002
 * @tc.desc: resize_add_metadata
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_002, TestSize.Level1)
{
    int32_t ret;
    auto metaData = make_shared<CameraMetadata>(1, 8);
    int8_t cameraType[] = {10, 30};

    ret = metaData->addEntry(OHOS_ABILITY_CAMERA_TYPE, cameraType, 2);
    EXPECT_EQ(ret, true);

    ret = metaData->addEntry(OHOS_ABILITY_CAMERA_TYPE, cameraType, 2);
    EXPECT_EQ(ret, true);

    ret = metaData->addEntry(0, cameraType, 2);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: Camera_Metedate_Info_003
 * @tc.desc: nullptr test
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_003, TestSize.Level1)
{
    CameraMetadata *cameraMetadata = new CameraMetadata(1, 10);
    bool ret = cameraMetadata->addEntry(0, nullptr, 0);
    EXPECT_EQ(ret, false);
    ret = cameraMetadata->addEntry(OHOS_ABILITY_CAMERA_TYPE, nullptr, 1);
    EXPECT_EQ(ret, false);
    int32_t temp[] = {1};
    ret = cameraMetadata->addEntry(OHOS_ABILITY_CAMERA_TYPE, temp, 1);
    EXPECT_EQ(ret, true);
    ret = cameraMetadata->updateEntry(OHOS_ABILITY_CAMERA_TYPE, nullptr, 1);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: Camera_Metedate_Info_004
 * @tc.desc: get method test
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_004, TestSize.Level1)
{
    CameraMetadata *cameraMetadata = new CameraMetadata(10, 40);
    common_metadata_header_t *header1 = cameraMetadata->get();
    const common_metadata_header_t *header2;
    header2 = cameraMetadata->get();
    EXPECT_NE(header1, nullptr);
    EXPECT_NE(header2, nullptr);
}

/**
 * @tc.name: Camera_Metedate_Info_005
 * @tc.desc: dst = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_005, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_005 start...");
    FreeCameraMetadataBuffer(nullptr);
}

/**
 * @tc.name: Camera_Metedate_Info_006
 * @tc.desc: dst = nullptr, item = 131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_006, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_006 start...");
    int ret = DeleteCameraMetadataItem(nullptr, 131071);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_Metedate_Info_007
 * @tc.desc: dataCount = 1, item = 18, data = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_007, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_007 start...");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->item_count = 1;
    int ret = UpdateCameraMetadataItem(dst, 18, nullptr, 1, nullptr);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_Metedate_Info_008
 * @tc.desc: dataCount = 1, item = -131071, data = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_008, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_008 start...");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->item_count = 1;
    int ret = UpdateCameraMetadataItem(dst, -131071, nullptr, 1, nullptr);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_Metedate_Info_009
 * @tc.desc: dataCount = 0, item = -131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_009, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_009 start...");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->item_count = 1;
    int32_t value = 0;
    int ret = UpdateCameraMetadataItem(dst, -131071, &value, 0, nullptr);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_Metedate_Info_010
 * @tc.desc: index = 50, dataCount = 1, data = 0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_010, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_010 start...");
    common_metadata_header_t *dst = new common_metadata_header_t;
    dst->item_count = 1;
    int32_t value = 0;
    int ret = UpdateCameraMetadataItemByIndex(dst, 50, &value, 1, nullptr); // 1009
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: Camera_Metedate_Info_011
 * @tc.desc: index = 50, dataCount = 1, data = 0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_011, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_011 start...");

    auto metaData = make_shared<CameraMetadata>(100, 200);
    float jpegGpsCoordinates[5] = {0};
    int ret = metaData->addEntry(OHOS_JPEG_GPS_COORDINATES, jpegGpsCoordinates, 5);
    EXPECT_NE(ret, false);

    int32_t value = 0;
    ret = UpdateCameraMetadataItemByIndex(metaData->get(), 50, &value, 50, nullptr);
    EXPECT_NE(ret, 0);
    ret = UpdateCameraMetadataItemByIndex(metaData->get(), 0, &value, 5, nullptr);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: Camera_Metedate_Info_012
 * @tc.desc: index = 50, dataCount = 1, data = 0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_012, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_012 start...");

    int32_t ret;
    uint32_t index = 0;
    auto metaData = make_shared<CameraMetadata>(100, 200);
    int8_t cameraType[] = {10, 30};
    int32_t cameraFpsRange[] = {10, 30};
    camera_metadata_item_t *item = new camera_metadata_item_t;

    ret = metaData->addEntry(OHOS_ABILITY_FPS_RANGES, cameraFpsRange, 2);
    EXPECT_EQ(ret, true);
    ret = metaData->addEntry(OHOS_ABILITY_CAMERA_TYPE, cameraType, 2);
    EXPECT_EQ(ret, true);
    common_metadata_header_t *header1 = metaData->get();

    ret = GetCameraMetadataItem(header1, 50, item);
    EXPECT_EQ(ret, 2);
    ret = metaData->FindCameraMetadataItemIndex(header1, 0, &index, true);
    EXPECT_EQ(ret, 3);
}

/**
 * @tc.name: Camera_Metedate_Info_014
 * @tc.desc: index = 50, dataCount = 1, data = 0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_013, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_014 start...");

    int32_t ret;
    int32_t value = 0;
    CameraMetadata *cameraMetadata = new CameraMetadata(10, 40);

    ret = cameraMetadata->updateEntry(OHOS_ABILITY_MOON_CAPTURE_BOOST, &value, 0);
    EXPECT_EQ(ret, false);
}