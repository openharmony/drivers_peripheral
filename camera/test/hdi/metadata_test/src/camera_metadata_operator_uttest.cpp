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

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraMetadataOperatorTest::SetUpTestCase(void) {}
void CameraMetadataOperatorTest::TearDownTestCase(void) {}
void CameraMetadataOperatorTest::SetUp(void)
{
    printf("CameraMetadataOperatorTest start");
}

void CameraMetadataOperatorTest::TearDown(void)
{
    printf("CameraMetadataOperatorTest end");
}

/**
 * @tc.name: Camera_metedate_opertor_001
 * @tc.desc: metadataHeader is nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_001, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_001 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_002 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_003 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_004 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_005 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_006 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_007 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_008 start...");
    uint32_t data = 0;
    GetCameraMetadataItemType(131071, &data);
}

/**
 * @tc.name: Camera_metedate_opertor_009
 * @tc.desc: item = -131071
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_009, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_009 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_010 start...");
    size_t ret = CalculateCameraMetadataItemDataSize(8, 0);
    size_t exp = 0;
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_011 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_012 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_013 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_014 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_015 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_016 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_017 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_018 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_019 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_020 start...");
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
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_021 start...");
    DeleteCameraMetadataItem(nullptr, -131071);
}

/**
 * @tc.name: Camera_metedate_opertor_022
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_022, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_022 start...");
    GetCameraMetadataItemCount(nullptr);
}

/**
 * @tc.name: Camera_metedate_opertor_023
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_023, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_023 start...");
    GetCameraMetadataItemCapacity(nullptr);
}

/**
 * @tc.name: Camera_metedate_opertor_024
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_024, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_024 start...");
    GetCameraMetadataDataSize(nullptr);
}

/**
 * @tc.name: Camera_metedate_opertor_025
 * @tc.desc: newMetadata == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_025, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_025 start...");
    CopyCameraMetadataItems(nullptr, nullptr);
}

/**
 * @tc.name: Camera_metedate_opertor_026
 * @tc.desc: metadataHeader == nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataOperatorTest, Camera_metedate_opertor_026, TestSize.Level1)
{
    printf("CameraMetadataOperatorTest Camera_metedate_opertor_026 start...");
    FormatCameraMetadataToString(nullptr);
}