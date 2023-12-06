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
