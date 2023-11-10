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
    printf("CameraMetadataInfoTest start");
}

void CameraMetadataInfoTest::TearDown(void)
{
    printf("CameraMetadataInfoTest end");
}

/**
 * @tc.name: Camera_Metedate_Info_001
 * @tc.desc: metadata_ is nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_001, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_001 start...");
    CameraMetadata *cameraMetadata = new CameraMetadata(0, 0);
    bool ret = cameraMetadata->addEntry(0, nullptr, 0);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: Camera_Metedate_Info_003
 * @tc.desc: metadata_ is nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_003, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_003 start...");
    CameraMetadata *cameraMetadata = new CameraMetadata(0, 0);
    bool ret = cameraMetadata->updateEntry(0, nullptr, 0);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: Camera_Metedate_Info_004
 * @tc.desc: get
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_004, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_004 start...");
    CameraMetadata *cameraMetadata = new CameraMetadata(0, 0);
    cameraMetadata->get();
}

/**
 * @tc.name: Camera_Metedate_Info_004
 * @tc.desc: isValid
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataInfoTest, Camera_Metedate_Info_005, TestSize.Level1)
{
    printf("CameraMetadataInfoTest Camera_Metedate_Info_005 start...");
    CameraMetadata *cameraMetadata = new CameraMetadata(0, 0);
    cameraMetadata->isValid();
}