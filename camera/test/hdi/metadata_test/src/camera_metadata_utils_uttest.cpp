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
#include "camera_metadata_utils_uttest.h"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraMetadataUtilsTest::SetUpTestCase(void) {}
void CameraMetadataUtilsTest::TearDownTestCase(void) {}
void CameraMetadataUtilsTest::SetUp(void)
{
    printf("CameraMetadataUtilsTest start");
}

void CameraMetadataUtilsTest::TearDown(void)
{
    printf("CameraMetadataUtilsTest end");
}

/**
 * @tc.name: Metadata_Utils_003
 * @tc.desc: metadata = nullptr
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraMetadataUtilsTest, Metadata_Utils_003, TestSize.Level1)
{
    printf("CameraMetadataUtilsTest Metadata_Utils_003 start...");
    std::vector<uint8_t> cameraAbility;
    bool ret = MetadataUtils::ConvertMetadataToVec(nullptr, cameraAbility);
    EXPECT_EQ(ret, false);
}