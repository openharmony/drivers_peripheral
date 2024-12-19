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
#include "camera_example_vendor_tags_uttest.h"
#include <vector>
#include "drivers/peripheral/camera/vdi_base/common/metadata_manager/src/camera_example_vendor_tags.cpp"

using namespace OHOS;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Camera;

void CameraExampleVendorTagsTest::SetUpTestCase(void) {}
void CameraExampleVendorTagsTest::TearDownTestCase(void) {}
void CameraExampleVendorTagsTest::SetUp(void)
{
    printf("CameraExampleVendorTagsTest start\n");
}

void CameraExampleVendorTagsTest::TearDown(void)
{
    printf("CameraExampleVendorTagsTest end\n");
}

/**
 * @tc.name: Camera_Example_Vendor_Tags_001
 * @tc.desc: GetAllVendorTags
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraExampleVendorTagsTest, Camera_Example_Vendor_Tags_001, TestSize.Level1)
{
    printf("CameraExampleVendorTagsTest Camera_Example_Vendor_Tags_001 start...\n");
    auto cameraVendorTagExample = std::make_shared<OHOS::Camera::CameraVendorTagExample>();
    std::vector<vendorTag_t> tagVec {};
    cameraVendorTagExample->GetAllVendorTags(tagVec);
    int ret = (int)cameraVendorTagExample->GetVendorTagCount();
    EXPECT_EQ(true, ret != -1);
}