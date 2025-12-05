/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#include <gtest/gtest.h>
#include <vector>
#include "v1_0/icamera_vendor_tag.h"

using namespace testing::ext;
using namespace OHOS;

static sptr<OHOS::HDI::Camera::Metadata::V1_0::ICameraVendorTag> g_cameraVendorTagService = nullptr;

class CameraVendorTagTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CameraVendorTagTest::SetUpTestCase()
{
    g_cameraVendorTagService = OHOS::HDI::Camera::Metadata::V1_0::ICameraVendorTag::Get(true);
    ASSERT_NE(nullptr, g_cameraVendorTagService);
}

void CameraVendorTagTest::TearDownTestCase()
{
}

void CameraVendorTagTest::SetUp()
{
}

void CameraVendorTagTest::TearDown()
{
}

/**
 * @tc.name: CameraVendorTagTest
 * @tc.desc: Test GetVendorTagName
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraVendorTagTest, GetVendorTagName001, TestSize.Level0)
{
    ASSERT_NE(nullptr, g_cameraVendorTagService);
    std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag> g_hdiTagVec;
    auto ret = g_cameraVendorTagService->GetAllVendorTags(g_hdiTagVec);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (auto item : g_hdiTagVec) {
        void* tagName = nullptr;
        ret = g_cameraVendorTagService->GetVendorTagName(item.tagId, tagName);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ASSERT_NE(nullptr, tagName);
        std::string tagNameByGetAllVendorTags(reinterpret_cast<const char*>(item.tagName));
        std::string tagNameByGetVendorTagName(reinterpret_cast<const char*>(tagName));
        ASSERT_EQ(tagNameByGetAllVendorTags, tagNameByGetVendorTagName);
    }
}

/**
 * @tc.name: CameraVendorTagTest
 * @tc.desc: Test GetVendorTagType
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraVendorTagTest, GetVendorTagType001, TestSize.Level0)
{
    ASSERT_NE(nullptr, g_cameraVendorTagService);
    std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag> g_hdiTagVec;
    auto ret = g_cameraVendorTagService->GetAllVendorTags(g_hdiTagVec);
    ASSERT_EQ(HDF_SUCCESS, ret);
    for (auto item : g_hdiTagVec) {
        int8_t hdiDataType = -1;
        ret = g_cameraVendorTagService->GetVendorTagType(item.tagId, hdiDataType);
        ASSERT_EQ(HDF_SUCCESS, ret);
        ASSERT_NE(-1, hdiDataType);
        ASSERT_EQ(item.tagType, hdiDataType);
    }
}

/**
 * @tc.name: CameraVendorTagTest
 * @tc.desc: Test GetAllVendorTags
 * @tc.level: Level0
 * @tc.size: MediumTest
 * @tc.type: Function
 */
HWTEST_F(CameraVendorTagTest, GetAllVendorTags001, TestSize.Level0)
{
    ASSERT_NE(nullptr, g_cameraVendorTagService);
    std::vector<OHOS::HDI::Camera::Metadata::V1_0::VendorTag> g_hdiTagVec;
    auto ret = g_cameraVendorTagService->GetAllVendorTags(g_hdiTagVec);
    ASSERT_EQ(HDF_SUCCESS, ret);
}