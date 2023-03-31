/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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
#include <osal_mem.h>
#include "codec_callback_if.h"
#include "codec_component_manager.h"
using namespace std;
using namespace testing::ext;
namespace {
class CodecHdiManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp()
    {
        manager_ = GetCodecComponentManager();
    }
    void TearDown()
    {
        CodecComponentManagerRelease();
        manager_ = nullptr;
    }

public:
    struct CodecComponentManager *manager_ = nullptr;
};

HWTEST_F(CodecHdiManagerTest, HdfCodecHdiGetComponentNumTest_001, TestSize.Level1)
{
    ASSERT_TRUE(manager_ != nullptr);
    auto count = manager_->GetComponentNum();
    EXPECT_TRUE(count >= 0);
}

HWTEST_F(CodecHdiManagerTest, HdfCodecHdiGetCapabilityListTest_001, TestSize.Level1)
{
    ASSERT_TRUE(manager_ != nullptr);
    auto count = manager_->GetComponentNum();
    ASSERT_TRUE(count > 0);
    CodecCompCapability *capList = (CodecCompCapability *)OsalMemAlloc(sizeof(CodecCompCapability) * count);
    ASSERT_TRUE(capList != nullptr);
    auto err = manager_->GetComponentCapabilityList(capList, count);
    EXPECT_EQ(err, HDF_SUCCESS);
    OsalMemFree(capList);
    capList = nullptr;
}

HWTEST_F(CodecHdiManagerTest, HdfCodecHdiCreateComponentTest_001, TestSize.Level1)
{
    struct CodecCallbackType *callback = CodecCallbackTypeGet(nullptr);
    ASSERT_TRUE(callback != nullptr);
    ASSERT_TRUE(manager_ != nullptr);
    struct CodecComponentType *component = nullptr;
    uint32_t componentId = 0;
    int32_t ret = manager_->CreateComponent(&component, &componentId, nullptr, (int64_t)this, callback);
    EXPECT_NE(ret, HDF_SUCCESS);
    EXPECT_EQ(component, nullptr);
    CodecCallbackTypeRelease(callback);
    callback = nullptr;
}

HWTEST_F(CodecHdiManagerTest, HdfCodecHdiCreateComponentTest_002, TestSize.Level1)
{
    ASSERT_TRUE(manager_ != nullptr);
    std::string compName("");
    auto count = manager_->GetComponentNum();
    ASSERT_TRUE(count > 0);
    CodecCompCapability *capList = (CodecCompCapability *)OsalMemAlloc(sizeof(CodecCompCapability) * count);
    ASSERT_TRUE(capList != nullptr);
    auto err = manager_->GetComponentCapabilityList(capList, count);
    EXPECT_EQ(err, HDF_SUCCESS);
    compName = capList[0].compName;
    OsalMemFree(capList);
    capList = nullptr;

    ASSERT_FALSE(compName.empty());
    struct CodecCallbackType *callback = CodecCallbackTypeGet(nullptr);
    struct CodecComponentType *component = nullptr;
    uint32_t componentId = 0;
    ASSERT_TRUE(callback != nullptr);
    auto ret = manager_->CreateComponent(&component, &componentId, compName.data(), (int64_t)this, callback);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (componentId != 0) {
        manager_->DestroyComponent(componentId);
    }
    CodecCallbackTypeRelease(callback);
    callback = nullptr;
}

HWTEST_F(CodecHdiManagerTest, HdfCodecHdiDestroyComponentTest_001, TestSize.Level1)
{
    ASSERT_TRUE(manager_ != nullptr);
    auto ret = manager_->DestroyComponent(0);
    EXPECT_EQ(ret, HDF_SUCCESS);
}
}  // namespace