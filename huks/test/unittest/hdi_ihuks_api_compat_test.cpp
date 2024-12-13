/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <vector>
#include <unistd.h>

#include "v1_1/ihuks.h"
#include "v1_1/ihuks_types.h"
#include "huks_sa_type.h"
#include "huks_hdi_test_util.h"

using namespace testing;
using namespace testing::ext;
namespace Unittest::HuksHdiTest {
static struct IHuks *g_huksHdiProxy = nullptr;
class HuksHdiApiCompatTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void HuksHdiApiCompatTest::SetUpTestCase(void)
{
    g_huksHdiProxy = IHuksGetInstance("hdi_service", true);
    int32_t ret = g_huksHdiProxy->ModuleInit(g_huksHdiProxy);
    HUKS_TEST_LOG_I("ModuleInit = %d", ret);
}

void HuksHdiApiCompatTest::TearDownTestCase(void)
{
    if (g_huksHdiProxy != nullptr) {
        IHuksReleaseInstance("hdi_service", g_huksHdiProxy, true);
        g_huksHdiProxy = nullptr;
    }
}

void HuksHdiApiCompatTest::SetUp()
{
}

void HuksHdiApiCompatTest::TearDown()
{
}

/**
 * @tc.name: HuksHdiApiCompatTest.HdiFuncCompatibilityTest001
 * @tc.desc: Test hdi func pointer params compatibility;
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWTEST_F(HuksHdiApiCompatTest, HdiFuncCompatibilityTest001, TestSize.Level0)
{
    ASSERT_EQ((int32_t)HUKS_SUCCESS, 0);
    ASSERT_EQ((int32_t)HUKS_FAILURE, -1);
    ASSERT_EQ((int32_t)HUKS_ERROR_NULL_POINTER, -14);
    ASSERT_EQ((int32_t)HUKS_ERROR_MALLOC_FAIL, -21);
    ASSERT_EQ((int32_t)HKS_CHIPSET_PLATFORM_DECRYPT_SCENE_TA_TO_TA, 1);
}

/**
 * @tc.name: HuksHdiApiCompatTest.HdiFuncCompatibilityTest002
 * @tc.desc: Test hdi func pointer params compatibility;
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWTEST_F(HuksHdiApiCompatTest, HdiFuncCompatibilityTest002, TestSize.Level0)
{
    struct HksBlob blob = {0};
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.size, 0);
}

/**
 * @tc.name: HuksHdiApiCompatTest.HdiFuncCompatibilityTest003
 * @tc.desc: Test hdi func pointer params compatibility;
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWTEST_F(HuksHdiApiCompatTest, HdiFuncCompatibilityTest003, TestSize.Level0)
{
    struct HksParam param = {0};
    ASSERT_EQ(param.tag, 0);
    ASSERT_EQ(param.boolParam, false);
    ASSERT_EQ(param.int32Param, 0);
    ASSERT_EQ(param.uint32Param, 0);
    ASSERT_EQ(param.uint64Param, 0);
    ASSERT_EQ(param.blob.data, nullptr);
    ASSERT_EQ(param.blob.size, 0);
}

/**
 * @tc.name: HuksHdiApiCompatTest.HdiFuncCompatibilityTest004
 * @tc.desc: Test hdi func pointer params compatibility;
 * @tc.require:issueI77AT9
 * @tc.type: FUNC
 */
HWTEST_F(HuksHdiApiCompatTest, HdiFuncCompatibilityTest004, TestSize.Level0)
{
    struct HksParamSet paramSet = {0};
    ASSERT_EQ(paramSet.paramSetSize, 0);
    ASSERT_EQ(paramSet.paramsCnt, 0);
}
}