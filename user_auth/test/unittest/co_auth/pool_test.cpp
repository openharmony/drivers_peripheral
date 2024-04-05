/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "securec.h"

#include "adaptor_memory.h"
#include "buffer.h"
#include "linked_list.h"
#include "pool.h"

extern "C" {
    extern LinkedList *g_poolList;
    extern void DestroyExecutorInfo(void *data);
    extern bool IsExecutorIdMatchById(const void *data, const void *condition);
    extern bool IsExecutorNodeMatch(const void *data, const void *condition);
    extern bool IsExecutorValid(const ExecutorInfoHal *executorInfo);
    extern ResultCode GenerateValidExecutorId(uint64_t *executorIndex);
    extern bool IsExecutorMatch(const ExecutorCondition *condition, const ExecutorInfoHal *credentialInfo);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class PoolTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(PoolTest, TestDestroyExecutorInfo, TestSize.Level0)
{
    DestroyExecutorInfo(nullptr);
    ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)Malloc(sizeof(ExecutorInfoHal));
    EXPECT_NE(executorInfo, nullptr);
    ASSERT_NE(executorInfo, nullptr);
    (void)memset_s(executorInfo, sizeof(ExecutorInfoHal), 0, sizeof(ExecutorInfoHal));
    DestroyExecutorInfo(executorInfo);
}

HWTEST_F(PoolTest, TestIsExecutorIdMatchById, TestSize.Level0)
{
    EXPECT_FALSE(IsExecutorIdMatchById(nullptr, nullptr));
}

HWTEST_F(PoolTest, TestIsExecutorNodeMatch, TestSize.Level0)
{
    EXPECT_FALSE(IsExecutorNodeMatch(nullptr, nullptr));
}

HWTEST_F(PoolTest, TestInitResourcePool, TestSize.Level0)
{
    g_poolList = CreateLinkedList(DestroyExecutorInfo);
    EXPECT_NE(g_poolList, nullptr);
    EXPECT_EQ(InitResourcePool(), 0);
    DestroyResourcePool();
}

HWTEST_F(PoolTest, TestIsExecutorValid, TestSize.Level0)
{
    EXPECT_FALSE(IsExecutorValid(nullptr));
}

HWTEST_F(PoolTest, TestGenerateValidExecutorId, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(GenerateValidExecutorId(nullptr), 8);
}

HWTEST_F(PoolTest, TestRegisterExecutorToPool_001, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE = 4;
    g_poolList = nullptr;
    EXPECT_EQ(RegisterExecutorToPool(nullptr), RESULT_NEED_INIT);
    InitResourcePool();
    EXPECT_EQ(RegisterExecutorToPool(nullptr), RESULT_BAD_PARAM);
    ExecutorInfoHal info = {};
    info.authType = AUTH_TYPE;
    EXPECT_EQ(RegisterExecutorToPool(&info), 0);
    g_poolList = nullptr;
}

HWTEST_F(PoolTest, TestRegisterExecutorToPool_002, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE = 1;
    constexpr uint32_t EXECUTOE_SENSOR_HINT = 20;
    constexpr uint32_t EXECUTOE_ROLE = 50;
    g_poolList = nullptr;
    EXPECT_EQ(RegisterExecutorToPool(nullptr), RESULT_NEED_INIT);
    InitResourcePool();
    EXPECT_EQ(RegisterExecutorToPool(nullptr), RESULT_BAD_PARAM);
    auto *info1 = static_cast<ExecutorInfoHal *>(Malloc(sizeof(ExecutorInfoHal)));
    info1->authType = AUTH_TYPE;
    info1->executorSensorHint = EXECUTOE_SENSOR_HINT;
    info1->executorRole = EXECUTOE_ROLE;
    g_poolList->insert(g_poolList, static_cast<void *>(info1));
    auto *info2 = static_cast<ExecutorInfoHal *>(Malloc(sizeof(ExecutorInfoHal)));
    info2->authType = AUTH_TYPE;
    info2->executorSensorHint = EXECUTOE_SENSOR_HINT;
    info2->executorRole = EXECUTOE_ROLE;
    EXPECT_EQ(RegisterExecutorToPool(info2), 0);
    DestroyResourcePool();
}

HWTEST_F(PoolTest, TestUnregisterExecutorToPool, TestSize.Level0)
{
    g_poolList = nullptr;
    constexpr uint64_t INDEX = 12;
    EXPECT_EQ(UnregisterExecutorToPool(INDEX), RESULT_NEED_INIT);
}

HWTEST_F(PoolTest, TestCopyExecutorInfo, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(CopyExecutorInfo(nullptr), nullptr);
}

HWTEST_F(PoolTest, TestIsExecutorMatch_001, TestSize.Level0)
{
    constexpr uint64_t INDEX = 245485;
    constexpr uint64_t EXECUTOR_INDEX = 2634;
    ExecutorInfoHal executorInfo = {};
    executorInfo.executorIndex = EXECUTOR_INDEX;
    ExecutorCondition condition = {};
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
    SetExecutorConditionExecutorIndex(&condition, INDEX);
    EXPECT_FALSE(IsExecutorMatch(&condition, &executorInfo));
    executorInfo.executorIndex = INDEX;
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
}

HWTEST_F(PoolTest, TestIsExecutorMatch_002, TestSize.Level0)
{
    constexpr uint64_t HINT = 245485;
    constexpr uint64_t EXECUTOR_INDEX = 2634;
    ExecutorInfoHal executorInfo = {};
    executorInfo.executorIndex = EXECUTOR_INDEX;
    ExecutorCondition condition = {};
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
    SetExecutorConditionSensorHint(&condition, HINT);
    EXPECT_FALSE(IsExecutorMatch(&condition, &executorInfo));
    executorInfo.executorSensorHint = HINT;
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
}

HWTEST_F(PoolTest, TestIsExecutorMatch_003, TestSize.Level0)
{
    constexpr uint64_t MATCHER = 245485;
    ExecutorInfoHal executorInfo = {};
    ExecutorCondition condition = {};
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
    SetExecutorConditionExecutorMatcher(&condition, MATCHER);
    EXPECT_FALSE(IsExecutorMatch(&condition, &executorInfo));
    executorInfo.executorMatcher = MATCHER;
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
}

HWTEST_F(PoolTest, TestQueryExecutor, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(QueryExecutor(nullptr), nullptr);
}

HWTEST_F(PoolTest, TestQueryCollecterMatcher, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE_1 = 1;
    constexpr uint32_t AUTH_TYPE_2 = 4;
    constexpr uint32_t EXECUTOR_SENSORP_HINT = 20;
    g_poolList = nullptr;
    EXPECT_EQ(QueryCollecterMatcher(AUTH_TYPE_1, EXECUTOR_SENSORP_HINT, nullptr), RESULT_NEED_INIT);
    InitResourcePool();
    EXPECT_EQ(QueryCollecterMatcher(AUTH_TYPE_1, EXECUTOR_SENSORP_HINT, nullptr), RESULT_BAD_PARAM);
    uint32_t matcher = 1245;
    EXPECT_EQ(QueryCollecterMatcher(AUTH_TYPE_1, EXECUTOR_SENSORP_HINT, &matcher), RESULT_NOT_FOUND);
    ExecutorInfoHal info1 = {};
    info1.authType = AUTH_TYPE_1;
    info1.executorSensorHint = EXECUTOR_SENSORP_HINT;
    info1.executorRole = ALL_IN_ONE;
    g_poolList->insert(g_poolList, static_cast<void *>(&info1));
    ExecutorInfoHal info2 = {};
    info2.authType = AUTH_TYPE_1;
    info2.executorSensorHint = EXECUTOR_SENSORP_HINT;
    info2.executorRole = VERIFIER;
    g_poolList->insert(g_poolList, static_cast<void *>(&info2));
    ExecutorInfoHal info3 = {};
    info3.authType = AUTH_TYPE_1;
    g_poolList->insert(g_poolList, static_cast<void *>(&info3));
    ExecutorInfoHal info4 = {};
    info4.authType = AUTH_TYPE_2;
    g_poolList->insert(g_poolList, static_cast<void *>(&info4));
    g_poolList->insert(g_poolList, nullptr);
    EXPECT_EQ(QueryCollecterMatcher(1, 20, &matcher), RESULT_SUCCESS);
    g_poolList = nullptr;
}

HWTEST_F(PoolTest, TestQueryCredentialExecutorIndex, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE_1 = 1;
    constexpr uint32_t AUTH_TYPE_2 = 4;
    constexpr uint32_t EXECUTOR_SENSORP_HINT = 20;
    constexpr uint32_t EXECUTOR_INDEX = 1267;
    g_poolList = nullptr;
    EXPECT_EQ(QueryCredentialExecutorIndex(AUTH_TYPE_1, EXECUTOR_SENSORP_HINT), INVALID_EXECUTOR_INDEX);
    InitResourcePool();
    EXPECT_EQ(QueryCredentialExecutorIndex(AUTH_TYPE_1, EXECUTOR_SENSORP_HINT), INVALID_EXECUTOR_INDEX);
    ExecutorInfoHal info1 = {};
    info1.authType = AUTH_TYPE_1;
    info1.executorSensorHint = EXECUTOR_SENSORP_HINT;
    info1.executorRole = ALL_IN_ONE;
    info1.executorIndex = EXECUTOR_INDEX;
    g_poolList->insert(g_poolList, static_cast<void *>(&info1));
    ExecutorInfoHal info2 = {};
    info2.authType = AUTH_TYPE_1;
    info2.executorSensorHint = EXECUTOR_SENSORP_HINT;
    info2.executorRole = COLLECTOR;
    g_poolList->insert(g_poolList, static_cast<void *>(&info2));
    ExecutorInfoHal info3 = {};
    info3.authType = AUTH_TYPE_1;
    g_poolList->insert(g_poolList, static_cast<void *>(&info3));
    ExecutorInfoHal info4 = {};
    info4.authType = AUTH_TYPE_2;
    g_poolList->insert(g_poolList, static_cast<void *>(&info4));
    g_poolList->insert(g_poolList, nullptr);
    EXPECT_EQ(QueryCredentialExecutorIndex(AUTH_TYPE_1, EXECUTOR_SENSORP_HINT), info1.executorIndex);
    g_poolList = nullptr;
}

HWTEST_F(PoolTest, TestSetExecutorConditionExecutorIndex, TestSize.Level0)
{
    constexpr uint32_t EXECUTOR_INDEX = 10;
    SetExecutorConditionExecutorIndex(nullptr, EXECUTOR_INDEX);
    ExecutorCondition condition = {};
    SetExecutorConditionExecutorIndex(&condition, EXECUTOR_INDEX);
    EXPECT_EQ(condition.executorIndex, EXECUTOR_INDEX);
    EXPECT_EQ(condition.conditonFactor & EXECUTOR_CONDITION_INDEX, EXECUTOR_CONDITION_INDEX);
}

HWTEST_F(PoolTest, TestSetExecutorConditionAuthType, TestSize.Level0)
{
    constexpr uint32_t AUTH_TYPE = 1;
    SetExecutorConditionAuthType(nullptr, AUTH_TYPE);
    ExecutorCondition condition = {};
    SetExecutorConditionAuthType(&condition, AUTH_TYPE);
    EXPECT_EQ(condition.authType, AUTH_TYPE);
    EXPECT_EQ(condition.conditonFactor & EXECUTOR_CONDITION_AUTH_TYPE, EXECUTOR_CONDITION_AUTH_TYPE);
}

HWTEST_F(PoolTest, TestSetExecutorConditionSensorHint, TestSize.Level0)
{
    constexpr uint32_t EXECUTOR_SENSOR_HINT = 20;
    SetExecutorConditionSensorHint(nullptr, EXECUTOR_SENSOR_HINT);
    ExecutorCondition condition = {};
    SetExecutorConditionSensorHint(&condition, EXECUTOR_SENSOR_HINT);
    EXPECT_EQ(condition.executorSensorHint, EXECUTOR_SENSOR_HINT);
    EXPECT_EQ(condition.conditonFactor & EXECUTOR_CONDITION_SENSOR_HINT, EXECUTOR_CONDITION_SENSOR_HINT);
}

HWTEST_F(PoolTest, TestSetExecutorConditionExecutorRole, TestSize.Level0)
{
    constexpr uint32_t EXECUTOR_ROLE = 2136;
    SetExecutorConditionExecutorRole(nullptr, EXECUTOR_ROLE);
    ExecutorCondition condition = {};
    SetExecutorConditionExecutorRole(&condition, EXECUTOR_ROLE);
    EXPECT_EQ(condition.executorRole, EXECUTOR_ROLE);
    EXPECT_EQ(condition.conditonFactor & EXECUTOR_CONDITION_ROLE, EXECUTOR_CONDITION_ROLE);
}

HWTEST_F(PoolTest, TestSetExecutorConditionExecutorMatcher, TestSize.Level0)
{
    constexpr uint32_t EXECUTOR_MATCHER = 2363;
    SetExecutorConditionExecutorMatcher(nullptr, EXECUTOR_MATCHER);
    ExecutorCondition condition = {};
    SetExecutorConditionExecutorMatcher(&condition, EXECUTOR_MATCHER);
    EXPECT_EQ(condition.executorMatcher, EXECUTOR_MATCHER);
    EXPECT_EQ(condition.conditonFactor & EXECUTOR_CONDITION_MATCHER, EXECUTOR_CONDITION_MATCHER);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
