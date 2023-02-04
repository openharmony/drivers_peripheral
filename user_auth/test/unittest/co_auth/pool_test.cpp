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
    g_poolList = nullptr;
    EXPECT_EQ(RegisterExecutorToPool(nullptr), RESULT_NEED_INIT);
    InitResourcePool();
    EXPECT_EQ(RegisterExecutorToPool(nullptr), RESULT_BAD_PARAM);
    ExecutorInfoHal info = {};
    info.authType = 4;
    EXPECT_EQ(RegisterExecutorToPool(&info), 0);
    g_poolList = nullptr;
}

HWTEST_F(PoolTest, TestRegisterExecutorToPool_002, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(RegisterExecutorToPool(nullptr), RESULT_NEED_INIT);
    InitResourcePool();
    EXPECT_EQ(RegisterExecutorToPool(nullptr), RESULT_BAD_PARAM);
    auto *info1 = static_cast<ExecutorInfoHal *>(Malloc(sizeof(ExecutorInfoHal)));
    info1->authType = 1;
    info1->executorSensorHint = 20;
    info1->executorRole = 50;
    g_poolList->insert(g_poolList, static_cast<void *>(info1));
    auto *info2 = static_cast<ExecutorInfoHal *>(Malloc(sizeof(ExecutorInfoHal)));
    info2->authType = 1;
    info2->executorSensorHint = 20;
    info2->executorRole = 50;
    EXPECT_EQ(RegisterExecutorToPool(info2), 0);
    DestroyResourcePool();
}

HWTEST_F(PoolTest, TestUnregisterExecutorToPool, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(UnregisterExecutorToPool(12), RESULT_NEED_INIT);
}

HWTEST_F(PoolTest, TestCopyExecutorInfo, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(CopyExecutorInfo(nullptr), nullptr);
}

HWTEST_F(PoolTest, TestIsExecutorMatch_001, TestSize.Level0)
{
    uint64_t index = 245485;
    ExecutorInfoHal executorInfo = {};
    executorInfo.executorIndex = 2634;
    ExecutorCondition condition = {};
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
    SetExecutorConditionExecutorIndex(&condition, index);
    EXPECT_FALSE(IsExecutorMatch(&condition, &executorInfo));
    executorInfo.executorIndex = index;
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
}

HWTEST_F(PoolTest, TestIsExecutorMatch_002, TestSize.Level0)
{
    uint32_t hint = 245485;
    ExecutorInfoHal executorInfo = {};
    executorInfo.executorSensorHint = 2634;
    ExecutorCondition condition = {};
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
    SetExecutorConditionSensorHint(&condition, hint);
    EXPECT_FALSE(IsExecutorMatch(&condition, &executorInfo));
    executorInfo.executorSensorHint = hint;
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
}

HWTEST_F(PoolTest, TestIsExecutorMatch_003, TestSize.Level0)
{
    uint32_t matcher = 245485;
    ExecutorInfoHal executorInfo = {};
    executorInfo.executorMatcher = 2634;
    ExecutorCondition condition = {};
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
    SetExecutorConditionExecutorMatcher(&condition, matcher);
    EXPECT_FALSE(IsExecutorMatch(&condition, &executorInfo));
    executorInfo.executorMatcher = matcher;
    EXPECT_TRUE(IsExecutorMatch(&condition, &executorInfo));
}

HWTEST_F(PoolTest, TestQueryExecutor, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(QueryExecutor(nullptr), nullptr);
}

HWTEST_F(PoolTest, TestQueryCollecterMatcher, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(QueryCollecterMatcher(1, 20, nullptr), RESULT_NEED_INIT);
    InitResourcePool();
    EXPECT_EQ(QueryCollecterMatcher(1, 20, nullptr), RESULT_BAD_PARAM);
    uint32_t matcher = 1245;
    EXPECT_EQ(QueryCollecterMatcher(1, 20, &matcher), RESULT_NOT_FOUND);
    ExecutorInfoHal info1 = {};
    info1.authType = 1;
    info1.executorSensorHint = 20;
    info1.executorRole = ALL_IN_ONE;
    g_poolList->insert(g_poolList, static_cast<void *>(&info1));
    ExecutorInfoHal info2 = {};
    info2.authType = 1;
    info2.executorSensorHint = 20;
    info2.executorRole = VERIFIER;
    g_poolList->insert(g_poolList, static_cast<void *>(&info2));
    ExecutorInfoHal info3 = {};
    info3.authType = 1;
    g_poolList->insert(g_poolList, static_cast<void *>(&info3));
    ExecutorInfoHal info4 = {};
    info4.authType = 4;
    g_poolList->insert(g_poolList, static_cast<void *>(&info4));
    g_poolList->insert(g_poolList, nullptr);
    EXPECT_EQ(QueryCollecterMatcher(1, 20, &matcher), RESULT_SUCCESS);
    g_poolList = nullptr;
}

HWTEST_F(PoolTest, TestQueryCredentialExecutorIndex, TestSize.Level0)
{
    g_poolList = nullptr;
    EXPECT_EQ(QueryCredentialExecutorIndex(1, 20), INVALID_EXECUTOR_INDEX);
    InitResourcePool();
    EXPECT_EQ(QueryCredentialExecutorIndex(1, 20), INVALID_EXECUTOR_INDEX);
    ExecutorInfoHal info1 = {};
    info1.authType = 1;
    info1.executorSensorHint = 20;
    info1.executorRole = ALL_IN_ONE;
    info1.executorIndex = 1267;
    g_poolList->insert(g_poolList, static_cast<void *>(&info1));
    ExecutorInfoHal info2 = {};
    info2.authType = 1;
    info2.executorSensorHint = 20;
    info2.executorRole = COLLECTOR;
    g_poolList->insert(g_poolList, static_cast<void *>(&info2));
    ExecutorInfoHal info3 = {};
    info3.authType = 1;
    g_poolList->insert(g_poolList, static_cast<void *>(&info3));
    ExecutorInfoHal info4 = {};
    info4.authType = 4;
    g_poolList->insert(g_poolList, static_cast<void *>(&info4));
    g_poolList->insert(g_poolList, nullptr);
    EXPECT_EQ(QueryCredentialExecutorIndex(1, 20), info1.executorIndex);
    g_poolList = nullptr;
}

HWTEST_F(PoolTest, TestSetExecutorConditionExecutorIndex, TestSize.Level0)
{
    SetExecutorConditionExecutorIndex(nullptr, 10);
    ExecutorCondition condition = {};
    SetExecutorConditionExecutorIndex(&condition, 10);
}

HWTEST_F(PoolTest, TestSetExecutorConditionAuthType, TestSize.Level0)
{
    SetExecutorConditionAuthType(nullptr, 1);
    ExecutorCondition condition = {};
    SetExecutorConditionAuthType(&condition, 1);
}

HWTEST_F(PoolTest, TestSetExecutorConditionSensorHint, TestSize.Level0)
{
    SetExecutorConditionSensorHint(nullptr, 20);
    ExecutorCondition condition = {};
    SetExecutorConditionSensorHint(&condition, 20);
}

HWTEST_F(PoolTest, TestSetExecutorConditionExecutorRole, TestSize.Level0)
{
    SetExecutorConditionExecutorRole(nullptr, 2136);
    ExecutorCondition condition = {};
    SetExecutorConditionExecutorRole(&condition, 2136);
}

HWTEST_F(PoolTest, TestSetExecutorConditionExecutorMatcher, TestSize.Level0)
{
    SetExecutorConditionExecutorMatcher(nullptr, 2363);
    ExecutorCondition condition = {};
    SetExecutorConditionExecutorMatcher(&condition, 2363);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
