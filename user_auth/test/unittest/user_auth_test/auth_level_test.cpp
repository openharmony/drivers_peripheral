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

#include "auth_level.h"
#include "idm_common.h"
#include "pool.h"

extern "C" {
    extern LinkedList *g_poolList;
    extern LinkedList *g_userInfoList;
    extern void DestroyExecutorInfo(void *data);
    extern ResultCode QueryScheduleAsl(const CoAuthSchedule *coAuthSchedule, uint32_t *asl);
    extern ResultCode GetAsl(uint32_t authType, uint32_t *asl);
    extern ResultCode GetAslAndAcl(uint32_t authType, uint32_t *asl, uint32_t *acl);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class AuthLevelTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(AuthLevelTest, TestGetAtl, TestSize.Level0)
{
    EXPECT_EQ(GetAtl(0, 0), 0);
}

HWTEST_F(AuthLevelTest, TestQueryScheduleAsl_001, TestSize.Level0)
{
    EXPECT_EQ(QueryScheduleAsl(nullptr, nullptr), RESULT_BAD_PARAM);
    CoAuthSchedule schedule = {};
    EXPECT_EQ(QueryScheduleAsl(&schedule, nullptr), RESULT_BAD_PARAM);
    uint32_t asl = 0;
    schedule.executorSize = 0;
    EXPECT_EQ(QueryScheduleAsl(&schedule, &asl), RESULT_BAD_PARAM);
}

HWTEST_F(AuthLevelTest, TestQueryScheduleAsl_002, TestSize.Level0)
{
    CoAuthSchedule schedule = {};
    ExecutorInfoHal executorInfo = {};
    constexpr uint32_t esl = 10;
    constexpr uint32_t excutorSize = 1;
    executorInfo.esl = esl;
    schedule.executors[0] = executorInfo;
    schedule.executorSize = excutorSize;
    uint32_t asl = 0;
    EXPECT_EQ(QueryScheduleAsl(&schedule, &asl), RESULT_SUCCESS);
}

HWTEST_F(AuthLevelTest, TestQueryScheduleAtl, TestSize.Level0)
{
    EXPECT_EQ(QueryScheduleAtl(nullptr, 0, nullptr), RESULT_BAD_PARAM);
    CoAuthSchedule schedule = {};
    EXPECT_EQ(QueryScheduleAtl(&schedule, 0, nullptr), RESULT_BAD_PARAM);
    uint32_t atl = 0;
    schedule.executorSize = 0;
    EXPECT_EQ(QueryScheduleAtl(&schedule, 0, &atl), RESULT_BAD_PARAM);
}

HWTEST_F(AuthLevelTest, TestGetAslAndAcl_001, TestSize.Level0)
{
    constexpr uint32_t authType = 1;
    uint32_t asl = 0;
    uint32_t acl = 0;
    EXPECT_EQ(GetAslAndAcl(authType, &asl, &acl), RESULT_UNKNOWN);
}

HWTEST_F(AuthLevelTest, TestGetAslAndAcl_002, TestSize.Level0)
{
    g_poolList = CreateLinkedList(DestroyExecutorInfo);
    EXPECT_NE(g_poolList, nullptr);
    ExecutorInfoHal executorInfo = {};
    executorInfo.authType = 1;
    executorInfo.executorRole = COLLECTOR;
    g_poolList->insert(g_poolList, static_cast<void *>(&executorInfo));
    constexpr uint32_t authType = 1;
    uint32_t asl = 0;
    uint32_t acl = 0;
    EXPECT_EQ(GetAslAndAcl(authType, &asl, &acl), RESULT_SUCCESS);
}

HWTEST_F(AuthLevelTest, TestGetAslAndAcl_003, TestSize.Level0)
{
    g_poolList = CreateLinkedList(DestroyExecutorInfo);
    EXPECT_NE(g_poolList, nullptr);
    ExecutorInfoHal executorInfo = {};
    executorInfo.authType = 1;
    executorInfo.executorRole = ALL_IN_ONE;
    executorInfo.esl = 0;
    g_poolList->insert(g_poolList, static_cast<void *>(&executorInfo));
    constexpr uint32_t authType = 1;
    uint32_t asl = 0;
    uint32_t acl = 0;
    EXPECT_EQ(GetAslAndAcl(authType, &asl, &acl), RESULT_SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
