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
    extern ResultCode GetAcl(int32_t userId, uint32_t authType, uint32_t *acl);
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
    executorInfo.esl = 10;
    schedule.executors[0] = executorInfo;
    schedule.executorSize = 1;
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

HWTEST_F(AuthLevelTest, TestGetAsl_001, TestSize.Level0)
{
    uint32_t authType = 1;
    uint32_t asl = 0;
    EXPECT_EQ(GetAsl(authType, &asl), RESULT_UNKNOWN);
}

HWTEST_F(AuthLevelTest, TestGetAsl_002, TestSize.Level0)
{
    g_poolList = CreateLinkedList(DestroyExecutorInfo);
    EXPECT_NE(g_poolList, nullptr);
    ExecutorInfoHal executorInfo = {};
    executorInfo.authType = 1;
    executorInfo.executorRole = COLLECTOR;
    g_poolList->insert(g_poolList, static_cast<void *>(&executorInfo));
    uint32_t authType = 1;
    uint32_t asl = 0;
    EXPECT_EQ(GetAsl(authType, &asl), RESULT_GENERAL_ERROR);
}

HWTEST_F(AuthLevelTest, TestGetAsl_003, TestSize.Level0)
{
    g_poolList = CreateLinkedList(DestroyExecutorInfo);
    EXPECT_NE(g_poolList, nullptr);
    ExecutorInfoHal executorInfo = {};
    executorInfo.authType = 1;
    executorInfo.executorRole = ALL_IN_ONE;
    executorInfo.esl = 0;
    g_poolList->insert(g_poolList, static_cast<void *>(&executorInfo));
    uint32_t authType = 1;
    uint32_t asl = 0;
    EXPECT_EQ(GetAsl(authType, &asl), RESULT_SUCCESS);
}

HWTEST_F(AuthLevelTest, TestGetAcl, TestSize.Level0)
{
    int32_t userId = 21361;
    uint32_t authType = 1;
    uint32_t acl = 0;
    EXPECT_EQ(GetAcl(userId, authType, &acl), RESULT_NOT_ENROLLED);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    EXPECT_EQ(GetAcl(userId, authType, &acl), RESULT_NOT_ENROLLED);
}

HWTEST_F(AuthLevelTest, TestSingleAuthTrustLevel_001, TestSize.Level0)
{
    int32_t userId = 21356;
    uint32_t authType = 1;
    EXPECT_EQ(SingleAuthTrustLevel(userId, authType, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(AuthLevelTest, TestSingleAuthTrustLevel_002, TestSize.Level0)
{
    g_poolList = CreateLinkedList(DestroyExecutorInfo);
    EXPECT_NE(g_poolList, nullptr);
    ExecutorInfoHal executorInfo = {};
    executorInfo.authType = 1;
    executorInfo.executorRole = ALL_IN_ONE;
    executorInfo.esl = 0;
    g_poolList->insert(g_poolList, static_cast<void *>(&executorInfo));
    g_userInfoList = nullptr;
    int32_t userId = 21356;
    uint32_t authType = 1;
    uint32_t atl = 0;
    EXPECT_EQ(SingleAuthTrustLevel(userId, authType, &atl), RESULT_NOT_ENROLLED);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
