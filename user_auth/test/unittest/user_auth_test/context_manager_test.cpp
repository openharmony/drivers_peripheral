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

#include "coauth.h"
#include "context_manager.h"
#include "idm_common.h"
#include "pool.h"

extern "C" {
    extern LinkedList *g_contextList;
    extern LinkedList *g_poolList;
    extern LinkedList *g_scheduleList;
    extern LinkedList *g_userInfoList;
    extern void DestroyExecutorInfo(void *data);
    extern void DestroyContextNode(void *data);
    extern LinkedList *GetAuthCredentialList(const UserAuthContext *context);
    extern ResultCode CheckCredentialSize(LinkedList *credList);
    extern ResultCode QueryAuthTempletaInfo(UserAuthContext *context, TemplateIdArrays *templateIds,
        uint32_t *sensorHint, uint32_t *matcher, uint32_t *acl);
    extern bool IsContextDuplicate(uint64_t contextId);
    extern bool MatchSchedule(const void *data, const void *condition);
    extern void DestroyContextNode(void *data);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class ContextManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(ContextManagerTest, TestInitUserAuthContextList, TestSize.Level0)
{
    EXPECT_EQ(InitUserAuthContextList(), RESULT_SUCCESS);
    EXPECT_EQ(InitUserAuthContextList(), RESULT_SUCCESS);
    DestoryUserAuthContextList();
}

HWTEST_F(ContextManagerTest, TestGenerateAuthContext, TestSize.Level0)
{
    AuthSolutionHal param = {};
    EXPECT_EQ(GenerateAuthContext(param, nullptr), RESULT_BAD_PARAM);
    UserAuthContext *context = nullptr;
    g_contextList = nullptr;
    EXPECT_EQ(GenerateAuthContext(param, &context), RESULT_NEED_INIT);
    g_contextList = CreateLinkedList(DestroyContextNode);
    EXPECT_NE(g_contextList, nullptr);
    UserAuthContext authContext = {};
    authContext.contextId = 321566;
    g_contextList->insert(g_contextList, static_cast<void *>(&authContext));
    param.contextId = 321566;
    EXPECT_EQ(GenerateAuthContext(param, &context), RESULT_DUPLICATE_CHECK_FAILED);
}

HWTEST_F(ContextManagerTest, TestGenerateIdentifyContext, TestSize.Level0)
{
    g_contextList = nullptr;
    IdentifyParam param = {};
    param.contextId = 234562;
    EXPECT_EQ(GenerateIdentifyContext(param), nullptr);
    g_contextList = CreateLinkedList(DestroyContextNode);
    EXPECT_NE(g_contextList, nullptr);
    UserAuthContext context = {};
    context.contextId = param.contextId;
    EXPECT_EQ(GenerateIdentifyContext(param), nullptr);
}

HWTEST_F(ContextManagerTest, TestGetContext, TestSize.Level0)
{
    g_contextList = nullptr;
    uint64_t contextId = 324112;
    EXPECT_EQ(GetContext(contextId), nullptr);
    g_contextList = CreateLinkedList(DestroyContextNode);
    EXPECT_NE(g_contextList, nullptr);
    UserAuthContext context = {};
    context.contextId = 31157;
    g_contextList->insert(g_contextList, static_cast<void *>(&context));
    g_contextList->insert(g_contextList, nullptr);
    EXPECT_EQ(GetContext(contextId), nullptr);
}

HWTEST_F(ContextManagerTest, TestGetAuthCredentialList_001, TestSize.Level0)
{
    g_poolList = nullptr;
    UserAuthContext context = {};
    context.collectorSensorHint = 10;
    EXPECT_EQ(GetAuthCredentialList(&context), nullptr);
}

HWTEST_F(ContextManagerTest, TestGetAuthCredentialList_002, TestSize.Level0)
{
    g_poolList = CreateLinkedList(DestroyExecutorInfo);
    EXPECT_NE(g_poolList, nullptr);
    ExecutorInfoHal executorInfo = {};
    executorInfo.authType = 2;
    executorInfo.executorSensorHint = 10;
    executorInfo.executorRole = ALL_IN_ONE;
    g_poolList->insert(g_poolList, static_cast<void *>(&executorInfo));
    UserAuthContext context = {};
    context.authType = 2;
    context.collectorSensorHint = 10;
    EXPECT_EQ(GetAuthCredentialList(&context), nullptr);
}

HWTEST_F(ContextManagerTest, TestCheckCredentialSize, TestSize.Level0)
{
    LinkedList *credList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(credList, nullptr);
    CredentialInfoHal info = {};
    uint32_t credNum = 102;
    for (uint32_t i = 0; i < credNum; ++i) {
        credList->insert(credList, static_cast<void *>(&info));
    }
    EXPECT_EQ(CheckCredentialSize(credList), RESULT_EXCEED_LIMIT);
}

HWTEST_F(ContextManagerTest, TestQueryAuthTempletaInfo, TestSize.Level0)
{
    g_poolList = nullptr;
    UserAuthContext context = {};
    context.authType = 2;
    context.contextId = 21245;
    context.userId = 76256;
    TemplateIdArrays array = {};
    uint32_t hint = 0;
    uint32_t matcher = 0;
    uint32_t acl = 0;
    EXPECT_EQ(QueryAuthTempletaInfo(&context, &array, &hint, &matcher, &acl), RESULT_UNKNOWN);
}

HWTEST_F(ContextManagerTest, TestIsContextDuplicate, TestSize.Level0)
{
    g_contextList = nullptr;
    uint64_t contextId = 36517;
    EXPECT_FALSE(IsContextDuplicate(contextId));

    g_contextList = CreateLinkedList(DestroyContextNode);
    EXPECT_NE(g_contextList, nullptr);
    UserAuthContext context1 = {};
    context1.contextId = contextId;
    g_contextList->insert(g_contextList, static_cast<void *>(&context1));
    UserAuthContext context2 = {};
    context2.contextId = 36529;
    g_contextList->insert(g_contextList, static_cast<void *>(&context2));
    g_contextList->insert(g_contextList, nullptr);
    EXPECT_TRUE(IsContextDuplicate(contextId));
}

HWTEST_F(ContextManagerTest, TestCopySchedules_001, TestSize.Level0)
{
    EXPECT_EQ(CopySchedules(nullptr, nullptr), RESULT_BAD_PARAM);
    UserAuthContext context = {};
    context.scheduleList = nullptr;
    EXPECT_EQ(CopySchedules(&context, nullptr), RESULT_BAD_PARAM);
    context.scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(context.scheduleList, nullptr);
    EXPECT_EQ(CopySchedules(&context, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(ContextManagerTest, TestCopySchedules_002, TestSize.Level0)
{
    UserAuthContext context = {};
    context.scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(context.scheduleList, nullptr);
    uint32_t scheduleNum = 6;
    CoAuthSchedule schedule = {};
    for (uint32_t i = 0; i < scheduleNum; ++i) {
        context.scheduleList->insert(context.scheduleList, static_cast<void *>(&schedule));
    }
    LinkedList *getSchedule = nullptr;
    EXPECT_EQ(CopySchedules(&context, &getSchedule), RESULT_UNKNOWN);
}

HWTEST_F(ContextManagerTest, TestCopySchedules_003, TestSize.Level0)
{
    UserAuthContext context = {};
    context.scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(context.scheduleList, nullptr);
    LinkedList *getSchedule = nullptr;
    EXPECT_EQ(CopySchedules(&context, &getSchedule), RESULT_SUCCESS);
}

HWTEST_F(ContextManagerTest, TestCopySchedules_004, TestSize.Level0)
{
    UserAuthContext context = {};
    context.scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(context.scheduleList, nullptr);
    context.scheduleList->insert(context.scheduleList, nullptr);
    LinkedList *getSchedule = nullptr;
    EXPECT_EQ(CopySchedules(&context, &getSchedule), RESULT_GENERAL_ERROR);
}

HWTEST_F(ContextManagerTest, TestCopySchedules_005, TestSize.Level0)
{
    UserAuthContext context = {};
    context.scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(context.scheduleList, nullptr);
    CoAuthSchedule schedule = {};
    schedule.templateIds.num = 12;
    context.scheduleList->insert(context.scheduleList, static_cast<void *>(&schedule));
    LinkedList *getSchedule = nullptr;
    EXPECT_EQ(CopySchedules(&context, &getSchedule), RESULT_GENERAL_ERROR);
}

HWTEST_F(ContextManagerTest, TestMatchSchedule, TestSize.Level0)
{
    EXPECT_FALSE(MatchSchedule(nullptr, nullptr));
    CoAuthSchedule schedule = {};
    EXPECT_FALSE(MatchSchedule(static_cast<void *>(&schedule), nullptr));
    schedule.scheduleId = 10;
    uint64_t condition = 20;
    EXPECT_FALSE(MatchSchedule(static_cast<void *>(&schedule), static_cast<void *>(&condition)));
}

HWTEST_F(ContextManagerTest, TestScheduleOnceFinish, TestSize.Level0)
{
    uint64_t scheduleId = 10;
    EXPECT_EQ(ScheduleOnceFinish(nullptr, scheduleId), RESULT_BAD_PARAM);
    UserAuthContext context = {};
    context.scheduleList = nullptr;
    EXPECT_EQ(ScheduleOnceFinish(&context, scheduleId), RESULT_BAD_PARAM);
}

HWTEST_F(ContextManagerTest, TestDestoryContext, TestSize.Level0)
{
    DestoryContext(nullptr);
    UserAuthContext context = {};
    g_contextList = nullptr;
    DestoryContext(&context);
}

HWTEST_F(ContextManagerTest, TestDestroyContextNode, TestSize.Level0)
{
    DestroyContextNode(nullptr);
    UserAuthContext context = {};
    context.scheduleList = nullptr;
    DestroyContextNode(nullptr);
    context.scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(context.scheduleList, nullptr);
    context.scheduleList->insert(context.scheduleList, nullptr);
    DestroyContextNode(nullptr);
}

HWTEST_F(ContextManagerTest, TestFillInContext_001, TestSize.Level0)
{
    EXPECT_EQ(FillInContext(nullptr, nullptr, nullptr), RESULT_BAD_PARAM);
    g_scheduleList = nullptr;
    UserAuthContext context = {};
    uint64_t credentialId = 10;
    ExecutorResultInfo info = {};
    info.scheduleId = 2135;
    EXPECT_EQ(FillInContext(&context, &credentialId, &info), RESULT_GENERAL_ERROR);
}

HWTEST_F(ContextManagerTest, TestFillInContext_002, TestSize.Level0)
{
    g_scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(g_scheduleList, nullptr);
    CoAuthSchedule schedule = {};
    schedule.scheduleId = 2135;
    schedule.executorSize = 0;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule));

    UserAuthContext context = {};
    uint64_t credentialId = 10;
    ExecutorResultInfo info = {};
    info.scheduleId = 2135;
    EXPECT_EQ(FillInContext(&context, &credentialId, &info), RESULT_BAD_PARAM);
}

HWTEST_F(ContextManagerTest, TestFillInContext_003, TestSize.Level0)
{
    g_scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(g_scheduleList, nullptr);
    CoAuthSchedule schedule = {};
    schedule.scheduleId = 2135;
    schedule.executorSize = 1;
    ExecutorInfoHal executorInfo = {};
    executorInfo.authType = 1;
    executorInfo.esl = 2;
    executorInfo.executorSensorHint = 10;
    executorInfo.executorRole = ALL_IN_ONE;
    schedule.executors[0] = executorInfo;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule));

    g_userInfoList = nullptr;

    UserAuthContext context = {};
    uint64_t credentialId = 10;
    ExecutorResultInfo info = {};
    info.scheduleId = 2135;
    EXPECT_EQ(FillInContext(&context, &credentialId, &info), RESULT_UNKNOWN);
}

HWTEST_F(ContextManagerTest, TestFillInContext_004, TestSize.Level0)
{
    g_scheduleList = CreateLinkedList(DestroyScheduleNode);
    EXPECT_NE(g_scheduleList, nullptr);
    CoAuthSchedule schedule = {};
    schedule.scheduleId = 2135;
    schedule.executorSize = 1;
    ExecutorInfoHal executorInfo = {};
    executorInfo.authType = 1;
    executorInfo.esl = 2;
    executorInfo.executorSensorHint = 10;
    executorInfo.executorRole = ALL_IN_ONE;
    schedule.executors[0] = executorInfo;
    g_scheduleList->insert(g_scheduleList, static_cast<void *>(&schedule));

    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo userInfo = {};
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.authType = 2;
    credInfo.templateId = 20;
    credInfo.executorSensorHint = 10;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));

    UserAuthContext context = {};
    context.authType = 2;
    uint64_t credentialId = 10;
    ExecutorResultInfo info = {};
    info.scheduleId = 2135;
    info.templateId = 20;
    EXPECT_EQ(FillInContext(&context, &credentialId, &info), RESULT_UNKNOWN);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
