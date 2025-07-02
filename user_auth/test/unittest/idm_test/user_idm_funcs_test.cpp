/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "adaptor_time.h"
#include "buffer.h"
#include "coauth.h"
#include "defines.h"
#include "executor_message.h"
#include "idm_database.h"
#include "idm_session.h"
#include "pool.h"
#include "user_idm_funcs.h"
#include "udid_manager.h"

extern "C" {
    extern struct SessionInfo {
        int32_t userId;
        uint32_t authType;
        uint64_t time;
        uint64_t validAuthTokenTime;
        uint8_t challenge[CHALLENGE_LEN];
        uint64_t scheduleId;
        ScheduleType scheduleType;
        bool isScheduleValid;
        PinChangeScence pinChangeScence;
        Buffer *oldRootSecret;
        Buffer *curRootSecret;
        Buffer *newRootSecret;
    } *g_session;
    extern LinkedList *g_poolList;
    extern LinkedList *g_userInfoList;
    extern LinkedList *g_scheduleList;
    extern CoAuthSchedule *GenerateIdmSchedule(const PermissionCheckParam *param, ScheduleType scheduleType);
    extern int32_t GetCredentialInfoFromSchedule(const ExecutorResultInfo *executorInfo,
        CredentialInfoHal *credentialInfo, const CoAuthSchedule *schedule);
    extern int32_t GetDeletedCredential(int32_t userId, CredentialInfoHal *deletedCredential);
    extern int32_t CheckResultValid(uint64_t scheduleId, int32_t userId);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class UserIdmFuncsTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(UserIdmFuncsTest, TestGenerateIdmSchedule_001, TestSize.Level0)
{
    PermissionCheckParam param = {};
    constexpr uint32_t executorSensorHint = 10;
    param.executorSensorHint = executorSensorHint;
    ScheduleType scheduleType = SCHEDULE_TYPE_ENROLL;
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
}

HWTEST_F(UserIdmFuncsTest, TestGenerateIdmSchedule_002, TestSize.Level0)
{
    InitResourcePool();
    EXPECT_NE(g_poolList, nullptr);
    constexpr uint32_t executorSensorHint = 10;
    ExecutorInfoHal *info = static_cast<ExecutorInfoHal *>(malloc(sizeof(ExecutorInfoHal)));
    EXPECT_NE(info, nullptr);
    info->authType = PIN_AUTH;
    info->executorSensorHint = executorSensorHint;
    info->executorRole = COLLECTOR;
    g_poolList->insert(g_poolList, static_cast<void *>(info));
    PermissionCheckParam param = {};
    param.authType = PIN_AUTH;
    param.executorSensorHint = executorSensorHint;
    ScheduleType scheduleType = SCHEDULE_TYPE_ENROLL;
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    DestroyResourcePool();
}

HWTEST_F(UserIdmFuncsTest, TestGenerateIdmSchedule_003, TestSize.Level0)
{
    LOG_INFO("TestGenerateIdmSchedule_003 start");
    PermissionCheckParam param = {};
    constexpr uint32_t executorSensorHint = 0;
    constexpr int32_t userId = 1;
    param.userId = userId;
    param.authType = PIN_AUTH;
    param.executorSensorHint = executorSensorHint;
    ScheduleType scheduleType = SCHEDULE_TYPE_UPDATE;
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    param.executorSensorHint = INVALID_SENSOR_HINT;
    static char udid[UDID_LEN + 1] = "0123456789012345678901234567890123456789012345678901234567890123";
    SetLocalUdid(udid);
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo *userInfo = static_cast<UserInfo *>(malloc(sizeof(UserInfo)));
    EXPECT_NE(userInfo, nullptr);
    userInfo->userId = userId;
    userInfo->credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo->enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(userInfo));
    CredentialInfoHal *credentialInfo = static_cast<CredentialInfoHal *>(malloc(sizeof(CredentialInfoHal)));
    EXPECT_NE(credentialInfo, nullptr);
    credentialInfo->credentialId = 1;
    credentialInfo->templateId = 1;
    credentialInfo->authType = PIN_AUTH;
    credentialInfo->isAbandoned = false;
    userInfo->credentialInfoList->insert(userInfo->credentialInfoList, static_cast<void *>(credentialInfo));
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    InitResourcePool();
    InitCoAuth();
    ExecutorInfoHal *info = static_cast<ExecutorInfoHal *>(malloc(sizeof(ExecutorInfoHal)));
    EXPECT_NE(info, nullptr);
    info->authType = PIN_AUTH;
    info->executorSensorHint = executorSensorHint;
    info->executorRole = ALL_IN_ONE;
    memcpy_s(info->deviceUdid, UDID_LEN, udid, UDID_LEN);
    g_poolList->insert(g_poolList, static_cast<void *>(info));
    EXPECT_NE(GenerateIdmSchedule(&param, scheduleType), nullptr);
    DestroyResourcePool();
    DestoryCoAuth();
    LOG_INFO("TestGenerateIdmSchedule_003 end");
}

HWTEST_F(UserIdmFuncsTest, TestGenerateIdmSchedule_004, TestSize.Level0)
{
    LOG_INFO("TestGenerateIdmSchedule_004 start");
    InitResourcePool();
    EXPECT_NE(g_poolList, nullptr);
    constexpr uint32_t executorSensorHint = 0;
    ExecutorInfoHal *info = static_cast<ExecutorInfoHal *>(malloc(sizeof(ExecutorInfoHal)));
    EXPECT_NE(info, nullptr);
    info->authType = PIN_AUTH;
    info->executorSensorHint = executorSensorHint;
    info->executorRole = ALL_IN_ONE;
    g_poolList->insert(g_poolList, static_cast<void *>(info));
    PermissionCheckParam param = {};
    param.authType = PIN_AUTH;
    param.executorSensorHint = executorSensorHint;
    ScheduleType scheduleType = SCHEDULE_TYPE_UPDATE;
    static char udid[UDID_LEN + 1] = "0123456789012345678901234567890123456789012345678901234567890123";
    SetLocalUdid(udid);
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    DestroyResourcePool();
    LOG_INFO("TestGenerateIdmSchedule_004 end");
}

static void TestInitUserInfoList()
{
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    UserInfo *userInfo = static_cast<UserInfo *>(malloc(sizeof(UserInfo)));
    EXPECT_NE(userInfo, nullptr);
    userInfo->userId = 1;
    userInfo->credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo->enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(userInfo));
    CredentialInfoHal *credentialInfo = static_cast<CredentialInfoHal *>(malloc(sizeof(CredentialInfoHal)));
    EXPECT_NE(credentialInfo, nullptr);
    credentialInfo->credentialId = 1;
    credentialInfo->templateId = 1;
    credentialInfo->authType = PIN_AUTH;
    credentialInfo->isAbandoned = false;
    userInfo->credentialInfoList->insert(userInfo->credentialInfoList, static_cast<void *>(credentialInfo));
}

HWTEST_F(UserIdmFuncsTest, TestGenerateIdmSchedule_005, TestSize.Level0)
{
    LOG_INFO("TestGenerateIdmSchedule_005 start");
    PermissionCheckParam param = {};
    constexpr uint32_t executorSensorHint = 10;
    constexpr int32_t userId = 1;
    param.userId = userId;
    param.authType = PIN_AUTH;
    param.executorSensorHint = executorSensorHint;
    ScheduleType scheduleType = SCHEDULE_TYPE_ABANDON;
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    param.executorSensorHint = INVALID_SENSOR_HINT;
    static char udid[UDID_LEN + 1] = "0123456789012345678901234567890123456789012345678901234567890123";
    SetLocalUdid(udid);
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    TestInitUserInfoList();
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    InitResourcePool();
    InitCoAuth();
    ExecutorInfoHal *info = static_cast<ExecutorInfoHal *>(malloc(sizeof(ExecutorInfoHal)));
    EXPECT_NE(info, nullptr);
    info->authType = PIN_AUTH;
    info->executorSensorHint = executorSensorHint;
    info->executorRole = ALL_IN_ONE;
    memcpy_s(info->deviceUdid, UDID_LEN, udid, UDID_LEN);
    g_poolList->insert(g_poolList, static_cast<void *>(info));
    struct SessionInfo session = {};
    session.userId = userId;
    session.isScheduleValid = true;
    session.scheduleId = 10;
    session.authType = PIN_AUTH;
    session.time = GetSystemTime();
    session.pinChangeScence = PIN_UPDATE_SCENCE;
    g_session = &session;
    EXPECT_NE(GenerateIdmSchedule(&param, scheduleType), nullptr);
    DestroyResourcePool();
    DestoryCoAuth();
    g_session = nullptr;
    LOG_INFO("TestGenerateIdmSchedule_005 end");
}

HWTEST_F(UserIdmFuncsTest, TestGenerateIdmSchedule_006, TestSize.Level0)
{
    LOG_INFO("TestGenerateIdmSchedule_006 start");
    PermissionCheckParam param = {};
    constexpr uint32_t executorSensorHint = 10;
    constexpr int32_t userId = 1;
    param.userId = userId;
    param.authType = PIN_AUTH;
    param.executorSensorHint = executorSensorHint;
    ScheduleType scheduleType = SCHEDULE_TYPE_ABANDON;
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    param.executorSensorHint = INVALID_SENSOR_HINT;
    static char udid[UDID_LEN + 1] = "0123456789012345678901234567890123456789012345678901234567890123";
    SetLocalUdid(udid);
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    TestInitUserInfoList();
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    InitResourcePool();
    InitCoAuth();
    ExecutorInfoHal *info = static_cast<ExecutorInfoHal *>(malloc(sizeof(ExecutorInfoHal)));
    EXPECT_NE(info, nullptr);
    info->authType = PIN_AUTH;
    info->executorSensorHint = executorSensorHint;
    info->executorRole = ALL_IN_ONE;
    memcpy_s(info->deviceUdid, UDID_LEN, udid, UDID_LEN);
    g_poolList->insert(g_poolList, static_cast<void *>(info));
    struct SessionInfo session = {};
    session.userId = userId;
    session.isScheduleValid = true;
    session.scheduleId = 10;
    session.authType = PIN_AUTH;
    session.time = GetSystemTime();
    session.pinChangeScence = PIN_RESET_SCENCE;
    g_session = &session;
    EXPECT_NE(GenerateIdmSchedule(&param, scheduleType), nullptr);
    DestroyResourcePool();
    DestoryCoAuth();
    g_session = nullptr;
    LOG_INFO("TestGenerateIdmSchedule_006 end");
}

HWTEST_F(UserIdmFuncsTest, TestGenerateIdmSchedule_007, TestSize.Level0)
{
    LOG_INFO("TestGenerateIdmSchedule_006 start");
    InitResourcePool();
    EXPECT_NE(g_poolList, nullptr);
    constexpr uint32_t executorSensorHint = 10;
    ExecutorInfoHal *info = static_cast<ExecutorInfoHal *>(malloc(sizeof(ExecutorInfoHal)));
    EXPECT_NE(info, nullptr);
    info->authType = PIN_AUTH;
    info->executorSensorHint = executorSensorHint;
    info->executorRole = ALL_IN_ONE;
    g_poolList->insert(g_poolList, static_cast<void *>(info));
    PermissionCheckParam param = {};
    param.authType = PIN_AUTH;
    param.executorSensorHint = executorSensorHint;
    ScheduleType scheduleType = SCHEDULE_TYPE_ABANDON;
    static char udid[UDID_LEN + 1] = "0123456789012345678901234567890123456789012345678901234567890123";
    SetLocalUdid(udid);
    EXPECT_EQ(GenerateIdmSchedule(&param, scheduleType), nullptr);
    DestroyResourcePool();
    LOG_INFO("TestGenerateIdmSchedule_006 start");
}

HWTEST_F(UserIdmFuncsTest, TestCheckEnrollPermission_001, TestSize.Level0)
{
    PermissionCheckParam param = {};
    EXPECT_EQ(CheckEnrollPermission(&param), RESULT_NEED_INIT);
}

HWTEST_F(UserIdmFuncsTest, TestCheckEnrollPermission_002, TestSize.Level0)
{
    constexpr int32_t userId = 32156;
    struct SessionInfo session = {};
    session.userId = userId;
    session.time = GetSystemTime();
    g_session = &session;

    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    PermissionCheckParam param = {};
    param.authType = FACE_AUTH;
    EXPECT_EQ(CheckEnrollPermission(&param), RESULT_GENERAL_ERROR);
    param.userId = userId;
    EXPECT_EQ(CheckEnrollPermission(&param), RESULT_VERIFY_TOKEN_FAIL);
    DestroyLinkedList(g_userInfoList);
    g_userInfoList = nullptr;
    g_session = nullptr;
}

HWTEST_F(UserIdmFuncsTest, TestCheckUpdatePermission_001, TestSize.Level0)
{
    PermissionCheckParam param = {};
    param.authType = FACE_AUTH;
    EXPECT_EQ(CheckUpdatePermission(&param), RESULT_BAD_PARAM);
    param.authType = PIN_AUTH;
    EXPECT_EQ(CheckUpdatePermission(&param), RESULT_NEED_INIT);
}

HWTEST_F(UserIdmFuncsTest, TestCheckUpdatePermission_002, TestSize.Level0)
{
    constexpr int32_t userId = 32156;
    constexpr uint32_t excutorSensorHint1 = 10;
    constexpr uint32_t excutorSensorHint2 = 20;
    struct SessionInfo session = {};
    session.userId = userId;
    session.time = GetSystemTime();
    g_session = &session;
    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);

    PermissionCheckParam param = {};
    param.authType = PIN_AUTH;
    param.userId = userId;
    EXPECT_EQ(CheckUpdatePermission(&param), RESULT_SUCCESS);
    UserInfo *userInfo = static_cast<UserInfo *>(malloc(sizeof(UserInfo)));
    EXPECT_NE(userInfo, nullptr);
    userInfo->userId = userId;
    userInfo->credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo->enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(userInfo->credentialInfoList, nullptr);
    CredentialInfoHal *credInfo = static_cast<CredentialInfoHal *>(malloc(sizeof(CredentialInfoHal)));
    EXPECT_NE(credInfo, nullptr);
    credInfo->authType = PIN_AUTH;
    credInfo->executorSensorHint = excutorSensorHint2;
    credInfo->isAbandoned = false;
    userInfo->credentialInfoList->insert(userInfo->credentialInfoList, static_cast<void *>(credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(userInfo));
    param.executorSensorHint = excutorSensorHint1;
    EXPECT_EQ(CheckUpdatePermission(&param), RESULT_VERIFY_TOKEN_FAIL);
    DestroyUserInfoList();
    g_session = nullptr;
}

HWTEST_F(UserIdmFuncsTest, TestGetCredentialInfoFromSchedule, TestSize.Level0)
{
    g_session = nullptr;
    ExecutorResultInfo resultInfo = {};
    CredentialInfoHal credInfo = {};
    CoAuthSchedule scheduleInfo = {};
    EXPECT_EQ(GetCredentialInfoFromSchedule(&resultInfo, &credInfo, &scheduleInfo), RESULT_GENERAL_ERROR);

    constexpr int32_t userId = 32158;
    struct SessionInfo session = {};
    session.userId = userId;
    session.isScheduleValid = true;
    session.scheduleId = 10;
    session.authType = FACE_AUTH;
    session.time = UINT64_MAX;
    g_session = &session;

    resultInfo.scheduleId = 311157;
    EXPECT_EQ(GetCredentialInfoFromSchedule(&resultInfo, &credInfo, &scheduleInfo), RESULT_GENERAL_ERROR);
    resultInfo.scheduleId = 10;
    EXPECT_EQ(GetCredentialInfoFromSchedule(&resultInfo, &credInfo, &scheduleInfo), RESULT_GENERAL_ERROR);

    session.time = GetSystemTime();
    g_scheduleList = nullptr;
    EXPECT_EQ(GetCredentialInfoFromSchedule(&resultInfo, &credInfo, &scheduleInfo), RESULT_SUCCESS);
    g_session = nullptr;
}

HWTEST_F(UserIdmFuncsTest, TestAddCredentialFunc, TestSize.Level0)
{
    constexpr int32_t userId1 = 21345;
    constexpr int32_t userId2 = 1122;
    EXPECT_EQ(AddCredentialFunc(userId1, nullptr, nullptr, nullptr, nullptr), RESULT_BAD_PARAM);
    Buffer *scheduleResult = CreateBufferBySize(20);
    uint64_t credentialId = 0;
    Buffer *rootSecret = nullptr;
    Buffer *authToken = nullptr;
    EXPECT_EQ(AddCredentialFunc(userId1, scheduleResult, &credentialId, &rootSecret, &authToken), RESULT_UNKNOWN);
    struct SessionInfo session = {};
    session.userId = userId2;
    g_session = &session;
    EXPECT_EQ(AddCredentialFunc(userId1, scheduleResult, &credentialId, &rootSecret, &authToken), RESULT_UNKNOWN);
    g_session = nullptr;
}

HWTEST_F(UserIdmFuncsTest, TestDeleteCredentialFunc, TestSize.Level0)
{
    CredentialDeleteParam param = {};
    EXPECT_EQ(DeleteCredentialFunc(param, nullptr), RESULT_BAD_PARAM);

    OperateResult operateResult = {};
    UserAuthTokenHal token = {};
    token.tokenDataPlain.authType = 4;
    EXPECT_EQ(memcpy_s(param.token, sizeof(UserAuthTokenHal), &token, sizeof(UserAuthTokenHal)), EOK);
    EXPECT_EQ(DeleteCredentialFunc(param, &operateResult), RESULT_VERIFY_TOKEN_FAIL);
}

HWTEST_F(UserIdmFuncsTest, TestQueryCredentialFunc, TestSize.Level0)
{
    EXPECT_EQ(QueryCredentialFunc(0, 0, nullptr), RESULT_BAD_PARAM);
    LinkedList *creds = nullptr;
    g_userInfoList = nullptr;
    EXPECT_EQ(QueryCredentialFunc(0, 0, &creds), RESULT_UNKNOWN);
}

HWTEST_F(UserIdmFuncsTest, TestGetUserInfoFunc, TestSize.Level0)
{
    EXPECT_EQ(GetUserInfoFunc(0, nullptr, nullptr, nullptr, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(UserIdmFuncsTest, TestGetDeletedCredential, TestSize.Level0)
{
    g_userInfoList = nullptr;
    constexpr int32_t userId = 2156;
    CredentialInfoHal deletedCredInfo = {};
    EXPECT_EQ(GetDeletedCredential(userId, &deletedCredInfo), RESULT_UNKNOWN);

    g_userInfoList = CreateLinkedList(DestroyUserInfoNode);
    EXPECT_NE(g_userInfoList, nullptr);
    EXPECT_EQ(GetDeletedCredential(userId, &deletedCredInfo), RESULT_UNKNOWN);

    UserInfo *userInfo = static_cast<UserInfo *>(malloc(sizeof(UserInfo)));
    EXPECT_NE(userInfo, nullptr);
    userInfo->userId = userId;
    userInfo->credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    userInfo->enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    EXPECT_NE(userInfo->credentialInfoList, nullptr);
    CredentialInfoHal *credInfo = static_cast<CredentialInfoHal *>(malloc(sizeof(CredentialInfoHal)));
    EXPECT_NE(credInfo, nullptr);
    credInfo->authType = 1;
    credInfo->isAbandoned = false;
    userInfo->credentialInfoList->insert(userInfo->credentialInfoList, static_cast<void *>(credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(userInfo));
    EXPECT_EQ(GetDeletedCredential(userId, &deletedCredInfo), RESULT_SUCCESS);
    DestroyUserInfoList();
}

HWTEST_F(UserIdmFuncsTest, TestCheckResultValid, TestSize.Level0)
{
    g_session = nullptr;
    constexpr uint64_t scheduleId = 10;
    constexpr int32_t userId = 2112;
    EXPECT_EQ(CheckResultValid(scheduleId, userId), RESULT_GENERAL_ERROR);

    struct SessionInfo session = {};
    session.userId = 1122;
    session.scheduleId = 20;
    session.authType = FACE_AUTH;
    session.isScheduleValid = true;
    session.time = UINT64_MAX;
    g_session = &session;
    EXPECT_EQ(CheckResultValid(scheduleId, userId), RESULT_GENERAL_ERROR);

    session.scheduleId = scheduleId;
    EXPECT_EQ(CheckResultValid(scheduleId, userId), RESULT_GENERAL_ERROR);

    session.time = GetSystemTime();
    EXPECT_EQ(CheckResultValid(scheduleId, userId), RESULT_REACH_LIMIT);

    session.userId = userId;
    EXPECT_EQ(CheckResultValid(scheduleId, userId), RESULT_UNKNOWN);
}

HWTEST_F(UserIdmFuncsTest, TestUpdateCredentialFunc, TestSize.Level0)
{
    EXPECT_EQ(UpdateCredentialFunc(0, nullptr, nullptr), RESULT_BAD_PARAM);

    constexpr uint32_t bufferSize = 10;
    Buffer *scheduleResult = CreateBufferBySize(bufferSize);
    UpdateCredentialOutput output = {};
    EXPECT_EQ(UpdateCredentialFunc(0, scheduleResult, &output), RESULT_UNKNOWN);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
