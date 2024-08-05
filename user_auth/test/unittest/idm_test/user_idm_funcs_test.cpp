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

extern "C" {
    extern struct SessionInfo {
        int32_t userId;
        uint32_t authType;
        uint64_t time;
        uint64_t validAuthTokenTime;
        uint8_t challenge[CHALLENGE_LEN];
        uint64_t scheduleId;
        bool isUpdate;
        bool isScheduleValid;
    } *g_session;
    extern LinkedList *g_poolList;
    extern LinkedList *g_userInfoList;
    extern LinkedList *g_scheduleList;
    extern CoAuthSchedule *GenerateIdmSchedule(const PermissionCheckParam *param);
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
    EXPECT_EQ(GenerateIdmSchedule(&param), nullptr);
}

HWTEST_F(UserIdmFuncsTest, TestGenerateIdmSchedule_002, TestSize.Level0)
{
    InitResourcePool();
    EXPECT_NE(g_poolList, nullptr);
    constexpr uint32_t executorSensorHint = 10;
    ExecutorInfoHal info = {};
    info.authType = PIN_AUTH;
    info.executorSensorHint = executorSensorHint;
    info.executorRole = COLLECTOR;
    g_poolList->insert(g_poolList, static_cast<void *>(&info));
    PermissionCheckParam param = {};
    param.authType = PIN_AUTH;
    param.executorSensorHint = executorSensorHint;
    EXPECT_EQ(GenerateIdmSchedule(&param), nullptr);
    g_poolList = nullptr;
}

HWTEST_F(UserIdmFuncsTest, TestCheckEnrollPermission_001, TestSize.Level0)
{
    PermissionCheckParam param = {};
    EXPECT_EQ(CheckEnrollPermission(param, nullptr), RESULT_BAD_PARAM);
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
    uint64_t scheduleId = 0;
    EXPECT_EQ(CheckEnrollPermission(param, &scheduleId), RESULT_GENERAL_ERROR);
    param.userId = userId;
    EXPECT_EQ(CheckEnrollPermission(param, &scheduleId), RESULT_VERIFY_TOKEN_FAIL);
    DestroyLinkedList(g_userInfoList);
    g_userInfoList = nullptr;
    g_session = nullptr;
}

HWTEST_F(UserIdmFuncsTest, TestCheckUpdatePermission_001, TestSize.Level0)
{
    PermissionCheckParam param = {};
    param.authType = FACE_AUTH;
    EXPECT_EQ(CheckUpdatePermission(param, nullptr), RESULT_BAD_PARAM);
    uint64_t scheduleId = 0;
    EXPECT_EQ(CheckUpdatePermission(param, &scheduleId), RESULT_BAD_PARAM);
    param.authType = PIN_AUTH;
    EXPECT_EQ(CheckUpdatePermission(param, &scheduleId), RESULT_NEED_INIT);
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
    uint64_t scheduleId = 0;
    EXPECT_EQ(CheckUpdatePermission(param, &scheduleId), RESULT_SUCCESS);
    UserInfo userInfo = {};
    userInfo.userId = userId;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.authType = PIN_AUTH;
    credInfo.executorSensorHint = excutorSensorHint2;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    param.executorSensorHint = excutorSensorHint1;
    EXPECT_EQ(CheckUpdatePermission(param, &scheduleId), RESULT_VERIFY_TOKEN_FAIL);
    g_userInfoList = nullptr;
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

    CredentialInfoHal credInfo = {};
    UserAuthTokenHal token = {};
    token.tokenDataPlain.authType = 4;
    EXPECT_EQ(memcpy_s(param.token, sizeof(UserAuthTokenHal), &token, sizeof(UserAuthTokenHal)), EOK);
    EXPECT_EQ(DeleteCredentialFunc(param, &credInfo), RESULT_VERIFY_TOKEN_FAIL);
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

    UserInfo userInfo = {};
    userInfo.userId = userId;
    userInfo.credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    EXPECT_NE(userInfo.credentialInfoList, nullptr);
    CredentialInfoHal credInfo = {};
    credInfo.authType = 1;
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    userInfo.credentialInfoList->insert(userInfo.credentialInfoList, static_cast<void *>(&credInfo));
    g_userInfoList->insert(g_userInfoList, static_cast<void *>(&userInfo));
    EXPECT_EQ(GetDeletedCredential(userId, &deletedCredInfo), RESULT_UNKNOWN);
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
