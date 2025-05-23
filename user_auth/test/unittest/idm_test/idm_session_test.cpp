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

#include "adaptor_time.h"
#include "defines.h"
#include "idm_session.h"

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
    extern ResultCode GenerateChallenge(uint8_t *challenge, uint32_t challengeLen);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class IdmSessionTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(IdmSessionTest, TestOpenEditSession, TestSize.Level0)
{
    EXPECT_EQ(OpenEditSession(0, nullptr, 0), RESULT_BAD_PARAM);
}

HWTEST_F(IdmSessionTest, TestRefreshValidTokenTime, TestSize.Level0)
{
    g_session = nullptr;
    RefreshValidTokenTime();
    struct SessionInfo session = {};
    g_session = &session;
    RefreshValidTokenTime();
    EXPECT_LE(g_session->validAuthTokenTime, GetSystemTime());
    g_session = nullptr;
}

HWTEST_F(IdmSessionTest, TestIsValidTokenTime, TestSize.Level0)
{
    g_session = nullptr;
    EXPECT_FALSE(IsValidTokenTime(0));
}

HWTEST_F(IdmSessionTest, TestGetUserId, TestSize.Level0)
{
    g_session = nullptr;
    EXPECT_EQ(GetUserId(nullptr), RESULT_BAD_PARAM);
    int32_t userId = 0;
    EXPECT_EQ(GetUserId(&userId), RESULT_BAD_PARAM);
}

HWTEST_F(IdmSessionTest, TestCheckChallenge_001, TestSize.Level0)
{
    g_session = nullptr;
    EXPECT_EQ(CheckChallenge(nullptr, 0), RESULT_BAD_PARAM);
    uint8_t challenge = 0;
    EXPECT_EQ(CheckChallenge(&challenge, 0), RESULT_BAD_PARAM);
    EXPECT_EQ(CheckChallenge(&challenge, CHALLENGE_LEN), RESULT_NEED_INIT);
}

HWTEST_F(IdmSessionTest, TestCheckChallenge_002, TestSize.Level0)
{
    uint8_t challenge[CHALLENGE_LEN];
    EXPECT_EQ(memset_s(challenge, CHALLENGE_LEN, 0, CHALLENGE_LEN), EOK);
    struct SessionInfo session;
    EXPECT_EQ(GenerateChallenge(session.challenge, CHALLENGE_LEN), RESULT_SUCCESS);
    g_session = &session;
    EXPECT_EQ(CheckChallenge(challenge, CHALLENGE_LEN), RESULT_BAD_MATCH);
    g_session = nullptr;
}

HWTEST_F(IdmSessionTest, TestAssociateCoauthSchedule, TestSize.Level0)
{
    g_session = nullptr;
    EXPECT_EQ(AssociateCoauthSchedule(0, 0, SCHEDULE_TYPE_ENROLL), RESULT_NEED_INIT);
}

HWTEST_F(IdmSessionTest, TestGetEnrollScheduleInfo_001, TestSize.Level0)
{
    EXPECT_EQ(GetEnrollScheduleInfo(nullptr, nullptr), RESULT_BAD_PARAM);
    uint64_t scheduleId = 0;
    EXPECT_EQ(GetEnrollScheduleInfo(&scheduleId, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmSessionTest, TestGetEnrollScheduleInfo_002, TestSize.Level0)
{
    g_session = nullptr;
    uint64_t scheduleId = 0;
    uint32_t authType = 1;
    EXPECT_EQ(GetEnrollScheduleInfo(&scheduleId, &authType), RESULT_NEED_INIT);
    struct SessionInfo session;
    session.isScheduleValid = false;
    g_session = &session;
    EXPECT_EQ(GetEnrollScheduleInfo(&scheduleId, &authType), RESULT_NEED_INIT);
    session.isScheduleValid = true;
    EXPECT_EQ(GetEnrollScheduleInfo(&scheduleId, &authType), RESULT_SUCCESS);
    g_session = nullptr;
}

HWTEST_F(IdmSessionTest, TestCheckSessionTimeout, TestSize.Level0)
{
    g_session = nullptr;
    EXPECT_EQ(CheckSessionTimeout(), RESULT_NEED_INIT);
    struct SessionInfo session;
    session.time = UINT64_MAX;
    g_session = &session;
    EXPECT_EQ(CheckSessionTimeout(), RESULT_GENERAL_ERROR);
    g_session = nullptr;
}

HWTEST_F(IdmSessionTest, TestGetScheduleType, TestSize.Level0)
{
    EXPECT_EQ(GetScheduleType(nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdmSessionTest, TestCheckSessionValid, TestSize.Level0)
{
    struct SessionInfo session;
    constexpr int32_t userId = 2135;
    session.userId = userId;
    session.time = UINT64_MAX;
    g_session = &session;
    EXPECT_EQ(CheckSessionValid(0), RESULT_GENERAL_ERROR);
    session.time = GetSystemTime();
    EXPECT_EQ(CheckSessionValid(0), RESULT_GENERAL_ERROR);
    g_session = nullptr;
}

HWTEST_F(IdmSessionTest, TestGetChallenge, TestSize.Level0)
{
    constexpr uint32_t arrayLen = 32;
    uint8_t challengeArray[arrayLen] = {};
    EXPECT_EQ(GetChallenge(nullptr, 0), RESULT_BAD_PARAM);
    EXPECT_EQ(GetChallenge(nullptr, arrayLen), RESULT_BAD_PARAM);
    EXPECT_EQ(GetChallenge(challengeArray, arrayLen), RESULT_NEED_INIT);
}

HWTEST_F(IdmSessionTest, TestGetCurRootSecret, TestSize.Level0)
{
    LOG_INFO("start");
    struct SessionInfo session;
    constexpr int32_t userId = 1;
    session.userId = userId;
    session.time = GetSystemTime();
    session.oldRootSecret = nullptr;
    session.curRootSecret = nullptr;
    session.newRootSecret = nullptr;
    g_session = &session;
    Buffer *rootSecret = GetCurRootSecret(0);
    EXPECT_EQ(rootSecret, nullptr);
    rootSecret = GetCurRootSecret(userId);
    EXPECT_EQ(rootSecret, nullptr);
    g_session = NULL;
    LOG_INFO("end");
}

HWTEST_F(IdmSessionTest, TestSetCurRootSecret, TestSize.Level0)
{
    LOG_INFO("start");
    struct SessionInfo session;
    constexpr int32_t userId = 1;
    session.userId = userId;
    session.time = GetSystemTime();
    session.oldRootSecret = nullptr;
    session.curRootSecret = nullptr;
    session.newRootSecret = nullptr;
    g_session = &session;
    SetCurRootSecret(0, nullptr);
    EXPECT_EQ(GetCurRootSecret(userId), nullptr);
    SetCurRootSecret(userId, nullptr);
    EXPECT_EQ(GetCurRootSecret(userId), nullptr);
    constexpr int32_t dataLen = 32;
    Buffer *test = CreateBufferBySize(dataLen);
    test->contentSize = dataLen;
    SetCurRootSecret(userId, test);
    EXPECT_NE(GetCurRootSecret(userId), nullptr);
    DestoryBuffer(test);
    g_session = NULL;
    LOG_INFO("end");
}

HWTEST_F(IdmSessionTest, TestIsValidUserType, TestSize.Level0)
{
    constexpr int32_t userType = 1024;
    EXPECT_EQ(IsValidUserType(userType), RESULT_BAD_PARAM);
}

HWTEST_F(IdmSessionTest, TestGetOldRootSecret, TestSize.Level0)
{
    LOG_INFO("start");
    struct SessionInfo session;
    constexpr int32_t userId = 1;
    session.userId = userId;
    session.time = GetSystemTime();
    session.oldRootSecret = nullptr;
    session.curRootSecret = nullptr;
    session.newRootSecret = nullptr;
    g_session = &session;
    Buffer *rootSecret = GetOldRootSecret(0);
    EXPECT_EQ(rootSecret, nullptr);
    rootSecret = GetOldRootSecret(userId);
    EXPECT_EQ(rootSecret, nullptr);
    g_session = NULL;
    LOG_INFO("end");
}

HWTEST_F(IdmSessionTest, TestSetOldRootSecret, TestSize.Level0)
{
    LOG_INFO("start");
    struct SessionInfo session;
    constexpr int32_t userId = 1;
    session.userId = userId;
    session.time = GetSystemTime();
    session.oldRootSecret = nullptr;
    session.curRootSecret = nullptr;
    session.newRootSecret = nullptr;
    g_session = &session;
    SetOldRootSecret(0, nullptr);
    EXPECT_EQ(GetOldRootSecret(userId), nullptr);
    SetOldRootSecret(userId, nullptr);
    EXPECT_EQ(GetOldRootSecret(userId), nullptr);
    constexpr int32_t dataLen = 32;
    Buffer *test = CreateBufferBySize(dataLen);
    test->contentSize = dataLen;
    SetOldRootSecret(userId, test);
    EXPECT_NE(GetOldRootSecret(userId), nullptr);
    DestoryBuffer(test);
    g_session = NULL;
    LOG_INFO("end");
}

HWTEST_F(IdmSessionTest, TestGetNewRootSecret, TestSize.Level0)
{
    LOG_INFO("start");
    struct SessionInfo session;
    constexpr int32_t userId = 1;
    session.userId = userId;
    session.time = GetSystemTime();
    session.oldRootSecret = nullptr;
    session.curRootSecret = nullptr;
    session.newRootSecret = nullptr;
    g_session = &session;
    Buffer *rootSecret = GetNewRootSecret(0);
    EXPECT_EQ(rootSecret, nullptr);
    rootSecret = GetNewRootSecret(userId);
    EXPECT_EQ(rootSecret, nullptr);
    g_session = NULL;
    LOG_INFO("end");
}

HWTEST_F(IdmSessionTest, TestSetNewRootSecret, TestSize.Level0)
{
    LOG_INFO("start");
    struct SessionInfo session;
    constexpr int32_t userId = 1;
    session.userId = userId;
    session.time = GetSystemTime();
    session.oldRootSecret = nullptr;
    session.curRootSecret = nullptr;
    session.newRootSecret = nullptr;
    g_session = &session;
    EXPECT_EQ(SetNewRootSecret(0, nullptr), RESULT_GENERAL_ERROR);
    EXPECT_EQ(GetNewRootSecret(userId), nullptr);
    EXPECT_EQ(SetNewRootSecret(userId, nullptr), RESULT_GENERAL_ERROR);
    EXPECT_EQ(GetNewRootSecret(userId), nullptr);
    constexpr int32_t dataLen = 32;
    Buffer *test = CreateBufferBySize(dataLen);
    test->contentSize = dataLen;
    EXPECT_EQ(SetNewRootSecret(userId, test), RESULT_SUCCESS);
    EXPECT_NE(GetNewRootSecret(userId), nullptr);
    DestoryBuffer(test);
    g_session = NULL;
    LOG_INFO("end");
}

HWTEST_F(IdmSessionTest, TestGetPinChangeScence, TestSize.Level0)
{
    LOG_INFO("start");
    struct SessionInfo session;
    constexpr int32_t userId = 2135;
    session.userId = userId;
    session.time = GetSystemTime();
    session.pinChangeScence = PIN_UPDATE_SCENCE;
    g_session = &session;
    PinChangeScence pinChangeScence = GetPinChangeScence(0);
    EXPECT_EQ(pinChangeScence, 0);
    pinChangeScence = GetPinChangeScence(userId);
    EXPECT_EQ(pinChangeScence, 0);
    g_session = NULL;
    LOG_INFO("end");
}

HWTEST_F(IdmSessionTest, TestSetPinChangeScence, TestSize.Level0)
{
    LOG_INFO("start");
    struct SessionInfo session;
    constexpr int32_t userId = 2135;
    session.userId = userId;
    session.time = GetSystemTime();
    session.pinChangeScence = PIN_UPDATE_SCENCE;
    session.authType = PIN_AUTH;
    g_session = &session;
    SetPinChangeScence(0, DEFUALT);
    SetPinChangeScence(userId, DEFUALT);
    PinChangeScence pinChangeScence = GetPinChangeScence(userId);
    EXPECT_EQ(pinChangeScence, PIN_UPDATE_SCENCE);
    SetPinChangeScence(userId, ABANDONED_PIN_AUTH);
    pinChangeScence = GetPinChangeScence(userId);
    EXPECT_EQ(pinChangeScence, PIN_RESET_SCENCE);
    g_session = NULL;
    LOG_INFO("end");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
