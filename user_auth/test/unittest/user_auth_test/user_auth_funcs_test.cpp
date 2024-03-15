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
#include <thread>

#include "adaptor_time.h"
#include "user_auth_funcs.h"

extern "C" {
    extern UnlockAuthResultCache g_unlockAuthResult;
    extern void SetUnlockAuthResult(int32_t userId, const UserAuthTokenHal *unlockToken,
        const EnrolledStateHal *enrolledState);
    extern ResultCode GetUnlockAuthResult(int32_t *userId, UserAuthTokenHal *token, EnrolledStateHal *enrolledState);
    extern int32_t SetAuthResult(int32_t userId, uint32_t authType, const ExecutorResultInfo *info, AuthResult *result);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class UserAuthFuncsTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(UserAuthFuncsTest, TestGenerateSolutionFunc, TestSize.Level0)
{
    AuthSolutionHal param = {};
    EXPECT_EQ(GenerateSolutionFunc(param, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(UserAuthFuncsTest, TestRequestAuthResultFunc, TestSize.Level0)
{
    uint64_t contextId = 2131;
    EXPECT_EQ(RequestAuthResultFunc(contextId, nullptr, nullptr, nullptr), RESULT_BAD_PARAM);
    Buffer *scheduleResult = CreateBufferBySize(10);
    UserAuthTokenHal token = {};
    AuthResult result = {};
    EXPECT_EQ(RequestAuthResultFunc(contextId, scheduleResult, nullptr, nullptr), RESULT_BAD_PARAM);
    EXPECT_EQ(RequestAuthResultFunc(contextId, scheduleResult, &token, nullptr), RESULT_BAD_PARAM);
    result.rootSecret = CreateBufferBySize(10);
    EXPECT_EQ(RequestAuthResultFunc(contextId, scheduleResult, &token, &result), RESULT_BAD_PARAM);
}

HWTEST_F(UserAuthFuncsTest, TestGetEnrolledStateFunc, TestSize.Level0)
{
    int32_t userId = 1;
    uint32_t authType = 1;
    EnrolledStateHal enrolledStateHal = {};
    EXPECT_EQ(GetEnrolledStateFunc(userId, authType, &enrolledStateHal), RESULT_NOT_ENROLLED);
}

HWTEST_F(UserAuthFuncsTest, TestGetUnlockAuthToken, TestSize.Level0)
{
    int32_t userId = 0;
    UserAuthTokenHal userAuthToken;
    EnrolledStateHal enrolledState;
    EXPECT_EQ(GetUnlockAuthResult(&userId, nullptr, &enrolledState), RESULT_BAD_PARAM);
    EXPECT_EQ(GetUnlockAuthResult(&userId, &userAuthToken, &enrolledState), RESULT_GENERAL_ERROR);

    int32_t userIdCached = 0;
    UserAuthTokenHal userAuthTokenCached;
    userAuthTokenCached.tokenDataPlain.time = GetSystemTime() + 600;
    userAuthTokenCached.tokenDataPlain.authType = 1;
    userAuthTokenCached.tokenDataPlain.authTrustLevel = ATL4;
    SetUnlockAuthResult(userIdCached, &userAuthTokenCached, &enrolledState);
    EXPECT_EQ(GetUnlockAuthResult(&userId, &userAuthToken, &enrolledState), RESULT_GENERAL_ERROR);

    userAuthTokenCached.tokenDataPlain.time = GetSystemTime();
    SetUnlockAuthResult(userIdCached, &userAuthTokenCached, &enrolledState);
    EXPECT_EQ(GetUnlockAuthResult(&userId, &userAuthToken, &enrolledState), RESULT_SUCCESS);
    (void)memset_s(&g_unlockAuthResult, sizeof(UnlockAuthResultCache), 0, sizeof(UnlockAuthResultCache));
}

HWTEST_F(UserAuthFuncsTest, TestCheckReuseUnlockResultFunc001, TestSize.Level0)
{
    ReuseUnlockInfoHal info;
    UserAuthTokenHal authToken;
    EnrolledStateHal enrolledState;
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, nullptr, nullptr), RESULT_BAD_PARAM);

    info.reuseUnlockResultDuration = 10;
    info.reuseUnlockResultMode = AUTH_TYPE_IRRELEVANT;
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, &authToken, &enrolledState), RESULT_GENERAL_ERROR);
    (void)memset_s(&g_unlockAuthResult, sizeof(UnlockAuthResultCache), 0, sizeof(UnlockAuthResultCache));
}

HWTEST_F(UserAuthFuncsTest, TestCheckReuseUnlockResultFunc002, TestSize.Level0)
{
    int32_t userIdCached = 0;
    UserAuthTokenHal userAuthTokenCached;
    userAuthTokenCached.tokenDataPlain.authType = 1;
    userAuthTokenCached.tokenDataPlain.authTrustLevel = ATL3;
    userAuthTokenCached.tokenDataPlain.time = GetSystemTime() + 300;
    EnrolledStateHal enrolledState;
    SetUnlockAuthResult(userIdCached, &userAuthTokenCached, &enrolledState);

    ReuseUnlockInfoHal info;
    UserAuthTokenHal authToken;
    info.reuseUnlockResultDuration = 200;
    info.userId = 1;
    info.authTrustLevel = ATL4;
    info.reuseUnlockResultMode = AUTH_TYPE_IRRELEVANT;
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, &authToken, &enrolledState), RESULT_GENERAL_ERROR);

    userAuthTokenCached.tokenDataPlain.time = GetSystemTime();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    SetUnlockAuthResult(userIdCached, &userAuthTokenCached, &enrolledState);
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, &authToken, &enrolledState), RESULT_TOKEN_TIMEOUT);

    userAuthTokenCached.tokenDataPlain.time = GetSystemTime();
    SetUnlockAuthResult(userIdCached, &userAuthTokenCached, &enrolledState);
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, &authToken, &enrolledState), RESULT_GENERAL_ERROR);

    info.userId = 0;
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, &authToken, &enrolledState), RESULT_GENERAL_ERROR);

    info.authTrustLevel = ATL2;
    info.authTypes[0] = 2;
    info.authTypeSize = 1;
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, &authToken, &enrolledState), RESULT_SUCCESS);

    info.reuseUnlockResultMode = AUTH_TYPE_RELEVANT;
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, &authToken, &enrolledState), RESULT_GENERAL_ERROR);

    info.authTypes[1] = 1;
    info.authTypeSize = 2;
    EXPECT_EQ(CheckReuseUnlockResultFunc(&info, &authToken, &enrolledState), RESULT_SUCCESS);
    (void)memset_s(&g_unlockAuthResult, sizeof(UnlockAuthResultCache), 0, sizeof(UnlockAuthResultCache));
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
