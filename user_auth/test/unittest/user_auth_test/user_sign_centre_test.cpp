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

#include <cstring>
#include "securec.h"
#include <thread>

#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "token_key.h"
#include "user_sign_centre.h"

extern "C" {
    extern bool IsTimeValid(const UserAuthTokenHal *userAuthToken);
    extern ResultCode UserAuthTokenHmac(UserAuthTokenHal *userAuthToken, HksAuthTokenKey *authTokenKey);
    extern ResultCode GetTokenDataCipherResult(const TokenDataToEncrypt *data, UserAuthTokenHal *authToken,
        const HksAuthTokenKey *tokenKey);
    extern ResultCode DecryptTokenCipher(const UserAuthTokenHal *userAuthToken, UserAuthTokenPlain *tokenPlain,
        HksAuthTokenKey *tokenKey);
    extern ResultCode CheckUserAuthTokenHmac(const UserAuthTokenHal *userAuthToken, HksAuthTokenKey *tokenKey);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

#define DEAULT_CHALLENGE {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, \
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
#define DEFAULT_CIPHER {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, \
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7}
#define DEFAULT_TAG {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}
#define DEFAULT_IV {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}
#define DEFAULT_SIGN {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, \
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1}

class UserAuthSignTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(UserAuthSignTest, TestIsTimeValid, TestSize.Level0)
{
    UserAuthTokenHal token = {};
    token.tokenDataPlain.time = UINT64_MAX;
    EXPECT_FALSE(IsTimeValid(&token));
    token.tokenDataPlain.time = 0;
    IsTimeValid(&token);
    token.tokenDataPlain.time = GetSystemTime();
    EXPECT_TRUE(IsTimeValid(&token));
}

HWTEST_F(UserAuthSignTest, TestUserAuthTokenHmac, TestSize.Level0)
{
    UserAuthTokenHal token = {};
    HksAuthTokenKey userAuthTokenKey = {};
    EXPECT_EQ(UserAuthTokenHmac(&token, &userAuthTokenKey), RESULT_SUCCESS);
}

HWTEST_F(UserAuthSignTest, TestTokenGenerateAndVerify, TestSize.Level0)
{
    constexpr uint32_t testVersion = 1;
    constexpr uint32_t testAuthTrustLevel = 3;
    constexpr uint32_t testAuthType = 4;
    constexpr uint32_t testAuthMode = 5;
    constexpr uint32_t testSecurityLevel = 6;
    constexpr int32_t testUserId = 7;
    constexpr uint64_t testSecureId = 8;
    constexpr uint64_t testEnrolledId = 9;
    constexpr uint64_t testCredentialId = 10;
    UserAuthTokenHal token = {
        .version = testVersion,
        .tokenDataPlain = {
            .challenge = DEAULT_CHALLENGE,
            .time = GetSystemTime(),
            .authTrustLevel = testAuthTrustLevel,
            .authType = testAuthType,
            .authMode = testAuthMode,
            .securityLevel = testSecurityLevel,
        },
        .tokenDataCipher = DEFAULT_CIPHER,
        .tag = DEFAULT_TAG,
        .iv = DEFAULT_IV,
        .sign = DEFAULT_SIGN,
    };
    TokenDataToEncrypt data = {
        .userId = testUserId,
        .secureUid = testSecureId,
        .enrolledId = testEnrolledId,
        .credentialId = testCredentialId,
    };
    HksAuthTokenKey userAuthTokenKey = {};
    EXPECT_EQ(GetTokenKey(&userAuthTokenKey), RESULT_SUCCESS);
    EXPECT_EQ(GetTokenDataCipherResult(&data, &token, &userAuthTokenKey), RESULT_SUCCESS);
    EXPECT_EQ(UserAuthTokenHmac(&token, &userAuthTokenKey), RESULT_SUCCESS);
    UserAuthTokenPlain userAuthTokenPlain = {};
    EXPECT_EQ(UserAuthTokenVerify(&token, &userAuthTokenPlain), RESULT_SUCCESS);
    EXPECT_EQ(memcmp(&(userAuthTokenPlain.tokenDataPlain), &(token.tokenDataPlain),
        sizeof(userAuthTokenPlain.tokenDataPlain)), 0);
    EXPECT_EQ(memcmp(&(userAuthTokenPlain.tokenDataToEncrypt), &data,
        sizeof(userAuthTokenPlain.tokenDataToEncrypt)), 0);
}

HWTEST_F(UserAuthSignTest, TestDecryptTokenCipher, TestSize.Level0)
{
    UserAuthTokenHal userAuthToken = {};
    UserAuthTokenPlain userAuthTokenPlain = {};
    HksAuthTokenKey userAuthTokenKey = {};
    EXPECT_EQ(DecryptTokenCipher(&userAuthToken, &userAuthTokenPlain, &userAuthTokenKey), RESULT_GENERAL_ERROR);
}

HWTEST_F(UserAuthSignTest, TestCheckUserAuthTokenHmac, TestSize.Level0)
{
    UserAuthTokenHal userAuthToken = {};
    HksAuthTokenKey tokenKey = {};
    EXPECT_EQ(CheckUserAuthTokenHmac(&userAuthToken, &tokenKey), RESULT_BAD_SIGN);
}

HWTEST_F(UserAuthSignTest, TestUserAuthTokenVerify, TestSize.Level0)
{
    UserAuthTokenHal userAuthToken = {};
    UserAuthTokenPlain userAuthTokenPlain = {};
    HksAuthTokenKey userAuthTokenKey = {};
    EXPECT_EQ(GetTokenKey(&userAuthTokenKey), RESULT_SUCCESS);
    EXPECT_EQ(UserAuthTokenVerify(nullptr, &userAuthTokenPlain), RESULT_BAD_PARAM);
    EXPECT_EQ(UserAuthTokenVerify(&userAuthToken, nullptr), RESULT_BAD_PARAM);
    userAuthToken.tokenDataPlain.time = UINT64_MAX;
    EXPECT_EQ(UserAuthTokenVerify(&userAuthToken, &userAuthTokenPlain), RESULT_TOKEN_TIMEOUT);
    userAuthToken.tokenDataPlain.time = GetSystemTime();
    EXPECT_EQ(UserAuthTokenVerify(&userAuthToken, &userAuthTokenPlain), RESULT_BAD_SIGN);
    EXPECT_EQ(UserAuthTokenHmac(&userAuthToken, &userAuthTokenKey), RESULT_SUCCESS);
    EXPECT_EQ(UserAuthTokenVerify(&userAuthToken, &userAuthTokenPlain), RESULT_GENERAL_ERROR);
}

HWTEST_F(UserAuthSignTest, TestReuseUnlockTokenSign, TestSize.Level0)
{
    UserAuthTokenHal token = {};
    EXPECT_EQ(ReuseUnlockTokenSign(nullptr), RESULT_BAD_PARAM);
    EXPECT_EQ(ReuseUnlockTokenSign(&token), RESULT_SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
