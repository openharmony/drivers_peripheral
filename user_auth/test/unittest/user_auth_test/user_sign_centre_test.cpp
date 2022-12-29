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

#include "user_sign_centre.h"

extern "C" {
    extern LinkedList *g_userInfoList;
    extern bool IsTimeValid(const UserAuthTokenHal *userAuthToken);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

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
    token.time = UINT64_MAX;
    EXPECT_FALSE(IsTimeValid(&token));
    token.time = 0;
    IsTimeValid(&token);
}

HWTEST_F(UserAuthSignTest, TestUserAuthTokenSign, TestSize.Level0)
{
    EXPECT_EQ(UserAuthTokenSign(nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(UserAuthSignTest, TestUserAuthTokenVerify, TestSize.Level0)
{
    EXPECT_EQ(UserAuthTokenVerify(nullptr), RESULT_BAD_PARAM);
    UserAuthTokenHal token = {};
    token.time = UINT64_MAX;
    EXPECT_EQ(UserAuthTokenVerify(&token), RESULT_TOKEN_TIMEOUT);
}

HWTEST_F(UserAuthSignTest, TestGetTokenDataAndSign, TestSize.Level0)
{
    g_userInfoList = nullptr;
    EXPECT_EQ(GetTokenDataAndSign(nullptr, 0, 0, nullptr), RESULT_BAD_PARAM);
    UserAuthContext context = {};
    context.userId = 2135;
    context.authType = 2;
    UserAuthTokenHal token = {};
    EXPECT_EQ(GetTokenDataAndSign(&context, 0, 0, &token), RESULT_NOT_FOUND);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
