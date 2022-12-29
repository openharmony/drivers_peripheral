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

#include "user_auth_funcs.h"

extern "C" {
    extern int32_t SetAuthResult(uint32_t authType, const ExecutorResultInfo *info, AuthResult *result);
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

HWTEST_F(UserAuthFuncsTest, TestSetAuthResult, TestSize.Level0)
{
    uint32_t authType = 1;
    ExecutorResultInfo info = {};
    info.result = 0;
    info.rootSecret = nullptr;
    AuthResult result = {};
    EXPECT_EQ(SetAuthResult(authType, &info, &result), RESULT_NO_MEMORY);
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
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
