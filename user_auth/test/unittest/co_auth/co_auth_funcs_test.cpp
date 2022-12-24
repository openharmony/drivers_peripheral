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

#include "coauth_funcs.h"

extern "C" {
    extern LinkedList *g_poolList;
    extern ResultCode InitResourcePool(void);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class CoAuthFuncsTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(CoAuthFuncsTest, TestRegisterExecutor, TestSize.Level0)
{
    EXPECT_EQ(RegisterExecutor(nullptr, nullptr), RESULT_BAD_PARAM);
    g_poolList = nullptr;
    ExecutorInfoHal info = {};
    uint64_t index = 0;
    EXPECT_EQ(RegisterExecutor(&info, &index), RESULT_NEED_INIT);
}

HWTEST_F(CoAuthFuncsTest, TestUnregisterExecutorToPool, TestSize.Level0)
{
    g_poolList = nullptr;
    uint64_t index = 3226;
    EXPECT_EQ(UnregisterExecutorToPool(index), RESULT_NEED_INIT);
    InitResourcePool();
    ExecutorInfoHal info = {};
    info.authType = 1;
    info.executorRole = VERIFIER;
    EXPECT_EQ(RegisterExecutor(&info, &index), RESULT_SUCCESS);
    EXPECT_EQ(UnregisterExecutorToPool(index), RESULT_SUCCESS);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
