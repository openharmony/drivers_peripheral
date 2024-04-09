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

#include "identify_funcs.h"

extern "C" {
    extern LinkedList *g_contextList;
    extern void DestroyContextNode(void *data);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class IdentifyFuncsTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(IdentifyFuncsTest, TestDoIdentify, TestSize.Level0)
{
    IdentifyParam param = {};
    EXPECT_EQ(DoIdentify(param, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdentifyFuncsTest, TestDoUpdateIdentify_001, TestSize.Level0)
{
    constexpr uint64_t contextId = 1235;
    EXPECT_EQ(DoUpdateIdentify(contextId, nullptr, nullptr, nullptr, nullptr), RESULT_BAD_PARAM);
}

HWTEST_F(IdentifyFuncsTest, TestDoUpdateIdentify_002, TestSize.Level0)
{
    constexpr uint64_t contextId = 1235;
    Buffer *scheduleResult = CreateBufferBySize(10);
    int32_t userId = 32156;
    UserAuthTokenHal token = {};
    int32_t result = 0;
    g_contextList = CreateLinkedList(DestroyContextNode);
    EXPECT_NE(g_contextList, nullptr);
    UserAuthContext context = {};
    context.contextId = contextId;
    g_contextList->insert(g_contextList, static_cast<void *>(&context));
    EXPECT_EQ(DoUpdateIdentify(contextId, scheduleResult, &userId, &token, &result), RESULT_GENERAL_ERROR);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
