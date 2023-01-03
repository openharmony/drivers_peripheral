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

#include "idm_common.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class IdmCommonTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

HWTEST_F(IdmCommonTest, TestDestroyUserInfoNode, TestSize.Level0)
{
    DestroyUserInfoNode(nullptr);
}

HWTEST_F(IdmCommonTest, TestDestroyCredentialNode, TestSize.Level0)
{
    DestroyCredentialNode(nullptr);
}

HWTEST_F(IdmCommonTest, TestDestroyEnrolledNode, TestSize.Level0)
{
    DestroyEnrolledNode(nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
