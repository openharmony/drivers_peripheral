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

#include "adaptor_memory.h"
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
    UserInfo *node = (UserInfo *)Malloc(sizeof(UserInfo));
    EXPECT_NE(node, nullptr);
    ASSERT_NE(node, nullptr);
    (void)memset_s(node, sizeof(UserInfo), 0, sizeof(UserInfo));
    DestroyUserInfoNode(node);
}

HWTEST_F(IdmCommonTest, TestDestroyCredentialNode, TestSize.Level0)
{
    DestroyCredentialNode(nullptr);
    CredentialInfoHal *credentialInfoHal = (CredentialInfoHal *)Malloc(sizeof(CredentialInfoHal));
    EXPECT_NE(credentialInfoHal, nullptr);
    ASSERT_NE(credentialInfoHal, nullptr);
    (void)memset_s(credentialInfoHal, sizeof(CredentialInfoHal), 0, sizeof(CredentialInfoHal));
    DestroyCredentialNode(credentialInfoHal);
}

HWTEST_F(IdmCommonTest, TestDestroyEnrolledNode, TestSize.Level0)
{
    DestroyEnrolledNode(nullptr);
    EnrolledInfoHal *enrolledInfoHal = (EnrolledInfoHal *)Malloc(sizeof(EnrolledInfoHal));
    EXPECT_NE(enrolledInfoHal, nullptr);
    ASSERT_NE(enrolledInfoHal, nullptr);
    (void)memset_s(enrolledInfoHal, sizeof(EnrolledInfoHal), 0, sizeof(EnrolledInfoHal));
    DestroyEnrolledNode(enrolledInfoHal);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
