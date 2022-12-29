/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "key_mgr_test.h"

#include "ed25519_key.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;
void KeyMgrTest::SetUpTestCase()
{
}

void KeyMgrTest::TearDownTestCase()
{
}

void KeyMgrTest::SetUp()
{
}

void KeyMgrTest::TearDown()
{
}

HWTEST_F(KeyMgrTest, TestGenerateKeyPair, TestSize.Level0)
{
    EXPECT_EQ(GenerateKeyPair(), RESULT_SUCCESS);
    DestoryEd25519KeyPair();
}

HWTEST_F(KeyMgrTest, TestGetPriKey, TestSize.Level0)
{
    EXPECT_EQ(GetPriKey(), nullptr);
    EXPECT_EQ(GenerateKeyPair(), RESULT_SUCCESS);
    EXPECT_NE(GetPriKey(), nullptr);
    DestoryEd25519KeyPair();
}

HWTEST_F(KeyMgrTest, TestGetPubKey, TestSize.Level0)
{
    EXPECT_EQ(GetPubKey(), nullptr);
    EXPECT_EQ(GenerateKeyPair(), RESULT_SUCCESS);
    EXPECT_NE(GetPubKey(), nullptr);
    DestoryEd25519KeyPair();
}

HWTEST_F(KeyMgrTest, TestExecutorMsgSign, TestSize.Level0)
{
    EXPECT_EQ(ExecutorMsgSign(nullptr), nullptr);
    EXPECT_EQ(GenerateKeyPair(), RESULT_SUCCESS);
    EXPECT_EQ(ExecutorMsgSign(nullptr), nullptr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
