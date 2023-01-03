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

#include "tlv_base_test.h"

#include "adaptor_memory.h"
#include "tlv_base.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void TlvBaseTest::SetUpTestCase()
{
}

void TlvBaseTest::TearDownTestCase()
{
}

void TlvBaseTest::SetUp()
{
}

void TlvBaseTest::TearDown()
{
}

HWTEST_F(TlvBaseTest, TestCreateTlvType, TestSize.Level0)
{
    int32_t type = 212;
    uint32_t length = 100;
    void *value = nullptr;
    EXPECT_EQ(CreateTlvType(type, length, value), nullptr);
    int32_t temp = 1230;
    value = static_cast<void *>(&temp);
    TlvType *tlv = CreateTlvType(type, length, value);
    EXPECT_NE(tlv, nullptr);
    Free(tlv->value);
    Free(tlv);
}

HWTEST_F(TlvBaseTest, TestDestroyTlvList, TestSize.Level0)
{
    EXPECT_EQ(DestroyTlvList(nullptr), 1001);
}

HWTEST_F(TlvBaseTest, TestAddTlvNode, TestSize.Level0)
{
    TlvListNode *head = nullptr;
    TlvObject *object = nullptr;
    EXPECT_EQ(AddTlvNode(head, object), 1001);
    TlvListNode node = {};
    head = &node;
    EXPECT_EQ(AddTlvNode(head, object), 1001);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
