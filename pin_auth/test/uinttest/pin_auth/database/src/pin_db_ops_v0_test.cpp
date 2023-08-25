/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "pin_db_ops_v0_test.h"

#include "adaptor_memory.h"
#include "pin_db_ops_v0.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinDataBaseOpsV0Test::SetUpTestCase()
{
}

void PinDataBaseOpsV0Test::TearDownTestCase()
{
}

void PinDataBaseOpsV0Test::SetUp()
{
}

void PinDataBaseOpsV0Test::TearDown()
{
}

/**
 * @tc.name: GetPinDbV0 test
 * @tc.desc: verify GetPinDbV0
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataBaseOpsV0Test, GetPinDbV0_test, TestSize.Level1)
{
    uint32_t dataLen = 20;
    uint8_t *data = new (std::nothrow) uint8_t(dataLen);
    EXPECT_NE(data, NULL);

    void *result = GetPinDbV0(NULL, dataLen);
    EXPECT_EQ(result, nullptr);

    result = GetPinDbV0(data, 0);
    EXPECT_EQ(result, nullptr);
    delete(data);
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
