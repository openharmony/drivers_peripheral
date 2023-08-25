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

#include "pin_db_ops_test.h"

#include "adaptor_memory.h"
#include "pin_db_ops.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinDataOpsTest::SetUpTestCase()
{
}

void PinDataOpsTest::TearDownTestCase()
{
}

void PinDataOpsTest::SetUp()
{
}

void PinDataOpsTest::TearDown()
{
}

/**
 * @tc.name: GetPinDbV1 test
 * @tc.desc: verify GetPinDbV1
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataOpsTest, ReadPinDb_test, TestSize.Level1)
{
    PinDbV1 *result = ReadPinDb();
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: WritePinDb test
 * @tc.desc: verify WritePinDb
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataOpsTest, WritePinDb_test, TestSize.Level1)
{
    PinDbV1 *pinDbV1 = (PinDbV1 *)Malloc(sizeof(PinDbV1));
    EXPECT_NE(pinDbV1, NULL);

    pinDbV1->dbVersion = 0;
    pinDbV1->pinIndexLen = 1;
    pinDbV1->pinIndex = (PinIndexV1 *)Malloc(sizeof(PinIndexV1) * pinDbV1->pinIndexLen);
    EXPECT_NE(pinDbV1->pinIndex, NULL);
    pinDbV1->pinIndex[0].pinInfo.algoVersion = 1;
    pinDbV1->pinIndex[0].pinInfo.templateId = 123;
    pinDbV1->pinIndex[0].pinInfo.subType = 10010;

    ResultCode result = WritePinDb(NULL);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    result = WritePinDb(pinDbV1);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    pinDbV1->dbVersion = 1;
    pinDbV1->pinIndexLen = 0;
    result = WritePinDb(pinDbV1);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    pinDbV1->pinIndexLen = 50;
    result = WritePinDb(pinDbV1);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    FreePinDbV1((void**)(&pinDbV1));
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
