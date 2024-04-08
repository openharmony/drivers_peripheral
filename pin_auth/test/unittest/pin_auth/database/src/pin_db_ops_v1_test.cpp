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

#include "pin_db_ops_v1_test.h"

#include "adaptor_memory.h"
#include "pin_db_ops_v1.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinDataBaseOpsV1Test::SetUpTestCase()
{
}

void PinDataBaseOpsV1Test::TearDownTestCase()
{
}

void PinDataBaseOpsV1Test::SetUp()
{
}

void PinDataBaseOpsV1Test::TearDown()
{
}

/**
 * @tc.name: GetPinDbV1 test
 * @tc.desc: verify GetPinDbV1
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataBaseOpsV1Test, GetPinDbV1_test, TestSize.Level1)
{
    uint32_t dataLen = 20;
    uint8_t *data = new (std::nothrow) uint8_t(dataLen);
    EXPECT_NE(data, NULL);

    void *result = GetPinDbV1(NULL, dataLen);
    EXPECT_NE(result, nullptr);

    result = GetPinDbV1(data, 0);
    EXPECT_NE(result, nullptr);
    delete(data);
}

/**
 * @tc.name: UpdatePinDbFrom0To1 test
 * @tc.desc: verify UpdatePinDbFrom0To1
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataBaseOpsV1Test, UpdatePinDbFrom0To1_test, TestSize.Level1)
{
    PinDbV0 *pinDbV0 = (PinDbV0 *)Malloc(sizeof(PinDbV0));
    EXPECT_NE(pinDbV0, NULL);

    pinDbV0->version = 0;
    pinDbV0->pinIndexLen = 1;
    pinDbV0->pinIndex = (PinIndexV0 *)Malloc(sizeof(PinIndexV0) * pinDbV0->pinIndexLen);
    EXPECT_NE(pinDbV0->pinIndex, NULL);
    pinDbV0->pinIndex[0].pinInfo.templateId = 123;
    pinDbV0->pinIndex[0].pinInfo.subType = 10010;

    PinDbV1 *pinDbV1 = (PinDbV1 *)UpdatePinDbFrom0To1(NULL);
    EXPECT_EQ(pinDbV1, NULL);

    pinDbV0->pinIndexLen = 0;
    pinDbV1 = (PinDbV1 *)UpdatePinDbFrom0To1(pinDbV0);
    EXPECT_NE(pinDbV1, NULL);

    pinDbV0->pinIndexLen = 1;
    pinDbV1 = (PinDbV1 *)UpdatePinDbFrom0To1(pinDbV0);
    EXPECT_NE(pinDbV1, NULL);
    EXPECT_EQ(pinDbV1->pinIndex[0].pinInfo.templateId, pinDbV0->pinIndex[0].pinInfo.templateId);
    EXPECT_EQ(pinDbV1->pinIndex[0].pinInfo.subType, pinDbV0->pinIndex[0].pinInfo.subType);
    EXPECT_EQ(pinDbV1->pinIndex[0].pinInfo.algoVersion, 0);

    FreePinDbV1((void**)(&pinDbV1));
    Free(pinDbV0->pinIndex);
    Free(pinDbV0);
}

/**
 * @tc.name: WritePinDbV1 test
 * @tc.desc: verify WritePinDbV1
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataBaseOpsV1Test, WritePinDbV1_test, TestSize.Level1)
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

    ResultCode result = WritePinDbV1(NULL);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    result = WritePinDbV1(pinDbV1);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    pinDbV1->dbVersion = 1;
    pinDbV1->pinIndexLen = 0;
    result = WritePinDbV1(pinDbV1);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    pinDbV1->pinIndexLen = 50;
    result = WritePinDbV1(pinDbV1);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    FreePinDbV1((void**)(&pinDbV1));
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
