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

#include "pin_db_ops_base_test.h"

#include "pin_db_ops_base.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void PinDataBaseOpsBaseTest::SetUpTestCase()
{
}

void PinDataBaseOpsBaseTest::TearDownTestCase()
{
}

void PinDataBaseOpsBaseTest::SetUp()
{
}

void PinDataBaseOpsBaseTest::TearDown()
{
}

/**
 * @tc.name: GetDataFromBuf test
 * @tc.desc: verify GetDataFromBuf
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataBaseOpsBaseTest, GetDataFromBuf_test, TestSize.Level1)
{
    uint8_t src = 1;
    uint8_t *srcTest = &src;
    uint32_t srcLen = 2;
    uint32_t *srcLenTest = &srcLen;
    uint8_t dest = 3;
    uint8_t *destTest = &dest;
    uint32_t destLen = 3;
    ResultCode result = GetDataFromBuf(NULL, srcLenTest, destTest, destLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetDataFromBuf(&srcTest, NULL, destTest, destLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetDataFromBuf(&srcTest, srcLenTest, NULL, destLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetDataFromBuf(&srcTest, srcLenTest, destTest, destLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    destLen = 1;
    result = GetDataFromBuf(&srcTest, srcLenTest, destTest, destLen);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

/**
 * @tc.name: GenerateFileName test
 * @tc.desc: verify GenerateFileName
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataBaseOpsBaseTest, GetBufFromData_test, TestSize.Level1)
{
    uint8_t src = 1;
    uint8_t *srcTest = &src;
    uint32_t srcLenTest = 2;
    uint8_t dest = 3;
    uint8_t *destTest = &dest;
    uint32_t destLen = 1;
    uint32_t *destLenTest = &destLen;
    ResultCode result = GetBufFromData(NULL, srcLenTest, &destTest, destLenTest);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetBufFromData(srcTest, srcLenTest, &destTest, NULL);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetBufFromData(srcTest, srcLenTest, NULL, destLenTest);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetBufFromData(srcTest, srcLenTest, &destTest, destLenTest);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
}

/**
 * @tc.name: GenerateFileName test
 * @tc.desc: verify GenerateFileName
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */

HWTEST_F(PinDataBaseOpsBaseTest, GenerateFileName_test, TestSize.Level1)
{
    uint64_t templateId = 0;
    const char *prefix = "hello";
    const char *suffix = "we";
    char fileName[5] = "test";
    uint32_t fileNameLen = 2;
    ResultCode result = GenerateFileName(templateId, nullptr, suffix, fileName, fileNameLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GenerateFileName(templateId, prefix, nullptr, fileName, fileNameLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GenerateFileName(templateId, prefix, suffix, nullptr, fileNameLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GenerateFileName(templateId, prefix, suffix, fileName, fileNameLen);
    EXPECT_EQ(result, RESULT_BAD_COPY);
}

/**
 * @tc.name: GenerateFileName test
 * @tc.desc: verify ReadPinFile
 * @tc.type: FUNC
 * @tc.require: #I7SPE1
 */
HWTEST_F(PinDataBaseOpsBaseTest, ReadPinFile_test, TestSize.Level1)
{
    uint32_t dataLen = 100;
    uint8_t *data = new (std::nothrow) uint8_t(dataLen);
    EXPECT_NE(data, nullptr);
    const char *suffix = "test";
    ResultCode result = ReadPinFile(nullptr, dataLen, 1, suffix);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = ReadPinFile(data, dataLen, 1, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = ReadPinFile(data, dataLen, 1, suffix);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    delete(data);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
