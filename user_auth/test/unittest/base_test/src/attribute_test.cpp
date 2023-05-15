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

#include "attribute_test.h"

#include "attribute.h"
#include "adaptor_memory.h"
#include "securec.h"

extern "C" {
    extern ResultCode GetAttributeIndex(AttributeKey key, uint32_t *index);
    extern bool IsAttributeSizeValid(uint32_t actualSize, uint32_t attributeIndex);
    extern ResultCode ReadDataFromMsg(const Uint8Array msg, uint32_t *readIndex, Uint8Array *retData);
    extern ResultCode ReadUint32FromMsg(const Uint8Array msg, uint32_t *readIndex, uint32_t *retValue);
    extern ResultCode WriteDataToMsg(Uint8Array *msg, uint32_t *writeIndex, const Uint8Array data);
    extern ResultCode WriteUInt32ToMsg(Uint8Array *msg, uint32_t *writeIndex, uint32_t value);
    extern ResultCode ParseAttributeSerializedMsg(Attribute *attribute, const Uint8Array msg);
    ResultCode ParseAttributeSerializedMsgInner(Attribute *attribute, const Uint8Array msg,
        const Uint8Array readBuffer);
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

constexpr uint32_t MAX_MSG_LEN = 1000;
constexpr uint32_t MAX_SIZE = 10;

void AttributeTest::SetUpTestCase()
{}

void AttributeTest::TearDownTestCase()
{}

void AttributeTest::SetUp()
{}

void AttributeTest::TearDown()
{}


HWTEST_F(AttributeTest, GetAttributeIndexTest, TestSize.Level0)
{
    AttributeKey key = AUTH_RESULT_CODE;
    uint32_t index = 1000;
    ResultCode result = GetAttributeIndex(key, &index);
    EXPECT_EQ(result, RESULT_SUCCESS);

    index = 1000;
    key = static_cast<AttributeKey>(100002);
    result = GetAttributeIndex(key, &index);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
}

HWTEST_F(AttributeTest, IsAttributeSizeValidTest, TestSize.Level0)
{
    uint32_t actualSize = 0;
    uint32_t attributeIndex = 1;
    bool result = IsAttributeSizeValid(actualSize, attributeIndex);
    EXPECT_EQ(result, false);
    actualSize = 1;
    result = IsAttributeSizeValid(actualSize, attributeIndex);
    EXPECT_EQ(result, true);
    actualSize = sizeof(int32_t);
    attributeIndex = 0;
    EXPECT_EQ(result, true);
}

HWTEST_F(AttributeTest, ReadDataFromMsgTest, TestSize.Level0)
{
    constexpr uint32_t dataLen = 5;
    uint8_t array[dataLen] = {1, 2, 3, 4, 5};
    Uint8Array msg = { &array[0], dataLen };
    uint32_t readIndex = 6;
    Uint8Array retData = { (uint8_t *)Malloc(dataLen), dataLen };
    ResultCode result = ReadDataFromMsg(msg, &readIndex, &retData);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    readIndex = 2;
    result = ReadDataFromMsg(msg, &readIndex, &retData);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    readIndex = 0;
    result = ReadDataFromMsg(msg, &readIndex, &retData);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

HWTEST_F(AttributeTest, WriteDataToMsgTest, TestSize.Level0)
{
    constexpr uint32_t dataLen = 5;
    uint8_t array[dataLen] = {1, 2, 3, 4, 5};
    Uint8Array data = { &array[0], dataLen };
    uint32_t writeIndex = 6;
    Uint8Array msg = { (uint8_t *)Malloc(dataLen), dataLen };
    ResultCode result = WriteDataToMsg(&msg, &writeIndex, data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    writeIndex = 2;
    result = WriteDataToMsg(&msg, &writeIndex, data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    writeIndex = 0;
    result = WriteDataToMsg(&msg, &writeIndex, data);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

HWTEST_F(AttributeTest, WriteUInt32ToMsgTest, TestSize.Level0)
{
    uint32_t value = 1;
    uint32_t writeIndex = 6;
    constexpr uint32_t dataLen = 5;
    Uint8Array msg = { (uint8_t *)Malloc(dataLen), dataLen };
    ResultCode result = WriteUInt32ToMsg(&msg, &writeIndex, value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    writeIndex = 0;
    result = WriteUInt32ToMsg(&msg, &writeIndex, value);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

HWTEST_F(AttributeTest, ParseAttributeSerializedMsgTest, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    constexpr uint32_t dataLen = 5;
    Uint8Array msg = { (uint8_t *)Malloc(dataLen), dataLen };
    ResultCode result = ParseAttributeSerializedMsg(nullptr, msg);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, ParseAttributeSerializedMsgInnerTest, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    constexpr uint32_t dataLen = 5;
    Uint8Array msg = { (uint8_t *)Malloc(dataLen), dataLen };
    ResultCode result = ParseAttributeSerializedMsgInner(nullptr, msg, msg);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, GetAttributeSerializedMsgTest, TestSize.Level0)
{
    Uint8Array msg = { (uint8_t *)Malloc(MAX_MSG_LEN), MAX_MSG_LEN };
    ResultCode result = GetAttributeSerializedMsg(nullptr, &msg);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    uint32_t testUint32 = 123;
    result = SetAttributeUint32(attribute, AUTH_IDENTIFY_MODE, testUint32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeSerializedMsg(attribute, nullptr);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    msg.len = 0;
    result = GetAttributeSerializedMsg(attribute, &msg);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    msg.len = MAX_MSG_LEN;
    result = GetAttributeSerializedMsg(attribute, &msg);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, CreateEmptyAttributeTest, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, CreateAttributeFromSerializedMsgTest, TestSize.Level0)
{
    constexpr uint32_t dataLen = 5;
    uint8_t array[dataLen] = {1, 2, 3, 4, 5};
    Uint8Array data = { &array[0], dataLen };
    Attribute *result = CreateAttributeFromSerializedMsg(data);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(AttributeTest, FreeAttributeTest, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, GetAttributeUint32Test, TestSize.Level0)
{
    uint32_t value;
    ResultCode result = GetAttributeUint32(nullptr, AUTH_RESULT_CODE, &value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    uint32_t testUint32 = 123;
    result = SetAttributeUint32(attribute, AUTH_RESULT_CODE, testUint32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeUint32(attribute, AUTH_RESULT_CODE, nullptr);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = GetAttributeUint32(attribute, AUTH_TEMPLATE_ID, &value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = GetAttributeUint32(attribute, AUTH_RESULT_CODE, &value);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, SetAttributeUint32Test, TestSize.Level0)
{
    uint32_t value = 123;
    ResultCode result = SetAttributeUint32(nullptr, AUTH_RESULT_CODE, value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    result = SetAttributeUint32(attribute, AUTH_TEMPLATE_ID, value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = SetAttributeUint32(attribute, AUTH_RESULT_CODE, value);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, GetAttributeInt32Test, TestSize.Level0)
{
    int32_t value;
    ResultCode result = GetAttributeInt32(nullptr, AUTH_RESULT_CODE, &value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    int32_t testInt32 = 234;
    result = SetAttributeInt32(attribute, AUTH_REMAIN_COUNT, testInt32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeInt32(attribute, AUTH_REMAIN_COUNT, nullptr);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = GetAttributeInt32(attribute, AUTH_REMAIN_COUNT, &value);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(value, testInt32);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, SetAttributeInt32Test, TestSize.Level0)
{
    int32_t value = 123;
    ResultCode result = SetAttributeInt32(nullptr, AUTH_RESULT_CODE, value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    result = SetAttributeInt32(attribute, AUTH_REMAIN_COUNT, value);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, GetAttributeUint64Test, TestSize.Level0)
{
    uint64_t value;
    ResultCode result = GetAttributeUint64(nullptr, AUTH_TEMPLATE_ID, &value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    result = GetAttributeUint64(attribute, AUTH_TEMPLATE_ID, nullptr);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = GetAttributeUint64(attribute, AUTH_TEMPLATE_ID, &value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    uint64_t testValue = 123;
    result = SetAttributeUint64(attribute, AUTH_TEMPLATE_ID, testValue);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeUint64(attribute, AUTH_TEMPLATE_ID, &value);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, SetAttributeUint64Test, TestSize.Level0)
{
    uint64_t value = 123;
    ResultCode result = SetAttributeUint64(nullptr, AUTH_SCHEDULE_ID, value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    result = SetAttributeUint64(attribute, AUTH_REMAIN_COUNT, value);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = SetAttributeUint64(attribute, AUTH_SCHEDULE_ID, value);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, GetAttributeUint8ArrayTest, TestSize.Level0)
{
    constexpr uint32_t dataLen = 5;
    uint8_t array[dataLen] = {1, 2, 3, 4, 5};
    Uint8Array data = { &array[0], dataLen };
    ResultCode result = GetAttributeUint8Array(nullptr, AUTH_SIGNATURE, &data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    result = GetAttributeUint8Array(attribute, AUTH_SIGNATURE, nullptr);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    data.len = 0;
    result = GetAttributeUint8Array(attribute, AUTH_SIGNATURE, &data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    data.len = dataLen;
    result = SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeUint8Array(attribute, AUTH_SIGNATURE, &data);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, SetAttributeUint8ArrayTest, TestSize.Level0)
{
    constexpr uint32_t dataLen = 5;
    uint8_t array[dataLen] = {1, 2, 3, 4, 5};
    Uint8Array data = { &array[0], dataLen };
    ResultCode result = SetAttributeUint8Array(nullptr, AUTH_SIGNATURE, data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    data.len = 0;
    result = SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    data.len = dataLen;
    AttributeKey keyTest = static_cast<AttributeKey>(100003);
    result = SetAttributeUint8Array(attribute, keyTest, data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    result = SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, GetAttributeUint64ArrayTest, TestSize.Level0)
{
    constexpr uint32_t dataLen = 5;
    uint64_t array[dataLen] = {1, 2, 3, 4, 5};
    Uint64Array data = { &array[0], dataLen };
    ResultCode result = GetAttributeUint64Array(nullptr, AUTH_TEMPLATE_ID_LIST, &data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    result = GetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, nullptr);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    data.len = 0;
    result = GetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, &data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    data.len = dataLen;
    result = SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, data);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = GetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, &data);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, SetAttributeUint64ArrayTest, TestSize.Level0)
{
    constexpr uint32_t dataLen = 5;
    uint64_t array[dataLen] = {1, 2, 3, 4, 5};
    Uint64Array data = { &array[0], dataLen };
    ResultCode result = SetAttributeUint64Array(nullptr, AUTH_SIGNATURE, data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    Attribute *attribute = CreateEmptyAttribute();
    EXPECT_NE(attribute, nullptr);
    data.len = 0;
    result = SetAttributeUint64Array(attribute, AUTH_SIGNATURE, data);
    EXPECT_EQ(result, RESULT_GENERAL_ERROR);
    data.len = dataLen;
    result = SetAttributeUint64Array(attribute, AUTH_SIGNATURE, data);
    EXPECT_EQ(result, RESULT_SUCCESS);
    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, SetAndReadTest, TestSize.Level0)
{
    Attribute *originAttribute = CreateEmptyAttribute();
    EXPECT_NE(originAttribute, nullptr);
    uint32_t testUint32 = 123;
    int32_t testInt32 = 123;
    uint64_t testUint64 = 456;
    uint8_t testUint8Buffer[] = { 'a', 'b', 'c' };
    uint64_t testUint64Buffer[] = { 123, 456, 789 };
    Uint8Array testUint8Array = { testUint8Buffer, sizeof(testUint8Buffer) };
    Uint64Array testUint64Array = { testUint64Buffer, sizeof(testUint64Buffer) };
    ResultCode result = SetAttributeUint32(originAttribute, AUTH_IDENTIFY_MODE, testUint32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeInt32(originAttribute, AUTH_RESULT_CODE, testInt32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint64(originAttribute, AUTH_SCHEDULE_ID, testUint64);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint8Array(originAttribute, AUTH_SIGNATURE, testUint8Array);
    EXPECT_EQ(result, RESULT_SUCCESS);
    result = SetAttributeUint64Array(originAttribute, AUTH_TEMPLATE_ID_LIST, testUint64Array);
    EXPECT_EQ(result, RESULT_SUCCESS);
    uint8_t msgBuffer[MAX_MSG_LEN] = {};
    Uint8Array msg = { msgBuffer, sizeof(msgBuffer) };
    result = GetAttributeSerializedMsg(originAttribute, &msg);
    EXPECT_EQ(result, RESULT_SUCCESS);
    uint32_t parsedUint32;
    int32_t parsedInt32;
    uint64_t parsedUint64;
    uint8_t parsedUint8Buffer[MAX_SIZE];
    uint64_t parsedUint64Buffer[MAX_SIZE];
    Uint8Array parsedUint8Array = { parsedUint8Buffer, sizeof(parsedUint8Buffer) };
    Uint64Array parsedUint64Array = { parsedUint64Buffer, sizeof(parsedUint64Buffer) };
    Attribute *parsedAttribute = CreateAttributeFromSerializedMsg(msg);
    result = GetAttributeUint32(parsedAttribute, AUTH_IDENTIFY_MODE, &parsedUint32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(parsedUint32, testUint32);
    result = GetAttributeInt32(parsedAttribute, AUTH_RESULT_CODE, &parsedInt32);
    EXPECT_EQ(parsedInt32, testInt32);
    result = GetAttributeUint64(parsedAttribute, AUTH_SCHEDULE_ID, &parsedUint64);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(parsedUint64, testUint64);
    result = GetAttributeUint8Array(originAttribute, AUTH_SIGNATURE, &parsedUint8Array);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(testUint8Array.len, parsedUint8Array.len);
    EXPECT_EQ(testUint8Array.data[2], parsedUint8Array.data[2]);
    result = GetAttributeUint64Array(originAttribute, AUTH_TEMPLATE_ID_LIST, &parsedUint64Array);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(testUint64Array.len, parsedUint64Array.len);
    EXPECT_EQ(testUint64Array.data[2], parsedUint64Array.data[2]);
    FreeAttribute(&originAttribute);
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
