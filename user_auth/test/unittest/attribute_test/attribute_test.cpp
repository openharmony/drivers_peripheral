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

#include "attribute.h"

#include <cstdint>
#include <vector>
#include <gtest/gtest.h>

#include "securec.h"
#include "mock_adaptor_memory.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

class AttributeTest : public testing::Test {
public:
    static void SetUpTestCase() {};

    static void TearDownTestCase() {};

    void SetUp() {};

    void TearDown() {};
};

void RandomFillVector(std::vector<uint8_t> &src, uint32_t len)
{
    constexpr uint32_t MOD = 128;
    for (uint32_t i = 0; i < len; ++i) {
        uint32_t num = static_cast<uint32_t>(rand());
        src.push_back(static_cast<uint8_t>(num % MOD));
    }
}

HWTEST_F(AttributeTest, TestCreateEmptyAttribute_001, TestSize.Level0)
{
    MockMemMgr mock;
    EXPECT_CALL(mock, Malloc(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(
            [](const size_t size) {
                void *res = malloc(size);
                static_cast<void>(memset_s(res, size, 0, size));
                return res;
            }
        );

    EXPECT_CALL(mock, Free(_))
    .WillRepeatedly(
            [](void *ptr) {
                if (ptr != nullptr) {
                    free(ptr);
                }
            }
        );

    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_EQ(attribute, nullptr);

    attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestFreeAttribute_001, TestSize.Level0)
{
    FreeAttribute(nullptr);
    Attribute *attribute = nullptr;
    FreeAttribute(&attribute);

    attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    FreeAttribute(&attribute);
    ASSERT_EQ(attribute, nullptr);
}

HWTEST_F(AttributeTest, TestAttributeUint32_001, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    constexpr uint32_t VALUE_1 = 6036;
    constexpr uint32_t VALUE_2 = 5697;
    ASSERT_EQ(SetAttributeUint32(attribute, AUTH_REMAIN_TIME, VALUE_1), RESULT_SUCCESS);
    ASSERT_EQ(SetAttributeUint32(attribute, AUTH_PROPERTY_MODE, VALUE_2), RESULT_SUCCESS);

    uint32_t out1 = 0;
    uint32_t out2 = 0;
    ASSERT_EQ(GetAttributeUint32(attribute, AUTH_REMAIN_TIME, &out1), RESULT_SUCCESS);
    ASSERT_EQ(GetAttributeUint32(attribute, AUTH_PROPERTY_MODE, &out2), RESULT_SUCCESS);

    ASSERT_EQ(out1, VALUE_1);
    ASSERT_EQ(out2, VALUE_2);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint32_002, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    constexpr uint32_t VALUE = 6036;
    ASSERT_EQ(SetAttributeUint32(nullptr, AUTH_REMAIN_TIME, VALUE), RESULT_BAD_PARAM);
    ASSERT_EQ(SetAttributeUint32(attribute, AUTH_REMAIN_TIME, VALUE), RESULT_SUCCESS);

    uint32_t out = 0;
    ASSERT_EQ(GetAttributeUint32(nullptr, AUTH_REMAIN_TIME, &out), RESULT_BAD_PARAM);
    ASSERT_EQ(GetAttributeUint32(attribute, AUTH_REMAIN_TIME, nullptr), RESULT_BAD_PARAM);
    ASSERT_EQ(GetAttributeUint32(attribute, AUTH_PROPERTY_MODE, &out), RESULT_GENERAL_ERROR);
    ASSERT_EQ(GetAttributeUint32(attribute, AUTH_REMAIN_TIME, &out), RESULT_SUCCESS);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeInt32_001, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    constexpr int32_t VALUE_1 = 6036;
    constexpr int32_t VALUE_2 = 5697;
    ASSERT_EQ(SetAttributeInt32(attribute, AUTH_RESULT_CODE, VALUE_1), RESULT_SUCCESS);
    ASSERT_EQ(SetAttributeInt32(attribute, AUTH_REMAIN_COUNT, VALUE_2), RESULT_SUCCESS);

    int32_t out1 = 0;
    int32_t out2 = 0;
    ASSERT_EQ(GetAttributeInt32(attribute, AUTH_RESULT_CODE, &out1), RESULT_SUCCESS);
    ASSERT_EQ(GetAttributeInt32(attribute, AUTH_REMAIN_COUNT, &out2), RESULT_SUCCESS);

    ASSERT_EQ(out1, VALUE_1);
    ASSERT_EQ(out2, VALUE_2);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeInt32_002, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    constexpr int32_t VALUE = 6036;
    ASSERT_EQ(SetAttributeInt32(nullptr, AUTH_RESULT_CODE, VALUE), RESULT_BAD_PARAM);
    ASSERT_EQ(SetAttributeInt32(attribute, AUTH_RESULT_CODE, VALUE), RESULT_SUCCESS);

    int32_t out = 0;
    ASSERT_EQ(GetAttributeInt32(nullptr, AUTH_RESULT_CODE, &out), RESULT_BAD_PARAM);
    ASSERT_EQ(GetAttributeInt32(attribute, AUTH_RESULT_CODE, nullptr), RESULT_BAD_PARAM);
    ASSERT_EQ(GetAttributeInt32(attribute, AUTH_REMAIN_COUNT, &out), RESULT_GENERAL_ERROR);
    ASSERT_EQ(GetAttributeInt32(attribute, AUTH_RESULT_CODE, &out), RESULT_SUCCESS);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint64_001, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    constexpr uint64_t VALUE_1 = 6036;
    constexpr uint64_t VALUE_2 = 5697;
    ASSERT_EQ(SetAttributeUint64(attribute, AUTH_TEMPLATE_ID, VALUE_1), RESULT_SUCCESS);
    ASSERT_EQ(SetAttributeUint64(attribute, AUTH_SCHEDULE_ID, VALUE_2), RESULT_SUCCESS);

    uint64_t out1 = 0;
    uint64_t out2 = 0;
    ASSERT_EQ(GetAttributeUint64(attribute, AUTH_TEMPLATE_ID, &out1), RESULT_SUCCESS);
    ASSERT_EQ(GetAttributeUint64(attribute, AUTH_SCHEDULE_ID, &out2), RESULT_SUCCESS);

    ASSERT_EQ(out1, VALUE_1);
    ASSERT_EQ(out2, VALUE_2);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint64_002, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    constexpr uint64_t VALUE = 6036;
    ASSERT_EQ(SetAttributeUint64(nullptr, AUTH_TEMPLATE_ID, VALUE), RESULT_BAD_PARAM);
    ASSERT_EQ(SetAttributeUint64(attribute, AUTH_TEMPLATE_ID, VALUE), RESULT_SUCCESS);

    uint64_t out = 0;
    ASSERT_EQ(GetAttributeUint64(nullptr, AUTH_TEMPLATE_ID, &out), RESULT_BAD_PARAM);
    ASSERT_EQ(GetAttributeUint64(attribute, AUTH_TEMPLATE_ID, nullptr), RESULT_BAD_PARAM);
    ASSERT_EQ(GetAttributeUint64(attribute, AUTH_SCHEDULE_ID, &out), RESULT_GENERAL_ERROR);
    ASSERT_EQ(GetAttributeUint64(attribute, AUTH_TEMPLATE_ID, &out), RESULT_SUCCESS);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint8Array_001, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    constexpr uint8_t SIZE = 252;
    std::vector<uint8_t> array;
    array.reserve(SIZE);
    for (uint8_t i = 0; i < SIZE; ++i) {
        array.push_back(i);
    }
    Uint8Array data = { array.data(), SIZE };
    ASSERT_EQ(SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data), RESULT_SUCCESS);

    std::vector<uint8_t> out(SIZE);
    Uint8Array value = { out.data(), SIZE };
    ASSERT_EQ(GetAttributeUint8Array(attribute, AUTH_SIGNATURE, &value), RESULT_SUCCESS);
    ASSERT_THAT(out, ElementsAreArray(array));

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint8Array_002, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    ASSERT_EQ(GetAttributeUint8Array(nullptr, AUTH_SIGNATURE, nullptr), RESULT_BAD_PARAM);
    ASSERT_EQ(GetAttributeUint8Array(attribute, AUTH_SIGNATURE, nullptr), RESULT_BAD_PARAM);
    Uint8Array value = {};
    ASSERT_EQ(GetAttributeUint8Array(attribute, AUTH_SIGNATURE, &value), RESULT_BAD_PARAM);
    constexpr uint32_t SIZE = 20;
    std::vector<uint8_t> array(SIZE);
    value = { array.data(), 0 };
    ASSERT_EQ(GetAttributeUint8Array(attribute, AUTH_SIGNATURE, &value), RESULT_BAD_PARAM);

    value = { array.data(), static_cast<uint32_t>(array.size()) };
    constexpr uint32_t INVALID_KEY = 100000032;
    ASSERT_EQ(GetAttributeUint8Array(attribute, AUTH_CALLER_UID, &value), RESULT_GENERAL_ERROR);
    ASSERT_EQ(GetAttributeUint8Array(attribute, static_cast<AttributeKey>(INVALID_KEY), &value), RESULT_GENERAL_ERROR);

    std::vector<uint8_t> out(SIZE + SIZE);
    Uint8Array data = { out.data(), static_cast<uint32_t>(out.size()) };
    ASSERT_EQ(SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data), RESULT_SUCCESS);
    ASSERT_EQ(GetAttributeUint8Array(attribute, AUTH_SIGNATURE, &value), RESULT_GENERAL_ERROR);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint8Array_003, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    std::vector<uint8_t> array = {12, 14, 16, 15, 34, 123, 154, 48, 154, 102, 188};
    Uint8Array data = { nullptr, static_cast<uint32_t>(array.size()) };
    ASSERT_EQ(SetAttributeUint8Array(nullptr, AUTH_SIGNATURE, data), RESULT_BAD_PARAM);
    ASSERT_EQ(SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data), RESULT_BAD_PARAM);

    data = { array.data(), static_cast<uint32_t>(array.size()) };
    constexpr uint32_t INVALID_KEY = 100000032;
    ASSERT_EQ(SetAttributeUint8Array(attribute, static_cast<AttributeKey>(INVALID_KEY), data), RESULT_GENERAL_ERROR);

    MockMemMgr mock;
    EXPECT_CALL(mock, Malloc(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(
            [](const size_t size) {
                void *res = malloc(size);
                static_cast<void>(memset_s(res, size, 0, size));
                return res;
            }
        );

    EXPECT_CALL(mock, Free(_))
    .WillRepeatedly(
            [](void *ptr) {
                if (ptr != nullptr) {
                    free(ptr);
                }
            }
        );

    ASSERT_EQ(SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data), RESULT_GENERAL_ERROR);
    ASSERT_EQ(SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data), RESULT_SUCCESS);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestSetEmptyUint8Array_001, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    Uint8Array data = {};
    ASSERT_EQ(SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data), RESULT_SUCCESS);

    constexpr uint32_t SIZE = 20;
    std::vector<uint8_t> array(SIZE);
    Uint8Array value = { array.data(), static_cast<uint32_t>(array.size()) };
    ASSERT_EQ(GetAttributeUint8Array(attribute, AUTH_SIGNATURE, &value), RESULT_SUCCESS);

    ASSERT_EQ(value.len, 0);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint64Array_001, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    constexpr uint64_t SIZE = 8192;
    std::vector<uint64_t> array;
    array.reserve(SIZE);
    for (uint64_t i = 0; i < SIZE; ++i) {
        array.push_back(i);
    }
    Uint64Array data = { array.data(), SIZE };
    ASSERT_EQ(SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, data), RESULT_SUCCESS);

    std::vector<uint64_t> out(SIZE);
    Uint64Array value = { out.data(), SIZE };
    ASSERT_EQ(GetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, &value), RESULT_SUCCESS);
    ASSERT_THAT(out, ElementsAreArray(array));

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint64Array_002, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    ASSERT_EQ(GetAttributeUint64Array(nullptr, AUTH_TEMPLATE_ID_LIST, nullptr), RESULT_BAD_PARAM);
    ASSERT_EQ(GetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, nullptr), RESULT_BAD_PARAM);
    Uint64Array value = {};
    ASSERT_EQ(GetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, &value), RESULT_BAD_PARAM);
    constexpr uint32_t SIZE = 20;
    std::vector<uint64_t> array(SIZE);
    value = { array.data(), 0 };
    ASSERT_EQ(GetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, &value), RESULT_BAD_PARAM);

    value = { array.data(), static_cast<uint32_t>(array.size()) };
    constexpr uint32_t INVALID_KEY = 100000032;
    ASSERT_EQ(GetAttributeUint64Array(attribute, AUTH_CALLER_UID, &value), RESULT_GENERAL_ERROR);
    ASSERT_EQ(GetAttributeUint64Array(attribute, static_cast<AttributeKey>(INVALID_KEY), &value),
        RESULT_GENERAL_ERROR);

    std::vector<uint8_t> temp(SIZE);
    Uint8Array data = { temp.data(), static_cast<uint32_t>(temp.size()) };
    ASSERT_EQ(SetAttributeUint8Array(attribute, AUTH_SIGNATURE, data), RESULT_SUCCESS);
    ASSERT_EQ(GetAttributeUint64Array(attribute, AUTH_SIGNATURE, &value), RESULT_GENERAL_ERROR);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeUint64Array_003, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    std::vector<uint64_t> array = {12, 14, 16, 15, 34, 123, 154, 48, 154, 102, 188};
    Uint64Array data = { nullptr, static_cast<uint32_t>(array.size()) };
    ASSERT_EQ(SetAttributeUint64Array(nullptr, AUTH_TEMPLATE_ID_LIST, data), RESULT_BAD_PARAM);
    ASSERT_EQ(SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, data), RESULT_BAD_PARAM);

    data = { array.data(), static_cast<uint32_t>(array.size()) };

    MockMemMgr mock;
    EXPECT_CALL(mock, Malloc(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(
            [](const size_t size) {
                void *res = malloc(size);
                static_cast<void>(memset_s(res, size, 0, size));
                return res;
            }
        );

    EXPECT_CALL(mock, Free(_))
    .WillRepeatedly(
            [](void *ptr) {
                if (ptr != nullptr) {
                    free(ptr);
                }
            }
        );

    ASSERT_EQ(SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, data), RESULT_GENERAL_ERROR);
    ASSERT_EQ(SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, data), RESULT_SUCCESS);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestSetEmptyUint64Array_001, TestSize.Level0)
{
    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);

    Uint64Array data = {};
    ASSERT_EQ(SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, data), RESULT_SUCCESS);

    constexpr uint32_t SIZE = 20;
    std::vector<uint64_t> array(SIZE);
    Uint64Array value = { array.data(), static_cast<uint32_t>(array.size()) };
    ASSERT_EQ(GetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, &value), RESULT_SUCCESS);

    ASSERT_EQ(value.len, 0);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestGetAttributeSerializedMsg_001, TestSize.Level0)
{
    ASSERT_EQ(GetAttributeSerializedMsg(nullptr, nullptr), RESULT_BAD_PARAM);

    Attribute *attribute = CreateEmptyAttribute();
    ASSERT_NE(attribute, nullptr);
    ASSERT_EQ(GetAttributeSerializedMsg(attribute, nullptr), RESULT_BAD_PARAM);

    Uint8Array retMsg = { nullptr, 0 };
    ASSERT_EQ(GetAttributeSerializedMsg(attribute, &retMsg), RESULT_BAD_PARAM);

    constexpr uint32_t SIZE = 20;
    std::vector<uint8_t> temp(SIZE);
    retMsg = { temp.data(), 0 };
    ASSERT_EQ(GetAttributeSerializedMsg(attribute, &retMsg), RESULT_BAD_PARAM);

    retMsg = { temp.data(), static_cast<uint32_t>(temp.size()) };
    ASSERT_EQ(GetAttributeSerializedMsg(attribute, &retMsg), RESULT_SUCCESS);

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestCreateAttributeFromSerializedMsg_001, TestSize.Level0)
{
    Uint8Array msg = { nullptr, 0 };
    ASSERT_EQ(CreateAttributeFromSerializedMsg(msg), nullptr);

    constexpr uint32_t SIZE = 20;
    std::vector<uint8_t> temp(SIZE);
    msg = { temp.data(), 0 };
    ASSERT_EQ(CreateAttributeFromSerializedMsg(msg), nullptr);

    MockMemMgr mock;
    EXPECT_CALL(mock, Malloc(_))
        .WillOnce(Return(nullptr))
        .WillOnce(
            [](const size_t size) {
                void *res = malloc(size);
                static_cast<void>(memset_s(res, size, 0, size));
                return res;
            }
        )
        .WillRepeatedly(Return(nullptr));

    EXPECT_CALL(mock, Free(_))
    .WillRepeatedly(
            [](void *ptr) {
                if (ptr != nullptr) {
                    free(ptr);
                }
            }
        );

    msg = { temp.data(), static_cast<uint32_t>(temp.size()) };
    ASSERT_EQ(CreateAttributeFromSerializedMsg(msg), nullptr);
    ASSERT_EQ(CreateAttributeFromSerializedMsg(msg), nullptr);
}

HWTEST_F(AttributeTest, TestAttributeDeserialize, TestSize.Level0)
{
    const std::vector<AttributeKey> keys = {AUTH_RESULT_CODE, AUTH_SIGNATURE, AUTH_DATA,
        AUTH_REMAIN_COUNT, AUTH_SCHEDULE_MODE, AUTH_REMAIN_TIME, AUTH_SCHEDULE_ID, AUTH_ROOT_SECRET};
    constexpr uint32_t LEN_BASE = 100;
    constexpr uint32_t MAX_BUFFER_LEN = 2000;
    std::vector<uint8_t> msg;
    msg.reserve(MAX_BUFFER_LEN);
    std::vector<std::vector<uint8_t>> rawValues;
    for (const auto key : keys) {
        std::vector<uint8_t> type(sizeof(uint32_t));
        std::vector<uint8_t> len(sizeof(uint32_t));
        std::vector<uint8_t> value;
        uint32_t size = rand() % LEN_BASE + 1;
        static_cast<void>(memcpy_s(type.data(), type.size(), &key, sizeof(key)));
        static_cast<void>(memcpy_s(len.data(), len.size(), &size, sizeof(size)));
        RandomFillVector(value, size);
        msg.insert(msg.end(), type.begin(), type.end());
        msg.insert(msg.end(), len.begin(), len.end());
        msg.insert(msg.end(), value.begin(), value.end());
        rawValues.emplace_back(value);
    }

    Uint8Array data = { msg.data(), static_cast<uint32_t>(msg.size()) };
    Attribute *attribute = CreateAttributeFromSerializedMsg(data);

    for (uint32_t i = 0; i < keys.size(); ++i) {
        std::vector<uint8_t> out(LEN_BASE);
        Uint8Array value = { out.data(), static_cast<uint32_t>(out.size()) };
        ASSERT_EQ(GetAttributeUint8Array(attribute, keys[i], &value), RESULT_SUCCESS);
        out.resize(value.len);
        ASSERT_THAT(rawValues[i], ElementsAreArray(out));
    }

    FreeAttribute(&attribute);
}

HWTEST_F(AttributeTest, TestAttributeSetAndGet, TestSize.Level0)
{
    constexpr uint32_t MAX_MSG_LEN = 1000;
    constexpr uint32_t MAX_SIZE = 10;
    Attribute *originAttribute = CreateEmptyAttribute();
    EXPECT_NE(originAttribute, nullptr);
    uint32_t testUint32 = 123;
    int32_t testInt32 = 123;
    uint64_t testUint64 = 456;
    uint8_t testUint8Buffer[] = { 'a', 'b', 'c' };
    uint64_t testUint64Buffer[] = { 123, 456, 789 };
    Uint8Array testUint8Array = { testUint8Buffer, sizeof(testUint8Buffer) / sizeof(testUint8Buffer[0]) };
    Uint64Array testUint64Array = { testUint64Buffer, sizeof(testUint64Buffer) / sizeof(testUint64Buffer[0]) };
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
    Uint8Array msg = { msgBuffer, sizeof(msgBuffer) / sizeof(msgBuffer[0]) };
    result = GetAttributeSerializedMsg(originAttribute, &msg);
    EXPECT_EQ(result, RESULT_SUCCESS);
    uint32_t parsedUint32;
    int32_t parsedInt32;
    uint64_t parsedUint64;
    uint8_t parsedUint8Buffer[MAX_SIZE];
    uint64_t parsedUint64Buffer[MAX_SIZE];
    Uint8Array parsedUint8Array = { parsedUint8Buffer, sizeof(parsedUint8Buffer) / sizeof(parsedUint8Buffer[0]) };
    Uint64Array parsedUint64Array = { parsedUint64Buffer, sizeof(parsedUint64Buffer) / sizeof(parsedUint64Buffer[0]) };
    Attribute *parsedAttribute = CreateAttributeFromSerializedMsg(msg);
    result = GetAttributeUint32(parsedAttribute, AUTH_IDENTIFY_MODE, &parsedUint32);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(parsedUint32, testUint32);
    result = GetAttributeInt32(parsedAttribute, AUTH_RESULT_CODE, &parsedInt32);
    EXPECT_EQ(parsedInt32, testInt32);
    result = GetAttributeUint64(parsedAttribute, AUTH_SCHEDULE_ID, &parsedUint64);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(parsedUint64, testUint64);
    result = GetAttributeUint8Array(parsedAttribute, AUTH_SIGNATURE, &parsedUint8Array);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(testUint8Array.len, parsedUint8Array.len);
    EXPECT_EQ(testUint8Array.data[2], parsedUint8Array.data[2]);
    result = GetAttributeUint64Array(parsedAttribute, AUTH_TEMPLATE_ID_LIST, &parsedUint64Array);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(testUint64Array.len, parsedUint64Array.len);
    EXPECT_EQ(testUint64Array.data[2], parsedUint64Array.data[2]);
    FreeAttribute(&originAttribute);
    FreeAttribute(&parsedAttribute);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS