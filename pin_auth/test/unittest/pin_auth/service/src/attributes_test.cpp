/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "attributes_test.h"

#include <climits>

#include "attributes.h"

namespace OHOS {
namespace HDI {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;

void AttributesTest::SetUpTestCase()
{
}

void AttributesTest::TearDownTestCase()
{
}

void AttributesTest::SetUp()
{
}

void AttributesTest::TearDown()
{
}

HWTEST_F(AttributesTest, AttributesInit, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_EQ(attrs.Serialize().size(), 0U);
}

HWTEST_F(AttributesTest, AttributesSerialize, TestSize.Level0)
{
    const std::vector<Attributes::AttributeKey> desired = {Attributes::AUTH_EXPIRED_SYS_TIME};

    Attributes attrs;
    EXPECT_TRUE(attrs.SetUint64Value(Attributes::AUTH_EXPIRED_SYS_TIME, UINT64_MAX));

    EXPECT_THAT(attrs.GetKeys(), ElementsAreArray(desired));
    auto buff = attrs.Serialize();
    Attributes attrs2(buff);
    EXPECT_THAT(attrs2.GetKeys(), ElementsAreArray(desired));

    uint64_t u64Value;
    EXPECT_TRUE(attrs2.GetUint64Value(Attributes::AUTH_EXPIRED_SYS_TIME, u64Value));
    EXPECT_EQ(u64Value, UINT64_MAX);
}

HWTEST_F(AttributesTest, AttributesUint64Value, TestSize.Level0)
{
    Attributes attrs1;
    uint64_t value1;
    EXPECT_TRUE(attrs1.SetUint64Value(Attributes::AUTH_EXPIRED_SYS_TIME, UINT32_MAX));
    EXPECT_TRUE(attrs1.GetUint64Value(Attributes::AUTH_EXPIRED_SYS_TIME, value1));
    EXPECT_EQ(value1, UINT32_MAX);

    Attributes attrs2;
    uint64_t value2;
    EXPECT_TRUE(attrs2.SetUint64Value(Attributes::AUTH_EXPIRED_SYS_TIME, UINT64_MAX));
    EXPECT_TRUE(attrs2.GetUint64Value(Attributes::AUTH_EXPIRED_SYS_TIME, value2));
    EXPECT_EQ(value2, UINT64_MAX);
}

HWTEST_F(AttributesTest, AttributesUint8ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint8_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(i);
        }
        EXPECT_TRUE(attrs.SetUint8ArrayValue(Attributes::AUTH_ROOT, array));

        std::vector<uint8_t> out;
        EXPECT_TRUE(attrs.GetUint8ArrayValue(Attributes::AUTH_ROOT, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint8_t> array;
        EXPECT_TRUE(attrs.SetUint8ArrayValue(Attributes::AUTH_ROOT, array));

        EXPECT_TRUE(attrs.GetUint8ArrayValue(Attributes::AUTH_ROOT, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesEmptyArrays, TestSize.Level0)
{
    Attributes attrs1;
    std::vector<uint8_t> u8Vector;
    EXPECT_TRUE(attrs1.SetUint8ArrayValue(Attributes::AUTH_ROOT, u8Vector));

    EXPECT_TRUE(attrs1.GetUint8ArrayValue(Attributes::AUTH_ROOT, u8Vector));
    EXPECT_THAT(u8Vector, IsEmpty());
}

HWTEST_F(AttributesTest, AttributesCopyAndMove, TestSize.Level0)
{
    EXPECT_FALSE(std::is_copy_assignable<Attributes>::value);
    EXPECT_FALSE(std::is_copy_constructible<Attributes>::value);

    const std::vector<uint8_t> raw = {0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 255,
        255, 255, 255, 3, 0, 0, 0, 8, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 4, 0, 0, 0, 4, 0, 0, 0, 105, 97,
        109, 0, 5, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 6, 0, 0, 0, 40, 0,
        0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0,
        0, 0, 0, 0, 0};
    Attributes attrs1(raw);

    EXPECT_THAT(attrs1.Serialize(), ElementsAreArray(raw));

    Attributes attrs2 = std::move(attrs1);

    EXPECT_EQ(attrs1.Serialize().size(), 0U);
    EXPECT_THAT(attrs2.Serialize(), ElementsAreArray(raw));
}
} // namespace PinAuth
} // namespace HDI
} // namespace OHOS
