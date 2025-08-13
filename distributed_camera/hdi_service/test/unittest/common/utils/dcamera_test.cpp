/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dcamera.h"
#include "constants.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
class DCameraTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void DCameraTest::SetUpTestCase(void)
{
}

void DCameraTest::TearDownTestCase(void)
{
}

void DCameraTest::SetUp(void)
{
}

void DCameraTest::TearDown(void)
{
}

/**
 * @tc.name: MapToExternalRetCode_001
 * @tc.desc: Verify MapToExternalRetCode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, MapToExternalRetCode_001, TestSize.Level1)
{
    CamRetCode result = MapToExternalRetCode(DCamRetCode::SUCCESS);
    EXPECT_EQ(result, CamRetCode::NO_ERROR);

    result = MapToExternalRetCode(DCamRetCode::CAMERA_BUSY);
    EXPECT_EQ(result, CamRetCode::CAMERA_BUSY);

    result = MapToExternalRetCode(DCamRetCode::INVALID_ARGUMENT);
    EXPECT_EQ(result, CamRetCode::INVALID_ARGUMENT);

    result = MapToExternalRetCode(DCamRetCode::METHOD_NOT_SUPPORTED);
    EXPECT_EQ(result, CamRetCode::METHOD_NOT_SUPPORTED);

    result = MapToExternalRetCode(DCamRetCode::CAMERA_OFFLINE);
    EXPECT_EQ(result, CamRetCode::CAMERA_CLOSED);

    result = MapToExternalRetCode(DCamRetCode::EXCEED_MAX_NUMBER);
    EXPECT_EQ(result, CamRetCode::INSUFFICIENT_RESOURCES);

    result = MapToExternalRetCode(DCamRetCode::FAILED);
    EXPECT_EQ(result, CamRetCode::DEVICE_ERROR);

    result = MapToExternalRetCode(static_cast<DCamRetCode>(999));
    EXPECT_EQ(result, CamRetCode::DEVICE_ERROR);
}

/**
 * @tc.name: SplitString_001
 * @tc.desc: Verify SplitString
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, SplitString_001, TestSize.Level1)
{
    std::string input = "";
    std::string delimiter = ",";
    std::vector<std::string> tokens;
    SplitString(input, tokens, delimiter);
    EXPECT_TRUE(tokens.empty());
}

/**
 * @tc.name: Base64Encode_001
 * @tc.desc: Verify Base64Encode and Base64Decode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, Base64Encode_001, TestSize.Level1)
{
    const unsigned char* input = nullptr;
    unsigned int length = 0;

    std::string result = Base64Encode(input, length);
    EXPECT_EQ(result, "");

    length = 1;
    result = Base64Encode(input, length);
    EXPECT_EQ(result, "");

    std::string ret = Base64Decode(result);
    EXPECT_EQ(ret, "");
}

/**
 * @tc.name: Base64Encode_002
 * @tc.desc: Verify Base64Encode and Base64Decode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, Base64Encode_002, TestSize.Level1)
{
    const unsigned char input[] = "A";
    unsigned int length = 1;

    std::string result = Base64Encode(input, length);
    EXPECT_FALSE(result.empty());

    std::string ret = Base64Decode(result);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.name: Base64Encode_003
 * @tc.desc: Verify Base64Encode and Base64Decode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, Base64Encode_003, TestSize.Level1)
{
    const unsigned char input[] = "AB";
    unsigned int length = 2;

    std::string result = Base64Encode(input, length);
    EXPECT_FALSE(result.empty());

    std::string ret = Base64Decode(result);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.name: Base64Encode_004
 * @tc.desc: Verify Base64Encode and Base64Decode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, Base64Encode_004, TestSize.Level1)
{
    const unsigned char input[] = "ABC";
    unsigned int length = 3;

    std::string result = Base64Encode(input, length);
    EXPECT_FALSE(result.empty());

    std::string ret = Base64Decode(result);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.name: Base64Encode_005
 * @tc.desc: Verify Base64Encode and Base64Decode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, Base64Encode_005, TestSize.Level1)
{
    const unsigned char input[] = "ABCD";
    unsigned int length = 4;

    std::string result = Base64Encode(input, length);
    EXPECT_FALSE(result.empty());

    std::string ret = Base64Decode(result);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.name: Base64Encode_006
 * @tc.desc: Verify Base64Encode and Base64Decode
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, Base64Encode_006, TestSize.Level1)
{
    const unsigned char input[] = "Hello World";
    unsigned int length = 11;

    std::string result = Base64Encode(input, length);
    EXPECT_FALSE(result.empty());

    std::string ret = Base64Decode(result);
    EXPECT_FALSE(ret.empty());
}

/**
 * @tc.name: GetCurrentLocalTimeStamp_001
 * @tc.desc: Verify GetCurrentLocalTimeStamp
 * @tc.type: FUNC
 * @tc.require: AR
 */
HWTEST_F(DCameraTest, GetCurrentLocalTimeStamp_001, TestSize.Level1)
{
    uint64_t ret = GetCurrentLocalTimeStamp();
    EXPECT_TRUE(ret);
}
}
}