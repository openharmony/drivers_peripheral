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

#include "pin_db_test.h"

#include <gtest/gtest.h>

#include "pin_db.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;
namespace {
    constexpr uint32_t ROOT_SECRET_LEN = 32U;
}

void PinDataBaseTest::SetUpTestCase()
{
}

void PinDataBaseTest::TearDownTestCase()
{
}

void PinDataBaseTest::SetUp()
{
}

void PinDataBaseTest::TearDown()
{
}

/**
 * @tc.name: AddAndAuth test
 * @tc.desc: verify  AddAndAuth
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, AddAndAuth_test, TestSize.Level1)
{
    PinEnrollParam *pinEnrollParam = new (std::nothrow) PinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);

    pinEnrollParam->scheduleId = 1;
    pinEnrollParam->subType = 10010;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    (void)memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN);
    (void)memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN);

    uint64_t templateId = 0;
    Buffer *outRootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    uint32_t result = AddPin(pinEnrollParam, &templateId, outRootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    delete pinEnrollParam;

    result = AuthPinById(&pinData[0], CONST_PIN_DATA_LEN, 0, outRootSecret);
    EXPECT_EQ(result, RESULT_BAD_MATCH);

    result = AuthPinById(nullptr, CONST_PIN_DATA_LEN, 0, outRootSecret);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = AuthPinById(&pinData[0], CONST_PIN_DATA_LEN, templateId, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = AuthPinById(&pinData[0], CONST_PIN_DATA_LEN, templateId, outRootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = DelPinById(templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
    DestoryBuffer(outRootSecret);
}

/**
 * @tc.name: DoGetSalt test
 * @tc.desc: verify DoGetSalt
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, DoGetSalt_test, TestSize.Level1)
{
    PinEnrollParam *pinEnrollParam = new (std::nothrow) PinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);

    pinEnrollParam->scheduleId = 1;
    pinEnrollParam->subType = 10010;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    (void)memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN);
    (void)memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN);

    uint64_t templateId = 0;
    Buffer *outRootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    EXPECT_NE(outRootSecret, nullptr);
    uint32_t result = AddPin(pinEnrollParam, &templateId, outRootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    delete pinEnrollParam;
    DestoryBuffer(outRootSecret);

    uint32_t satLen = CONST_SALT_LEN;
    std::vector<uint8_t> saltRes(CONST_SALT_LEN, 0);
    result = DoGetSalt(INVALID_TEMPLATE_ID, &(saltRes[0]), &satLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = DoGetSalt(templateId, nullptr, &satLen);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = DoGetSalt(templateId, &(saltRes[0]), nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = DoGetSalt(0, &(saltRes[0]), &satLen);
    EXPECT_EQ(result, RESULT_BAD_MATCH);

    result = DoGetSalt(templateId, &(saltRes[0]), &satLen);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = DelPinById(templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

/**
 * @tc.name: ComputeFreezeTime test
 * @tc.desc: verify ComputeFreezeTime
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, ComputeFreezeTime_test, TestSize.Level1)
{
    PinEnrollParam *pinEnrollParam = new (std::nothrow) PinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);

    pinEnrollParam->scheduleId = 1;
    pinEnrollParam->subType = 10010;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    (void)memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN);
    (void)memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN);

    uint64_t templateId = 0;
    Buffer *outRootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    EXPECT_NE(outRootSecret, nullptr);
    uint32_t result = AddPin(pinEnrollParam, &templateId, outRootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    delete pinEnrollParam;
    DestoryBuffer(outRootSecret);

    uint32_t freezeTime = 0;
    result = ComputeFreezeTime(INVALID_TEMPLATE_ID, &freezeTime, 0, 0);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = ComputeFreezeTime(templateId, nullptr, 0, 0);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = ComputeFreezeTime(0, nullptr, 0, 0);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = ComputeFreezeTime(templateId, &freezeTime, 0, 0);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = DelPinById(templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

/**
 * @tc.name: GetRemainTimes test
 * @tc.desc: verify GetRemainTimes
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, GetRemainTimes_test, TestSize.Level1)
{
    PinEnrollParam *pinEnrollParam = new (std::nothrow) PinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);

    pinEnrollParam->scheduleId = 1;
    pinEnrollParam->subType = 10010;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    (void)memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN);
    (void)memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN);

    uint64_t templateId = 0;
    Buffer *outRootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    EXPECT_NE(outRootSecret, nullptr);
    uint32_t result = AddPin(pinEnrollParam, &templateId, outRootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    delete pinEnrollParam;
    DestoryBuffer(outRootSecret);

    uint32_t remainingAuthTimes = 0;
    result = GetRemainTimes(INVALID_TEMPLATE_ID, &remainingAuthTimes, 0);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetRemainTimes(templateId, nullptr, 0);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetRemainTimes(templateId, &remainingAuthTimes, 0);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = DelPinById(templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

/**
 * @tc.name: GetSubType test
 * @tc.desc: verify GetSubType
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, GetSubType_test, TestSize.Level1)
{
    PinEnrollParam *pinEnrollParam = new (std::nothrow) PinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);

    pinEnrollParam->scheduleId = 1;
    pinEnrollParam->subType = 10010;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    (void)memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN);
    (void)memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN);

    uint64_t templateId = 0;
    Buffer *outRootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    EXPECT_NE(outRootSecret, nullptr);
    uint32_t result = AddPin(pinEnrollParam, &templateId, outRootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    delete pinEnrollParam;
    DestoryBuffer(outRootSecret);

    uint64_t subType = 0;
    result = GetSubType(INVALID_TEMPLATE_ID, &subType);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetSubType(0, &subType);
    EXPECT_EQ(result, RESULT_BAD_MATCH);

    result = GetSubType(templateId, &subType);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = DelPinById(templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

/**
 * @tc.name: GetAntiBruteInfo test
 * @tc.desc: verify GetAntiBruteInfo
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, GetAntiBruteInfo_test, TestSize.Level1)
{
    PinEnrollParam *pinEnrollParam = new (std::nothrow) PinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);

    pinEnrollParam->scheduleId = 1;
    pinEnrollParam->subType = 10010;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    (void)memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN);
    (void)memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN);

    uint64_t templateId = 0;
    Buffer *outRootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    EXPECT_NE(outRootSecret, nullptr);
    uint32_t result = AddPin(pinEnrollParam, &templateId, outRootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    delete pinEnrollParam;
    DestoryBuffer(outRootSecret);

    uint32_t authErrorConut = 0;
    uint64_t startFreezeTime = 0;
    result = GetAntiBruteInfo(INVALID_TEMPLATE_ID, &authErrorConut, &startFreezeTime);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetAntiBruteInfo(templateId, nullptr, &startFreezeTime);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetAntiBruteInfo(templateId, &authErrorConut, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetAntiBruteInfo(0, &authErrorConut, &startFreezeTime);
    EXPECT_EQ(result, RESULT_BAD_MATCH);

    result = GetAntiBruteInfo(templateId, &authErrorConut, &startFreezeTime);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = DelPinById(templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
}

/**
 * @tc.name: VerifyTemplateDataPin test
 * @tc.desc: verify VerifyTemplateDataPin
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, VerifyTemplateDataPin_test, TestSize.Level1)
{
    std::vector<uint64_t> templateIdList = {1, 0};
    uint32_t templateIdListLen = 2;
    uint32_t result = VerifyTemplateDataPin(&templateIdList[0], templateIdListLen);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = VerifyTemplateDataPin(nullptr, 1);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
