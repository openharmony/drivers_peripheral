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

#include "pin_db.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;
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
    (void)memset_s(pinEnrollParam->salt, CONST_SALT_LEN, 1, CONST_SALT_LEN);
    (void)memset_s(pinEnrollParam->pinData, CONST_PIN_DATA_LEN, 1, CONST_PIN_DATA_LEN);
    uint64_t templateId = 0;
    Buffer *outRootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    uint32_t result = AddPin(pinEnrollParam, &templateId, outRootSecret);
    EXPECT_EQ(result, RESULT_SUCCESS);
    delete pinEnrollParam;

    Buffer *pinData = CreateBufferBySize(CONST_PIN_DATA_LEN);
    ASSERT_NE(pinData, nullptr);
    (void)memset_s(pinData->buf, pinData->maxSize, 1, pinData->maxSize);
    pinData->contentSize = pinData->maxSize;
    ResultCode compareRet = RESULT_GENERAL_ERROR;
    result = AuthPinById(pinData, 0, outRootSecret, &compareRet);
    EXPECT_EQ(result, RESULT_BAD_MATCH);

    result = AuthPinById(nullptr, 0, outRootSecret, &compareRet);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    pinData->contentSize = 0;
    result = AuthPinById(pinData, templateId, outRootSecret, &compareRet);
    EXPECT_EQ(result, RESULT_BAD_PARAM);
    pinData->contentSize = pinData->maxSize;

    result = AuthPinById(pinData, INVALID_TEMPLATE_ID, outRootSecret, &compareRet);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = AuthPinById(pinData, templateId, nullptr, &compareRet);
    EXPECT_EQ(result, RESULT_SUCCESS);

    result = AuthPinById(pinData, templateId, outRootSecret, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = AuthPinById(pinData, templateId, outRootSecret, &compareRet);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(compareRet, RESULT_SUCCESS);

    (void)memset_s(pinData->buf, pinData->maxSize, 2, pinData->maxSize);
    result = AuthPinById(pinData, templateId, outRootSecret, &compareRet);
    EXPECT_EQ(result, RESULT_SUCCESS);
    EXPECT_EQ(compareRet, RESULT_COMPARE_FAIL);

    result = DelPinById(templateId);
    EXPECT_EQ(result, RESULT_SUCCESS);
    DestroyBuffer(outRootSecret);
    DestroyBuffer(pinData);
}

/**
 * @tc.name: DoGetAlgoParameter test
 * @tc.desc: verify DoGetAlgoParameter
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, DoGetAlgoParameter_test, TestSize.Level1)
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
    DestroyBuffer(outRootSecret);

    uint32_t satLen = CONST_SALT_LEN;
    std::vector<uint8_t> saltRes(CONST_SALT_LEN, 0);
    uint32_t algoVersion;
    result = DoGetAlgoParameter(INVALID_TEMPLATE_ID, &(saltRes[0]), &satLen, &algoVersion);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = DoGetAlgoParameter(templateId, nullptr, &satLen, &algoVersion);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = DoGetAlgoParameter(templateId, &(saltRes[0]), nullptr, &algoVersion);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = DoGetAlgoParameter(0, &(saltRes[0]), &satLen, &algoVersion);
    EXPECT_EQ(result, RESULT_BAD_MATCH);

    result = DoGetAlgoParameter(templateId, &(saltRes[0]), &satLen, &algoVersion);
    EXPECT_EQ(algoVersion, 0);
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
    DestroyBuffer(outRootSecret);

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
    DestroyBuffer(outRootSecret);

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
    DestroyBuffer(outRootSecret);

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
    DestroyBuffer(outRootSecret);

    uint32_t authErrorCount = 0;
    uint64_t startFreezeTime = 0;
    result = GetAntiBruteInfo(INVALID_TEMPLATE_ID, &authErrorCount, &startFreezeTime);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetAntiBruteInfo(templateId, nullptr, &startFreezeTime);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetAntiBruteInfo(templateId, &authErrorCount, nullptr);
    EXPECT_EQ(result, RESULT_BAD_PARAM);

    result = GetAntiBruteInfo(0, &authErrorCount, &startFreezeTime);
    EXPECT_EQ(result, RESULT_BAD_MATCH);

    result = GetAntiBruteInfo(templateId, &authErrorCount, &startFreezeTime);
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

/**
 * @tc.name: GetNextFailLockoutDuration test
 * @tc.desc: get next fail lockout duration
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinDataBaseTest, GetNextFailLockoutDuration_test, TestSize.Level1)
{
    const uint32_t MS_OF_S = 1000uLL;
    const uint32_t ONE_MIN_TIME = 60;
    EXPECT_EQ(ONE_MIN_TIME * MS_OF_S, GetNextFailLockoutDuration(0));

    const uint32_t FIRST_ANTI_BRUTE_COUNT = 5;
    const uint32_t TEN_MIN_TIME = 600;
    EXPECT_EQ(TEN_MIN_TIME * MS_OF_S, GetNextFailLockoutDuration(FIRST_ANTI_BRUTE_COUNT));

    const uint32_t SECOND_ANTI_BRUTE_COUNT = 8;
    const uint32_t THIRTY_MIN_TIME = 1800;
    EXPECT_EQ(THIRTY_MIN_TIME * MS_OF_S, GetNextFailLockoutDuration(SECOND_ANTI_BRUTE_COUNT));

    const uint32_t THIRD_ANTI_BRUTE_COUNT = 11;
    const uint32_t ONE_HOUR_TIME = 3600;
    EXPECT_EQ(ONE_HOUR_TIME * MS_OF_S, GetNextFailLockoutDuration(THIRD_ANTI_BRUTE_COUNT));

    const uint32_t AUTH_ERROR_COUNT01 = 98;
    const uint32_t FAIL_LOCKOUT_DURATION01 = 3840;
    const uint32_t ATTI_BRUTE_FIRST_STAGE = 100;
    EXPECT_EQ(FAIL_LOCKOUT_DURATION01 * MS_OF_S, GetNextFailLockoutDuration(AUTH_ERROR_COUNT01));
    EXPECT_EQ(FAIL_LOCKOUT_DURATION01 * MS_OF_S, GetNextFailLockoutDuration(ATTI_BRUTE_FIRST_STAGE));

    const uint32_t ATTI_BRUTE_SECOND_STAGE = 140;
    const uint32_t ONE_DAY_TIME = 86400;
    EXPECT_EQ(ONE_DAY_TIME * MS_OF_S, GetNextFailLockoutDuration(ATTI_BRUTE_SECOND_STAGE - 1));
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
