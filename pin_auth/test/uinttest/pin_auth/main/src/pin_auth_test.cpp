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

#include "pin_auth_test.h"

#include <gtest/gtest.h>

#include "pin_auth.h"
#include "defines.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;
namespace {
    constexpr uint32_t CONST_SALT_LEN  = 32U;
    constexpr uint32_t CONST_PIN_DATA_LEN = 64U;
    constexpr uint64_t INVALID_TEMPLATE_ID = 0xFFFFFFFFFFFFFFFF;
    uint64_t g_antiTemplateId = 0;
}

void PinAuthTest::SetUpTestCase()
{
}

void PinAuthTest::TearDownTestCase()
{
}

void PinAuthTest::SetUp()
{
}

void PinAuthTest::TearDown()
{
}

/**
 * @tc.name: EnrollPin test
 * @tc.desc: verify EnrollPin
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, EnrollPin_test, TestSize.Level1)
{
    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> salt(30, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    int32_t result = pinAuth->EnrollPin(0, 10010, salt, pinData, resultTlv);
    EXPECT_EQ(result, INVALID_PARAMETERS);

    std::vector<uint8_t> salt1(CONST_SALT_LEN, 1);
    result = pinAuth->EnrollPin(0, 10010, salt1, std::vector<uint8_t>{}, resultTlv);
    EXPECT_EQ(result, INVALID_PARAMETERS);
    delete pinAuth;
}

/**
 * @tc.name: GetSalt test
 * @tc.desc: verify GetSalt
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, GetSalt_test, TestSize.Level1)
{
    std::vector<uint8_t> salt;
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    int32_t result = pinAuth->GetSalt(INVALID_TEMPLATE_ID, salt);
    EXPECT_EQ(result, INVALID_PARAMETERS);

    result = pinAuth->GetSalt(0, salt);
    EXPECT_EQ(result, GENERAL_ERROR);
    delete pinAuth;
}

/**
 * @tc.name: AuthPin test
 * @tc.desc: verify AuthPin
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, AuthPin_test, TestSize.Level1)
{
    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    int32_t result = pinAuth->AuthPin(0, 1, std::vector<uint8_t>{}, resultTlv);
    EXPECT_EQ(result, INVALID_PARAMETERS);

    result = pinAuth->AuthPin(0, INVALID_TEMPLATE_ID, pinData, resultTlv);
    EXPECT_EQ(result, GENERAL_ERROR);
    delete pinAuth;
}

/**
 * @tc.name: QueryPinInfo test
 * @tc.desc: verify QueryPinInfo
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, QueryPinInfo_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    PinCredentialInfo pinCredentialInfo = {};
    int32_t result = pinAuth->QueryPinInfo(0, pinCredentialInfo);
    EXPECT_EQ(result, GENERAL_ERROR);

    result = pinAuth->QueryPinInfo(INVALID_TEMPLATE_ID, pinCredentialInfo);
    EXPECT_EQ(result, INVALID_PARAMETERS);
    delete pinAuth;
}

/**
 * @tc.name: DeleteTemplate test
 * @tc.desc: verify DeleteTemplate
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, DeleteTemplate_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    int32_t result = pinAuth->DeleteTemplate(0);
    EXPECT_EQ(result, GENERAL_ERROR);

    result = pinAuth->DeleteTemplate(INVALID_TEMPLATE_ID);
    EXPECT_EQ(result, GENERAL_ERROR);
    delete pinAuth;
}

/**
 * @tc.name: GetExecutorInfo test
 * @tc.desc: verify GetExecutorInfo
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, GetExecutorInfo_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    std::vector<uint8_t> pubKey;
    uint32_t esl = 0;
    int32_t result = pinAuth->GetExecutorInfo(pubKey, esl);
    EXPECT_EQ(result, GENERAL_ERROR);
    delete pinAuth;
}

/**
 * @tc.name: VerifyTemplateData test
 * @tc.desc: verify VerifyTemplateData
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, VerifyTemplateData_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    std::vector<uint64_t> templateIdList = {};
    int32_t result = pinAuth->VerifyTemplateData(templateIdList);
    EXPECT_EQ(result, SUCCESS);
    delete pinAuth;
}

/**
 * @tc.name: Pin_Auth_Succ test
 * @tc.desc: verify enroll auth query and get...
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, Pin_Auth_Succ_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    pinAuth->Init();
    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    int32_t result = pinAuth->EnrollPin(0, 10010, salt, pinData, resultTlv);
    EXPECT_EQ(result, SUCCESS);
    uint64_t templateId = 0;
    (void)memcpy_s(&templateId, 8, &(resultTlv[36]), 8);

    result = pinAuth->AuthPin(0, templateId, pinData, resultTlv);
    EXPECT_EQ(result, SUCCESS);

    std::vector<uint8_t> saltRet;
    result = pinAuth->GetSalt(templateId, saltRet);
    EXPECT_EQ(result, SUCCESS);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(templateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 5);
    EXPECT_EQ(pinCredentialInfo.freezingTime, 0);

    std::vector<uint8_t> pubKey;
    uint32_t esl = 0;
    result = pinAuth->GetExecutorInfo(pubKey, esl);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(esl, 2);

    result = pinAuth->DeleteTemplate(templateId);
    EXPECT_EQ(result, SUCCESS);

    std::vector<uint64_t> templateIdList = {templateId, 1};
    result = pinAuth->VerifyTemplateData(templateIdList);
    EXPECT_EQ(result, SUCCESS);

    pinAuth->Close();
    delete pinAuth;
}

/**
 * @tc.name: Pin_Auth_AntiBruteInfo1_test test
 * @tc.desc: The first authentication failed
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, Pin_Auth_AntiBruteInfo1_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    pinAuth->Init();
    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    int32_t result = pinAuth->EnrollPin(0, 10010, salt, pinData, resultTlv);
    EXPECT_EQ(result, SUCCESS);
    (void)memcpy_s(&g_antiTemplateId, 8, &(resultTlv[36]), 8);

    /* The first auth failed */
    std::vector<uint8_t> pinErrorData(CONST_PIN_DATA_LEN, 2);
    result = pinAuth->AuthPin(0, g_antiTemplateId, pinErrorData, resultTlv);
    EXPECT_EQ(result, FAIL);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 4);
    EXPECT_EQ(pinCredentialInfo.freezingTime, 0);

    delete pinAuth;
}

/**
 * @tc.name: Pin_Auth_AntiBruteInfo2_test test
 * @tc.desc: Two consecutive authentication failed
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, Pin_Auth_AntiBruteInfo2_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);

    /* The second auth failed */
    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> pinErrorData(CONST_PIN_DATA_LEN, 2);
    int32_t result = pinAuth->AuthPin(0, g_antiTemplateId, pinErrorData, resultTlv);
    EXPECT_EQ(result, FAIL);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 3);
    EXPECT_EQ(pinCredentialInfo.freezingTime, 0);

    delete pinAuth;
}

/**
 * @tc.name: Pin_Auth_AntiBruteInfo3_test test
 * @tc.desc: Three consecutive authentication failed
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, Pin_Auth_AntiBruteInfo3_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);

    /* The third auth failed */
    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> pinErrorData(CONST_PIN_DATA_LEN, 2);
    int32_t result = pinAuth->AuthPin(0, g_antiTemplateId, pinErrorData, resultTlv);
    EXPECT_EQ(result, FAIL);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 2);
    EXPECT_EQ(pinCredentialInfo.freezingTime, 0);

    delete pinAuth;
}

/**
 * @tc.name: Pin_Auth_AntiBruteInfo4_test test
 * @tc.desc: Four consecutive authentication failed
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, Pin_Auth_AntiBruteInfo4_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);

    /* The fourth auth failed */
    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> pinErrorData(CONST_PIN_DATA_LEN, 2);
    int32_t result = pinAuth->AuthPin(0, g_antiTemplateId, pinErrorData, resultTlv);
    EXPECT_EQ(result, FAIL);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 1);
    EXPECT_EQ(pinCredentialInfo.freezingTime, 0);

    delete pinAuth;
}

/**
 * @tc.name: Pin_Auth_AntiBruteInfo5_test test
 * @tc.desc: Five consecutive authentication failed
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, Pin_Auth_AntiBruteInfo5_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);

    /* The fifth auth failed */
    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> pinErrorData(CONST_PIN_DATA_LEN, 2);
    int32_t result = pinAuth->AuthPin(0, g_antiTemplateId, pinErrorData, resultTlv);
    EXPECT_EQ(result, FAIL);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 0);
    EXPECT_LE(pinCredentialInfo.freezingTime, 60000);
    EXPECT_GE(pinCredentialInfo.freezingTime, 58000);

    pinAuth->Close();
    delete pinAuth;
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
