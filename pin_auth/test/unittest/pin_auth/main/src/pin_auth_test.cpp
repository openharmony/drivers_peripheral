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

#include "securec.h"

#include "attribute.h"
#include "common_impl.h"
#include "defines.h"
#include "pin_auth.h"
#include "pin_auth_hdi.h"

#include "adaptor_log.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
using namespace testing;
using namespace testing::ext;
namespace {
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

static PinEnrollParam *getPinEnrollParam()
{
    PinEnrollParam *pinEnrollParam = new (std::nothrow) PinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);

    uint32_t pinLength = 6;
    uint64_t subType = 10010;
    pinEnrollParam->scheduleId = 1;
    pinEnrollParam->subType = subType;
    pinEnrollParam->pinLength = pinLength;
    std::vector<uint8_t> salt(CONST_SALT_LEN, 1);
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    (void)memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN);
    (void)memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN);
    return pinEnrollParam;
}

static PinAuthParam *getPinAuthParam()
{
    PinAuthParam *pinAuthParam = new (std::nothrow) PinAuthParam();
    EXPECT_NE(pinAuthParam, nullptr);

    uint64_t templateId = 123;
    uint32_t pinLength = 6;
    pinAuthParam->scheduleId = 1;
    pinAuthParam->templateId = templateId;
    pinAuthParam->pinLength = pinLength;
    std::vector<uint8_t> pinData(CONST_PIN_DATA_LEN, 1);
    (void)memcpy_s(&(pinAuthParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN);
    return pinAuthParam;
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
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    PinEnrollParam *pinEnrollParam = getPinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);
    int32_t result = pinAuth->EnrollPin(*pinEnrollParam, resultTlv);
    EXPECT_EQ(result, INVALID_PARAMETERS);
    delete pinAuth;
}

/**
 * @tc.name: AllInOneAuth test
 * @tc.desc: verify AllInOneAuth
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, AllInOneAuth_test, TestSize.Level1)
{
    std::vector<uint8_t> salt;
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    std::vector<uint8_t> extraInfo;
    PinAlgoParam pinAlgoParam = {};
    int32_t result = pinAuth->AllInOneAuth(0, INVALID_TEMPLATE_ID, extraInfo, pinAlgoParam);
    EXPECT_EQ(result, INVALID_PARAMETERS);

    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> fwkPubKey(32);
    result = pinAuth->SetAllInOneFwkParam(templateIdList, fwkPubKey);
    EXPECT_EQ(result, SUCCESS);

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
    std::vector<uint8_t> extraInfo;
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    PinAuthParam *pinAuthParam = getPinAuthParam();
    EXPECT_NE(pinAuthParam, nullptr);
    int32_t result = pinAuth->AuthPin(*pinAuthParam, extraInfo, resultTlv);
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
    uint32_t acl = 0;
    int32_t result = pinAuth->GetExecutorInfo(HDI::PinAuth::HdiExecutorRole::SCHEDULER, pubKey, esl, acl);
    EXPECT_EQ(result, GENERAL_ERROR);
    delete pinAuth;
}

/**
 * @tc.name: SetAllInOneFwkParam test
 * @tc.desc: verify SetAllInOneFwkParam
 * @tc.type: FUNC
 * @tc.require: #I64XCB
 */
HWTEST_F(PinAuthTest, SetAllInOneFwkParam_test, TestSize.Level1)
{
    PinAuth *pinAuth = new (std::nothrow) PinAuth();
    EXPECT_NE(pinAuth, nullptr);
    std::vector<uint64_t> templateIdList = {};
    std::vector<uint8_t> fwkPubKey = {};

    int32_t result = pinAuth->SetAllInOneFwkParam(templateIdList, fwkPubKey);
    EXPECT_EQ(result, INVALID_PARAMETERS);

    fwkPubKey.resize(32);
    result = pinAuth->SetAllInOneFwkParam(templateIdList, fwkPubKey);
    EXPECT_EQ(result, SUCCESS);
    delete pinAuth;
}

static bool GetTemplateIdFromTlv(std::vector<uint8_t> resultTlv, uint64_t &templateId)
{
    bool ret = false;
    Uint8Array uint8array = {
        .data = resultTlv.data(),
        .len = resultTlv.size(),
    };
    Attribute *attrbute = CreateAttributeFromSerializedMsg(uint8array);
    if (attrbute == NULL) {
        return false;
    }
    ResultCode result = GetAttributeUint8Array(attrbute, ATTR_ROOT, &uint8array);
    if (result != RESULT_SUCCESS) {
        goto EXIT;
    }
    FreeAttribute(&attrbute);
    attrbute = CreateAttributeFromSerializedMsg(uint8array);
    if (attrbute == NULL) {
        goto EXIT;
    }
    result = GetAttributeUint8Array(attrbute, ATTR_DATA, &uint8array);
    if (result != RESULT_SUCCESS) {
        goto EXIT;
    }
    FreeAttribute(&attrbute);
    attrbute = CreateAttributeFromSerializedMsg(uint8array);
    if (attrbute == NULL) {
        goto EXIT;
    }
    result = GetAttributeUint64(attrbute, ATTR_TEMPLATE_ID, &templateId);
    if (result != RESULT_SUCCESS) {
        goto EXIT;
    };
    ret = true;

EXIT:
    FreeAttribute(&attrbute);
    return ret;
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

    KeyPair *keyPair = GenerateEd25519KeyPair();
    ASSERT_NE(keyPair, nullptr);

    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey(keyPair->pubKey->buf, keyPair->pubKey->buf + keyPair->pubKey->contentSize);
    int32_t result = pinAuth->SetAllInOneFwkParam(templateIdList, frameworkPublicKey);
    EXPECT_EQ(result, SUCCESS);

    std::vector<uint8_t> resultTlv;
    std::vector<uint8_t> extraInfo = {};
    PinEnrollParam *pinEnrollParam = getPinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);
    result = pinAuth->EnrollPin(*pinEnrollParam, resultTlv);
    EXPECT_EQ(result, SUCCESS);
    uint64_t templateId = 0;
    bool ret = GetTemplateIdFromTlv(resultTlv, templateId);
    ASSERT_EQ(ret, true);

    PinAuthParam *pinAuthParam = getPinAuthParam();
    EXPECT_NE(pinAuthParam, nullptr);
    pinAuthParam->templateId = templateId;
    result = pinAuth->AuthPin(*pinAuthParam, extraInfo, resultTlv);
    EXPECT_EQ(result, GENERAL_ERROR);

    uint8_t challenge[32] = {0};
    Buffer *fwkExtraInfo = GetAuthFwkExtraInfo(0, keyPair, challenge, 32);
    ASSERT_NE(fwkExtraInfo, nullptr);

    std::vector<uint8_t> authExtraInfo(fwkExtraInfo->buf, fwkExtraInfo->buf + fwkExtraInfo->contentSize);
    PinAlgoParam pinAlgoParam;
    result = pinAuth->AllInOneAuth(0, templateId, authExtraInfo, pinAlgoParam);
    EXPECT_EQ(pinAlgoParam.algoVersion, 0);
    EXPECT_EQ(result, SUCCESS);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(templateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 5);
    EXPECT_EQ(pinCredentialInfo.freezingTime, 0);

    std::vector<uint8_t> pubKey;
    uint32_t esl = 0;
    uint32_t acl = 0;
    result = pinAuth->GetExecutorInfo(HDI::PinAuth::HdiExecutorRole::ALL_IN_ONE, pubKey, esl, acl);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(esl, 2);

    result = pinAuth->DeleteTemplate(templateId);
    EXPECT_EQ(result, SUCCESS);

    pinAuth->Close();
    delete pinAuth;
    DestroyBuffer(fwkExtraInfo);
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
    std::vector<uint8_t> extraInfo;
    PinEnrollParam *pinEnrollParam = getPinEnrollParam();
    EXPECT_NE(pinEnrollParam, nullptr);
    int32_t result = pinAuth->EnrollPin(*pinEnrollParam, resultTlv);
    EXPECT_EQ(result, SUCCESS);
    bool ret = GetTemplateIdFromTlv(resultTlv, g_antiTemplateId);
    ASSERT_EQ(ret, true);
    PinAuthParam *pinAuthParam = getPinAuthParam();
    EXPECT_NE(pinAuthParam, nullptr);
    pinAuthParam->templateId = g_antiTemplateId;
    result = pinAuth->AuthPin(*pinAuthParam, extraInfo, resultTlv);
    EXPECT_EQ(result, GENERAL_ERROR);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 5);
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
    std::vector<uint8_t> extraInfo;
    PinAuthParam *pinAuthParam = getPinAuthParam();
    EXPECT_NE(pinAuthParam, nullptr);
    pinAuthParam->templateId = g_antiTemplateId;
    (void)memcpy_s(&(pinAuthParam->pinData[0]), CONST_PIN_DATA_LEN, &pinErrorData[0], CONST_PIN_DATA_LEN);
    int32_t result = pinAuth->AuthPin(*pinAuthParam, extraInfo, resultTlv);
    EXPECT_EQ(result, GENERAL_ERROR);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 5);
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
    std::vector<uint8_t> extraInfo;
    PinAuthParam *pinAuthParam = getPinAuthParam();
    EXPECT_NE(pinAuthParam, nullptr);
    pinAuthParam->templateId = g_antiTemplateId;
    (void)memcpy_s(&(pinAuthParam->pinData[0]), CONST_PIN_DATA_LEN, &pinErrorData[0], CONST_PIN_DATA_LEN);
    int32_t result = pinAuth->AuthPin(*pinAuthParam, extraInfo, resultTlv);
    EXPECT_EQ(result, GENERAL_ERROR);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 5);
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
    std::vector<uint8_t> extraInfo;
    PinAuthParam *pinAuthParam = getPinAuthParam();
    EXPECT_NE(pinAuthParam, nullptr);
    pinAuthParam->templateId = g_antiTemplateId;
    (void)memcpy_s(&(pinAuthParam->pinData[0]), CONST_PIN_DATA_LEN, &pinErrorData[0], CONST_PIN_DATA_LEN);
    int32_t result = pinAuth->AuthPin(*pinAuthParam, extraInfo, resultTlv);
    EXPECT_EQ(result, GENERAL_ERROR);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 5);
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
    std::vector<uint8_t> extraInfo;
    PinAuthParam *pinAuthParam = getPinAuthParam();
    EXPECT_NE(pinAuthParam, nullptr);
    pinAuthParam->templateId = g_antiTemplateId;
    (void)memcpy_s(&(pinAuthParam->pinData[0]), CONST_PIN_DATA_LEN, &pinErrorData[0], CONST_PIN_DATA_LEN);
    int32_t result = pinAuth->AuthPin(*pinAuthParam, extraInfo, resultTlv);
    EXPECT_EQ(result, GENERAL_ERROR);

    PinCredentialInfo pinCredentialInfo = {};
    result = pinAuth->QueryPinInfo(g_antiTemplateId, pinCredentialInfo);
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(pinCredentialInfo.subType, 10010);
    EXPECT_EQ(pinCredentialInfo.remainTimes, 5);

    pinAuth->Close();
    delete pinAuth;
}

} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
