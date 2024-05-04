/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "all_in_one_func.h"

#include "securec.h"

#include "adaptor_algorithm.h"

static KeyPair *g_keyPair = NULL;
static Buffer *g_fwkPubKey = NULL;

static ResultCode GenerateResultTlv(
    Buffer *retTlv, int32_t resultCode, uint64_t scheduleId, uint64_t templateId, Buffer *rootSecret)
{
    Attribute *attribute = GetAttributeDataBase(scheduleId, REMOTE_PIN_MSG_NONE);
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, RESULT_GENERAL_ERROR);

    int32_t result = RESULT_GENERAL_ERROR;
    if (!SetResultDataInfo(attribute, PinResultToFwkResult(resultCode), templateId, rootSecret)) {
        LOG_ERROR("SetResultDataInfo fail");
        goto EXIT;
    }

    uint32_t tlvSize = retTlv->maxSize;
    result = FormatTlvMsg(attribute, g_keyPair, retTlv->buf, &tlvSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("FormatTlvMsg fail");
        goto EXIT;
    }
    retTlv->contentSize = tlvSize;

EXIT:
    FreeAttribute(&attribute);
    return result;
}

ResultCode DoEnrollPin(PinEnrollParam *pinEnrollParam, Buffer *retTlv)
{
    if (pinEnrollParam == NULL || !IsBufferValid(retTlv)) {
        LOG_ERROR("get invalid params.");
        return RESULT_BAD_PARAM;
    }
    uint64_t templateId = INVALID_TEMPLATE_ID;
    Buffer *rootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    if (!IsBufferValid(rootSecret)) {
        LOG_ERROR("no memory.");
        return RESULT_BAD_PARAM;
    }
    ResultCode ret = AddPin(pinEnrollParam, &templateId, rootSecret);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("AddPin fail.");
        DestroyBuffer(rootSecret);
        return ret;
    }

    ret = GenerateResultTlv(retTlv, RESULT_SUCCESS, pinEnrollParam->scheduleId, templateId, rootSecret);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GenerateRetTlv DoEnrollPin fail.");
    }

    DestroyBuffer(rootSecret);
    return ret;
}

ResultCode DoAllInOneAuth(uint64_t scheduleId, uint64_t templateId,
    const uint8_t *extraInfo, uint32_t extraInfoSize, AlgoParamOut *algoParam)
{
    LOG_INFO("DoAllInOneAuth start %{public}x", (uint16_t)scheduleId);
    if ((extraInfo == NULL) || (extraInfoSize == 0) || (extraInfoSize > MAX_EXECUTOR_MSG_LEN) || (algoParam == NULL)) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }

    ResultCode result = GetSubType(templateId, &(algoParam->subType));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetSubType fail!");
        return result;
    }
    uint32_t algoParameterSize = CONST_SALT_LEN;
    result = DoGetAlgoParameter(templateId, algoParam->algoParameter, &algoParameterSize, &(algoParam->algoVersion));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGetAlgoParameter fail!");
    }
    return result;
}

ResultCode DoAuthPin(PinAuthParam *pinAuthParam, Buffer *retTlv, ResultCode *compareRet)
{
    if (!IsBufferValid(retTlv) || pinAuthParam == NULL || compareRet == NULL) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    *compareRet = RESULT_COMPARE_FAIL;

    PinCredentialInfos pinCredentialInfo = {};
    ResultCode ret = DoQueryPinInfo(pinAuthParam->templateId, &pinCredentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("DoQueryPinInfo fail.");
        return ret;
    }

    Buffer *rootSecret = CreateBufferBySize(ROOT_SECRET_LEN);
    if (!IsBufferValid(rootSecret)) {
        LOG_ERROR("no memory.");
        return RESULT_BAD_PARAM;
    }
    if (pinCredentialInfo.freezeTime == 0) {
        Buffer pinData = GetTmpBuffer(pinAuthParam->pinData, CONST_PIN_DATA_LEN, CONST_PIN_DATA_LEN);
        ret = AuthPinById(&pinData, pinAuthParam->templateId, rootSecret, compareRet);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("AuthPinById fail.");
            goto EXIT;
        }
    } else {
        LOG_ERROR("Pin is freezing.");
        *compareRet = RESULT_PIN_FREEZE;
    }

    ret = GenerateResultTlv(retTlv, *compareRet, pinAuthParam->scheduleId, pinAuthParam->templateId, rootSecret);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GenerateRetTlv DoAuthPin fail.");
    }

EXIT:
    DestroyBuffer(rootSecret);
    return ret;
}

ResultCode DoDeleteTemplate(uint64_t templateId)
{
    ResultCode ret = DelPinById(templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete pin fail.");
        return RESULT_BAD_DEL;
    }
    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
ResultCode GenerateAllInOneKeyPair(void)
{
    DestroyKeyPair(g_keyPair);
    g_keyPair = GenerateEd25519KeyPair();
    if (g_keyPair == NULL) {
        LOG_ERROR("GenerateEd25519Keypair fail!");
        return RESULT_GENERAL_ERROR;
    }
    LOG_INFO("GenerateKeyPair success");
    return RESULT_SUCCESS;
}

void DestroyAllInOneKeyPair(void)
{
    DestroyKeyPair(g_keyPair);
    g_keyPair = NULL;
    LOG_INFO("DestroyKeyPair success");
}

/* This is for example only, Should be implemented in trusted environment. */
ResultCode DoGetAllInOneExecutorInfo(PinExecutorInfo *pinExecutorInfo)
{
    if (pinExecutorInfo == NULL) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        LOG_ERROR("key pair not init!");
        return RESULT_NEED_INIT;
    }
    uint32_t pubKeyLen = ED25519_FIX_PUBKEY_BUFFER_SIZE;
    if (GetBufferData(g_keyPair->pubKey, pinExecutorInfo->pubKey, &pubKeyLen) != RESULT_SUCCESS) {
        LOG_ERROR("GetBufferData fail!");
        return RESULT_UNKNOWN;
    }
    pinExecutorInfo->esl = PIN_EXECUTOR_SECURITY_LEVEL;
    pinExecutorInfo->maxTemplateAcl = PIN_CAPABILITY_LEVEL;
    return RESULT_SUCCESS;
}

ResultCode DoSetAllInOneFwkParam(
    const uint64_t *templateIdList, uint32_t templateIdListLen, const uint8_t *fwkPubKey, uint32_t fwkPubKeySize)
{
    if (((templateIdListLen != 0) && (templateIdList == NULL)) ||
        (fwkPubKey == NULL) || (fwkPubKeySize != ED25519_FIX_PUBKEY_BUFFER_SIZE)) {
        LOG_ERROR("templateIdList should be not null, when templateIdListLen is not zero");
        return RESULT_BAD_PARAM;
    }
    DestroyBuffer(g_fwkPubKey);
    g_fwkPubKey = CreateBufferByData(fwkPubKey, fwkPubKeySize);
    if (g_fwkPubKey == NULL) {
        LOG_ERROR("DoSetAllInOneFwkParam create fwkPubKey fail!");
        return RESULT_NO_MEMORY;
    }
    ResultCode ret = VerifyTemplateDataPin(templateIdList, templateIdListLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("Verify TemplateDataPin fail.");
        return ret;
    }
    return RESULT_SUCCESS;
}

ResultCode DoWriteAntiBruteInfoToFile(uint64_t templateId)
{
    ResultCode ret = RefreshAntiBruteInfoToFile(templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("RefreshAntiBruteInfoToFile fail.");
    }
    return ret;
}
