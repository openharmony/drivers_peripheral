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

#include "pin_auth.h"

#include <map>
#include <sys/stat.h>
#include <vector>
#include <unistd.h>
#include <pthread.h>

#include "parameter.h"
#include "securec.h"
#include "sysparam_errno.h"

#include "adaptor_memory.h"
#include "adaptor_log.h"
#include "all_in_one_func.h"
#include "collector_func.h"
#include "executor_func_common.h"
#include "pin_auth_hdi.h"
#include "verifier_func.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
namespace {
constexpr uint32_t MAX_TEMPLATEID_LEN = 32;
std::map<int32_t, ResultCodeForCoAuth> g_convertResult = {
    {RESULT_SUCCESS, ResultCodeForCoAuth::SUCCESS},
    {RESULT_BAD_PARAM, ResultCodeForCoAuth::INVALID_PARAMETERS},
    {RESULT_COMPARE_FAIL, ResultCodeForCoAuth::FAIL},
    {RESULT_BUSY, ResultCodeForCoAuth::BUSY},
    {RESULT_PIN_FREEZE, ResultCodeForCoAuth::LOCKED},
    {RESULT_BAD_COPY, ResultCodeForCoAuth::GENERAL_ERROR},
    {RESULT_GENERAL_ERROR, ResultCodeForCoAuth::GENERAL_ERROR},
};
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::Init()
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    if (GenerateAllInOneKeyPair() != RESULT_SUCCESS) {
        LOG_ERROR("GenerateAllInOneKeyPair fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    if (GenerateCollectorKeyPair() != RESULT_SUCCESS) {
        LOG_ERROR("GenerateCollectorKeyPair fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    if (GenerateVerifierKeyPair() != RESULT_SUCCESS) {
        LOG_ERROR("GenerateVerifierKeyPair fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    LOG_INFO("InIt pinAuth succ");

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::Close()
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    DestroyAllInOneKeyPair();
    DestroyCollectorKeyPair();
    DestroyVerifierKeyPair();
    DestroyPinDb();
    LOG_INFO("Close pinAuth succ");

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::PinResultToCoAuthResult(int32_t resultCode)
{
    LOG_INFO("PinAuth::PinResultToCoAuthResult enter");
    if (g_convertResult.count(resultCode) == 0) {
        LOG_ERROR("PinResult and CoauthResult not match, convert GENERAL_ERROR");
        return ResultCodeForCoAuth::GENERAL_ERROR;
    } else {
        return g_convertResult[resultCode];
    }
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::EnrollPin(uint64_t scheduleId, uint64_t subType, std::vector<uint8_t> &salt,
    const std::vector<uint8_t> &pinData, std::vector<uint8_t> &resultTlv)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    if (salt.size() != CONST_SALT_LEN || pinData.size() != CONST_PIN_DATA_LEN) {
        LOG_ERROR("get bad params!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    PinEnrollParam pinEnrollParam = {};
    pinEnrollParam.scheduleId = scheduleId;
    pinEnrollParam.subType = subType;
    if (memcpy_s(&(pinEnrollParam.salt[0]), CONST_SALT_LEN, salt.data(), CONST_SALT_LEN) != EOK) {
        LOG_ERROR("copy salt to pinEnrollParam fail!");
        return PinResultToCoAuthResult(RESULT_BAD_COPY);
    }
    if (memcpy_s(&(pinEnrollParam.pinData[0]), CONST_PIN_DATA_LEN, pinData.data(), CONST_PIN_DATA_LEN) != EOK) {
        LOG_ERROR("copy pinData to pinEnrollParam fail!");
        return PinResultToCoAuthResult(RESULT_BAD_COPY);
    }
    Buffer *retTlv = CreateBufferBySize(RESULT_TLV_LEN);
    if (!IsBufferValid(retTlv)) {
        LOG_ERROR("retTlv is unValid!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode result = DoEnrollPin(&pinEnrollParam, retTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoEnrollPin fail!");
        goto ERROR;
    }

    resultTlv.resize(retTlv->contentSize);
    if (memcpy_s(resultTlv.data(), retTlv->contentSize, retTlv->buf, retTlv->contentSize) != EOK) {
        LOG_ERROR("copy retTlv to resultTlv fail!");
        result = RESULT_BAD_COPY;
        goto ERROR;
    }

ERROR:
    DestroyBuffer(retTlv);
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::GenerateAlgoParameter(std::vector<uint8_t> &algoParameter, uint32_t &algoVersion)
{
    LOG_INFO("start");
    static constexpr uint32_t deviceUuidLength = 65;
    char localDeviceId[deviceUuidLength] = {0};
    if (GetDevUdid(localDeviceId, deviceUuidLength) != EC_SUCCESS) {
        LOG_ERROR("GetDevUdid failed");
        return GENERAL_ERROR;
    }
    uint32_t algoParameterLen = CONST_SALT_LEN;
    algoParameter.resize(algoParameterLen);
    int32_t result = DoGenerateAlgoParameter(algoParameter.data(), &algoParameterLen, &algoVersion,
        (uint8_t *)&(localDeviceId[0]), deviceUuidLength);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGenerateAlgoParameter fail!");
        return PinResultToCoAuthResult(result);
    }
    if (algoParameterLen != CONST_SALT_LEN) {
        LOG_ERROR("algoParameterLen is error!");
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::AllInOneAuth(
    uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo, PinAlgoParam &pinAlgoParam)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    AlgoParamOut authAlgoParam = {};
    ResultCode result = DoAllInOneAuth(scheduleId, templateId, extraInfo.data(), extraInfo.size(), &authAlgoParam);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoAllInOneAuth fail!");
        return PinResultToCoAuthResult(result);
    }
    pinAlgoParam.algoVersion = authAlgoParam.algoVersion;
    pinAlgoParam.subType = authAlgoParam.subType;
    int32_t transResult = SetVectorByBuffer(
        pinAlgoParam.algoParameter, authAlgoParam.algoParameter, sizeof(authAlgoParam.algoParameter));
    if (transResult != RESULT_SUCCESS) {
        LOG_ERROR("set algoParameter fail!");
        return PinResultToCoAuthResult(transResult);
    }
    transResult = SetVectorByBuffer(pinAlgoParam.challenge, authAlgoParam.challenge, sizeof(authAlgoParam.challenge));
    if (transResult != RESULT_SUCCESS) {
        LOG_ERROR("set challenge fail!");
        return PinResultToCoAuthResult(transResult);
    }

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::AuthPin(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &pinData,
    const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &resultTlv)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    if (pinData.size() != CONST_PIN_DATA_LEN || extraInfo.size() == 0) {
        LOG_ERROR("bad pinData len!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }

    PinAuthParam pinAuthParam = {};
    pinAuthParam.scheduleId = scheduleId;
    pinAuthParam.templateId = templateId;
    if (memcpy_s(&(pinAuthParam.pinData[0]), CONST_PIN_DATA_LEN, pinData.data(), pinData.size()) != EOK) {
        LOG_ERROR("mem copy pinData to pinAuthParam fail!");
        return PinResultToCoAuthResult(RESULT_BAD_COPY);
    }
    Buffer *extra = CreateBufferByData(extraInfo.data(), extraInfo.size());
    if (!IsBufferValid(extra)) {
        LOG_ERROR("extraInfo is unValid!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    Buffer *retTlv = CreateBufferBySize(RESULT_TLV_LEN);
    if (!IsBufferValid(retTlv)) {
        LOG_ERROR("retTlv is unValid!");
        DestroyBuffer(extra);
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode compareRet = RESULT_COMPARE_FAIL;
    ResultCode result = DoAuthPin(&pinAuthParam, extra, retTlv, &compareRet);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoAuthPin fail!");
        goto ERROR;
    }
    resultTlv.resize(retTlv->contentSize);
    if (memcpy_s(resultTlv.data(), retTlv->contentSize, retTlv->buf, retTlv->contentSize) != EOK) {
        LOG_ERROR("copy retTlv to resultTlv fail!");
        result = RESULT_GENERAL_ERROR;
        goto ERROR;
    }
    result = compareRet;

ERROR:
    DestroyBuffer(extra);
    DestroyBuffer(retTlv);
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::QueryPinInfo(uint64_t templateId, PinCredentialInfo &pinCredentialInfoRet)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    PinCredentialInfos pinCredentialInfosRet = {};
    int32_t result = DoQueryPinInfo(templateId, &pinCredentialInfosRet);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoQueryPinInfo fail!");
        return PinResultToCoAuthResult(result);
    }
    pinCredentialInfoRet.subType = pinCredentialInfosRet.subType;
    pinCredentialInfoRet.remainTimes = pinCredentialInfosRet.remainTimes;
    pinCredentialInfoRet.freezingTime = pinCredentialInfosRet.freezeTime;
    pinCredentialInfoRet.nextFailLockoutDuration = pinCredentialInfosRet.nextFailLockoutDuration;

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::DeleteTemplate(uint64_t templateId)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    ResultCode result = DoDeleteTemplate(templateId);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoDeleteTemplate fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }

    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::GetExecutorInfo(int32_t executorRole, std::vector<uint8_t> &pubKey, uint32_t &esl,
    uint32_t &maxTemplateAcl)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    PinExecutorInfo pinExecutorInfo = {};
    int32_t result = RESULT_GENERAL_ERROR;
    switch (executorRole) {
        case HDI::PinAuth::HdiExecutorRole::ALL_IN_ONE:
            result = DoGetAllInOneExecutorInfo(&pinExecutorInfo);
            break;
        case HDI::PinAuth::HdiExecutorRole::COLLECTOR:
            result = DoGetCollectorExecutorInfo(&pinExecutorInfo);
            break;
        case HDI::PinAuth::HdiExecutorRole::VERIFIER:
            result = DoGetVerifierExecutorInfo(&pinExecutorInfo);
            break;
        default:
            LOG_ERROR("unknown role");
            break;
    }
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGetExecutorInfo fail!");
        goto ERROR;
    }
    esl = pinExecutorInfo.esl;
    maxTemplateAcl = pinExecutorInfo.maxTemplateAcl;
    pubKey.resize(ED25519_FIX_PUBKEY_BUFFER_SIZE);
    if (memcpy_s(pubKey.data(), ED25519_FIX_PUBKEY_BUFFER_SIZE,
        pinExecutorInfo.pubKey, ED25519_FIX_PUBKEY_BUFFER_SIZE) != EOK) {
        LOG_ERROR("copy pinExecutorInfo to pubKey fail!");
        result = RESULT_GENERAL_ERROR;
        goto ERROR;
    }

ERROR:
    static_cast<void>(memset_s(
        pinExecutorInfo.pubKey, ED25519_FIX_PUBKEY_BUFFER_SIZE, 0, ED25519_FIX_PUBKEY_BUFFER_SIZE));
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::SetAllInOneFwkParam(
    const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &frameworkPublicKey)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    uint32_t templateIdListLen = templateIdList.size();
    if (templateIdListLen > MAX_TEMPLATEID_LEN) {
        LOG_ERROR("check templateIdListLen fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode result = DoSetAllInOneFwkParam(
        &templateIdList[0], templateIdListLen, frameworkPublicKey.data(), frameworkPublicKey.size());
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoSetAllInOneFwkParam fail!");
    }

    return PinResultToCoAuthResult(result);
}

void PinAuth::WriteAntiBrute(uint64_t templateId)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    if (DoWriteAntiBruteInfoToFile(templateId) != RESULT_SUCCESS) {
        LOG_ERROR("DoWriteAntiBruteInfoToFile fail!");
    }
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::SetCollectorFwkParam(const std::vector<uint8_t> &frameworkPublicKey)
{
    std::lock_guard<std::mutex> gurard(mutex_);
    int32_t result = DoSetCollectorFwkParam(frameworkPublicKey.data(), frameworkPublicKey.size());
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoSetCollectorFwkParam fail!");
    }
    return PinResultToCoAuthResult(result);
}

int32_t PinAuth::SetVectorByBuffer(std::vector<uint8_t> &vec, const uint8_t *buf, uint32_t bufSize)
{
    if (bufSize == 0) {
        vec.clear();
        return RESULT_SUCCESS;
    }
    vec.resize(bufSize);
    if (memcpy_s(vec.data(), vec.size(), buf, bufSize) != EOK) {
        LOG_ERROR("copy buf fail!");
        return RESULT_BAD_COPY;
    }
    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::Collect(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &msg)
{
    std::lock_guard<std::mutex> gurard(mutex_);
    uint8_t *out = new (std::nothrow) uint8_t[MAX_EXECUTOR_MSG_LEN];
    if (out == nullptr) {
        LOG_ERROR("malloc out fail!");
        return GENERAL_ERROR;
    }
    uint32_t outSize = MAX_EXECUTOR_MSG_LEN;
    int32_t result = DoCollect(scheduleId, extraInfo.data(), extraInfo.size(), out, &outSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoCollect fail!");
        delete[] out;
        return PinResultToCoAuthResult(result);
    }
    result = SetVectorByBuffer(msg, out, outSize);
    delete[] out;
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set msg fail!");
    }
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::CancelCollect()
{
    std::lock_guard<std::mutex> gurard(mutex_);
    int32_t result = DoCancelCollect();
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoCancelCollect fail!");
    }
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::SendMessageToCollector(
    uint64_t scheduleId, const std::vector<uint8_t> &msg, PinAlgoParam &pinAlgoParam)
{
    std::lock_guard<std::mutex> gurard(mutex_);
    AlgoParamOut algoParam = {};
    int32_t result = DoSendMessageToCollector(scheduleId, msg.data(), msg.size(), &algoParam);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoSendMessageToCollector fail!");
        return PinResultToCoAuthResult(result);
    }
    pinAlgoParam.algoVersion = algoParam.algoVersion;
    pinAlgoParam.subType = algoParam.subType;
    result = SetVectorByBuffer(pinAlgoParam.algoParameter, algoParam.algoParameter, sizeof(algoParam.algoParameter));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set algoParameter fail!");
        return PinResultToCoAuthResult(result);
    }
    result = SetVectorByBuffer(pinAlgoParam.challenge, algoParam.challenge, sizeof(algoParam.challenge));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set challenge fail!");
        return PinResultToCoAuthResult(result);
    }

    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::SetDataToCollector(uint64_t scheduleId, const std::vector<uint8_t> &data, std::vector<uint8_t> &msg)
{
    std::lock_guard<std::mutex> gurard(mutex_);
    int32_t result = RESULT_GENERAL_ERROR;
    uint8_t *pinData = const_cast<uint8_t *>(data.data());
    uint8_t *out = new (std::nothrow) uint8_t[MAX_EXECUTOR_MSG_LEN];
    uint32_t outSize = MAX_EXECUTOR_MSG_LEN;
    if (out == nullptr) {
        LOG_ERROR("new out fail!");
        goto EXIT;
    }
    result = DoSetDataToCollector(scheduleId, pinData, data.size(), out, &outSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoSetDataToCollector fail!");
        goto EXIT;
    }
    result = SetVectorByBuffer(msg, out, outSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set msg fail!");
    }

EXIT:
    if (data.size() != 0) {
        (void)memset_s(pinData, data.size(), 0, data.size());
    }
    if (out != nullptr) {
        delete[] out;
    }
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::SetVerifierFwkParam(const std::vector<uint8_t> &frameworkPublicKey)
{
    std::lock_guard<std::mutex> gurard(mutex_);
    int32_t result = DoSetVerifierFwkParam(frameworkPublicKey.data(), frameworkPublicKey.size());
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoSetVerifierFwkParam fail!");
    }
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::VerifierAuth(
    uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &msgOut)
{
    std::lock_guard<std::mutex> gurard(mutex_);
    uint8_t *out = new (std::nothrow) uint8_t[MAX_EXECUTOR_MSG_LEN];
    if (out == nullptr) {
        LOG_ERROR("new out fail!");
        return GENERAL_ERROR;
    }
    VerifierMsg verifierMsg = {
        .msgIn = const_cast<uint8_t *>(extraInfo.data()),
        .msgInSize = extraInfo.size(),
        .msgOut = out,
        .msgOutSize = MAX_EXECUTOR_MSG_LEN,
        .isAuthEnd = false,
        .authResult = RESULT_GENERAL_ERROR,
    };
    int32_t result = DoVerifierAuth(scheduleId, templateId, &verifierMsg);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoVerifierAuth fail!");
        delete[] out;
        return PinResultToCoAuthResult(result);
    }
    if (verifierMsg.authResult == RESULT_SUCCESS) {
        delete[] out;
        return SUCCESS;
    }
    result = SetVectorByBuffer(msgOut, verifierMsg.msgOut, verifierMsg.msgOutSize);
    delete[] out;
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set msg fail!");
        return PinResultToCoAuthResult(result);
    }
    return PinResultToCoAuthResult(verifierMsg.authResult);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::CancelVerifierAuth()
{
    std::lock_guard<std::mutex> gurard(mutex_);
    int32_t result = DoCancelVerifierAuth();
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoCancelVerifierAuth fail!");
    }
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::SendMessageToVerifier(uint64_t scheduleId,
    const std::vector<uint8_t> &msgIn, std::vector<uint8_t> &msgOut, bool &isAuthEnd, int32_t &compareResult)
{
    std::lock_guard<std::mutex> gurard(mutex_);
    uint8_t *out = new (std::nothrow) uint8_t[MAX_EXECUTOR_MSG_LEN];
    if (out == nullptr) {
        LOG_ERROR("new out fail!");
        return GENERAL_ERROR;
    }
    VerifierMsg verifierMsg = {
        .msgIn = const_cast<uint8_t *>(msgIn.data()),
        .msgInSize = msgIn.size(),
        .msgOut = out,
        .msgOutSize = MAX_EXECUTOR_MSG_LEN,
        .isAuthEnd = false,
        .authResult = RESULT_GENERAL_ERROR,
    };
    int32_t result = DoSendMessageToVerifier(scheduleId, &verifierMsg);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoSendMessageToVerifier fail!");
        delete[] out;
        return PinResultToCoAuthResult(result);
    }
    result = SetVectorByBuffer(msgOut, out, verifierMsg.msgOutSize);
    delete[] out;
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set msg fail!");
        return PinResultToCoAuthResult(result);
    }
    isAuthEnd = verifierMsg.isAuthEnd;
    compareResult = PinResultToCoAuthResult(verifierMsg.authResult);
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::Abandon(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo,
    std::vector<uint8_t> &resultTlv)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    if (extraInfo.size() == 0) {
        LOG_ERROR("get bad params!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }

    PinAbandonParam pinAbandonParam = {};
    pinAbandonParam.scheduleId = scheduleId;
    pinAbandonParam.templateId = templateId;

    Buffer *extra = CreateBufferByData(extraInfo.data(), extraInfo.size());
    if (!IsBufferValid(extra)) {
        LOG_ERROR("extra is unValid!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }

    Buffer *retTlv = CreateBufferBySize(RESULT_TLV_LEN);
    if (!IsBufferValid(retTlv)) {
        LOG_ERROR("retTlv is unValid!");
        DestroyBuffer(extra);
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode result = DoAbandonPin(&pinAbandonParam, extra, retTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoEnrollPin fail!");
        goto ERROR;
    }

    resultTlv.resize(retTlv->contentSize);
    if (memcpy_s(resultTlv.data(), retTlv->contentSize, retTlv->buf, retTlv->contentSize) != EOK) {
        LOG_ERROR("copy retTlv to resultTlv fail!");
        result = RESULT_BAD_COPY;
        goto ERROR;
    }

ERROR:
    DestroyBuffer(extra);
    DestroyBuffer(retTlv);
    return PinResultToCoAuthResult(result);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
