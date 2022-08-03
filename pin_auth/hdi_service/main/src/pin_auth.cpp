/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "pthread.h"
#include "adaptor_memory.h"
#include "adaptor_log.h"
#include "pin_func.h"
#include "securec.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
std::map<int32_t, ResultCodeForCoAuth> g_convertResult = {
    {RESULT_SUCCESS, ResultCodeForCoAuth::SUCCESS},
    {RESULT_BAD_PARAM, ResultCodeForCoAuth::INVALID_PARAMETERS},
    {RESULT_COMPARE_FAIL, ResultCodeForCoAuth::FAIL},
    {RESULT_BUSY, ResultCodeForCoAuth::BUSY},
    {RESULT_PIN_FREEZE, ResultCodeForCoAuth::LOCKED},
};

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

PinAuth::PinAuth() { }

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::Init()
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    LOG_INFO("start InIt pinAuth.");
    InitPinDb();
    if (GenerateKeyPair() != RESULT_SUCCESS) {
        LOG_ERROR("GenerateKeyPair fail!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    LOG_INFO("InIt pinAuth succ");

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::Close()
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    LOG_INFO("start Close pinAuth");
    DestroyPinDb();
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    LOG_INFO("Close pinAuth succ");

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::PinResultToCoAuthResult(int resultCode)
{
    LOG_INFO("PinAuth::PinResultToCoAuthResult enter");
    if (g_convertResult.count(resultCode) == 0) {
        LOG_ERROR("PinResult and CoauthResult not match, convert GENERAL_ERROR");
        return ResultCodeForCoAuth::GENERAL_ERROR;
    } else {
        return g_convertResult[resultCode];
    }
}

static ResultCode InitPinEnrollParam(PinEnrollParam *pinEnrollParam, uint64_t scheduleId, uint64_t subType,
    std::vector<uint8_t> &salt, const std::vector<uint8_t> &pinData)
{
    pinEnrollParam->scheduleId= scheduleId;
    pinEnrollParam->subType = subType;
    if (memcpy_s(&(pinEnrollParam->salt[0]), CONST_SALT_LEN, &salt[0], CONST_SALT_LEN) != EOK) {
        LOG_ERROR("copy salt to pinEnrollParam fail!");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(&(pinEnrollParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], CONST_PIN_DATA_LEN) != EOK) {
        LOG_ERROR("copy pinData to pinEnrollParam fail!");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

static ResultCode SetResultTlv(Buffer *retTlv, std::vector<uint8_t> &resultTlv)
{
    resultTlv.resize(retTlv->contentSize);
    if (memcpy_s(&resultTlv[0], retTlv->contentSize, retTlv->buf, retTlv->contentSize) != EOK) {
        LOG_ERROR("copy retTlv to resultTlv fail!");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::EnrollPin(uint64_t scheduleId, uint64_t subType, std::vector<uint8_t> &salt,
    const std::vector<uint8_t> &pinData, std::vector<uint8_t> &resultTlv)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    if (salt.size() != CONST_SALT_LEN || pinData.size() != CONST_PIN_DATA_LEN) {
        LOG_ERROR("get bad params!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    PinEnrollParam *pinEnrollParam = new (std::nothrow) PinEnrollParam();
    if (pinEnrollParam == nullptr) {
        LOG_ERROR("generate pinEnrollParam fail!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode result = InitPinEnrollParam(pinEnrollParam, scheduleId, subType, salt, pinData);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("InitPinEnrollParam fail!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        delete pinEnrollParam;
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    Buffer *retTlv = CreateBufferBySize(RESULT_TLV_LEN);
    result = DoEnrollPin(pinEnrollParam, retTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoEnrollPin fail!");
        goto ERROR;
    }
    result = SetResultTlv(retTlv, resultTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetRsultTlv fail!");
        goto ERROR;
    }

ERROR:
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }
    DestoryBuffer(retTlv);
    delete pinEnrollParam;
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::GetSalt(uint64_t templateId, std::vector<uint8_t> &salt)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    salt.resize(CONST_SALT_LEN);
    if (salt.size() != CONST_SALT_LEN) {
        LOG_ERROR("salt resize fail!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_UNKNOWN);
    }
    uint32_t satLen = CONST_SALT_LEN;
    ResultCode result = DoGetSalt(templateId, &salt[0], &satLen);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGetSalt fail!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(result);
    }
    if (pthread_mutex_unlock(&g_mutex) != RESULT_SUCCESS) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::AuthPin(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &pinData,
    std::vector<uint8_t> &resultTlv)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    if (pinData.size() != CONST_PIN_DATA_LEN) {
        LOG_ERROR("bad pidData len!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }

    PinAuthParam *pinAuthParam = new (std::nothrow) PinAuthParam();
    if (pinAuthParam == nullptr) {
        LOG_ERROR("pinAuthParam is nullptr!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    pinAuthParam->scheduleId = scheduleId;
    pinAuthParam->templateId = templateId;
    if (memcpy_s(&(pinAuthParam->pinData[0]), CONST_PIN_DATA_LEN, &pinData[0], pinData.size()) != EOK) {
        LOG_ERROR("mem copy pinData to pinAuthParam fail!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        delete pinAuthParam;
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    Buffer *retTlv = CreateBufferBySize(RESULT_TLV_LEN);
    ResultCode result = DoAuthPin(pinAuthParam, retTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoAuthPin fail!");
    }
    ResultCode setRet = SetResultTlv(retTlv, resultTlv);
    if (setRet != RESULT_SUCCESS) {
        LOG_ERROR("SetRsultTlv fail!");
        result = setRet;
        resultTlv.clear();
        goto ERROR;
    }

ERROR:
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }
    DestoryBuffer(retTlv);
    delete pinAuthParam;
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::QueryPinInfo(uint64_t templateId, PinCredentialInfo &pinCredentialInfoRet)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    PinCredentialInfos *pinCredentialInfosRet = new (std::nothrow) PinCredentialInfos();
    if (pinCredentialInfosRet == nullptr) {
        LOG_ERROR("pinCredentialInfosRet is nullptr!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode result = DoQueryPinInfo(templateId, pinCredentialInfosRet);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoQueryPinInfo fail!");
        goto ERROR;
    }

    pinCredentialInfoRet.subType = pinCredentialInfosRet->subType;
    pinCredentialInfoRet.remainTimes = pinCredentialInfosRet->remainTimes;
    pinCredentialInfoRet.freezingTime = pinCredentialInfosRet->freezeTime;

ERROR:
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }
    delete pinCredentialInfosRet;
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::DeleteTemplate(uint64_t templateId)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    ResultCode result = DoDeleteTemplate(templateId);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoDeleteTemplate fail!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }

    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::GetExecutorInfo(std::vector<uint8_t> &pubKey, uint32_t &esl)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    PinExecutorInfo *pinExecutorInfo = new (std::nothrow) PinExecutorInfo();
    if (pinExecutorInfo == nullptr) {
        LOG_ERROR("pinExecutorInfo is nullptr!");
        static_cast<void>(pthread_mutex_unlock(&g_mutex));
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode result = DoGetExecutorInfo(pinExecutorInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGetExecutorInfo fail!");
        goto ERROR;
    }
    esl = pinExecutorInfo->esl;
    pubKey.resize(CONST_PUB_KEY_LEN);
    if (memcpy_s(&pubKey[0], CONST_PUB_KEY_LEN, &(pinExecutorInfo->pubKey[0]), CONST_PUB_KEY_LEN) != EOK) {
        LOG_ERROR("copy pinExecutorInfo to pubKey fail!");
        result = RESULT_GENERAL_ERROR;
        goto ERROR;
    }

ERROR:
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }
    static_cast<void>(memset_s(&(pinExecutorInfo->pubKey[0]), CONST_PUB_KEY_LEN, 0, CONST_PUB_KEY_LEN));
    delete pinExecutorInfo;
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::VerifyTemplateData(std::vector<uint64_t> templateIdList)
{
    if (pthread_mutex_lock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_lock fail!");
        return PinResultToCoAuthResult(RESULT_BAD_PARAM);
    }
    uint32_t templateIdListLen = templateIdList.size();
    ResultCode result = DoVerifyTemplateData(&templateIdList[0], templateIdListLen);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoVerifyTemplateData fail!");
    }
    if (pthread_mutex_unlock(&g_mutex) != 0) {
        LOG_ERROR("pthread_mutex_unlock fail!");
        result = RESULT_GENERAL_ERROR;
    }
    return PinResultToCoAuthResult(result);
}
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
