/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
    InitPinDb();
    if (GenerateKeyPair() != RESULT_SUCCESS) {
        LOG_ERROR("GenerateKeyPair fail!");
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
    DestroyPinDb();
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
    DestoryBuffer(retTlv);
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::GetSalt(uint64_t templateId, std::vector<uint8_t> &salt)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    salt.resize(CONST_SALT_LEN);
    uint32_t satLen = CONST_SALT_LEN;
    ResultCode result = DoGetSalt(templateId, &salt[0], &satLen);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGetSalt fail!");
        return PinResultToCoAuthResult(result);
    }

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::AuthPin(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &pinData,
    std::vector<uint8_t> &resultTlv)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    if (pinData.size() != CONST_PIN_DATA_LEN) {
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
    Buffer *retTlv = CreateBufferBySize(RESULT_TLV_LEN);
    if (!IsBufferValid(retTlv)) {
        LOG_ERROR("retTlv is unValid!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode compareRet = RESULT_COMPARE_FAIL;
    ResultCode result = DoAuthPin(&pinAuthParam, retTlv, &compareRet);
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
    DestoryBuffer(retTlv);
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::QueryPinInfo(uint64_t templateId, PinCredentialInfo &pinCredentialInfoRet)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    PinCredentialInfos pinCredentialInfosRet = {};
    ResultCode result = DoQueryPinInfo(templateId, &pinCredentialInfosRet);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoQueryPinInfo fail!");
        return PinResultToCoAuthResult(result);
    }
    pinCredentialInfoRet.subType = pinCredentialInfosRet.subType;
    pinCredentialInfoRet.remainTimes = pinCredentialInfosRet.remainTimes;
    pinCredentialInfoRet.freezingTime = pinCredentialInfosRet.freezeTime;

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
int32_t PinAuth::GetExecutorInfo(std::vector<uint8_t> &pubKey, uint32_t &esl)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    PinExecutorInfo pinExecutorInfo = {};
    ResultCode result = DoGetExecutorInfo(&pinExecutorInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoGetExecutorInfo fail!");
        goto ERROR;
    }
    esl = pinExecutorInfo.esl;
    pubKey.resize(CONST_PUB_KEY_LEN);
    if (memcpy_s(pubKey.data(), CONST_PUB_KEY_LEN, &(pinExecutorInfo.pubKey[0]), CONST_PUB_KEY_LEN) != EOK) {
        LOG_ERROR("copy pinExecutorInfo to pubKey fail!");
        result = RESULT_GENERAL_ERROR;
        goto ERROR;
    }

ERROR:
    static_cast<void>(memset_s(&(pinExecutorInfo.pubKey[0]), CONST_PUB_KEY_LEN, 0, CONST_PUB_KEY_LEN));
    return PinResultToCoAuthResult(result);
}

/* This is for example only, Should be implemented in trusted environment. */
int32_t PinAuth::VerifyTemplateData(std::vector<uint64_t> templateIdList)
{
    LOG_INFO("start");
    std::lock_guard<std::mutex> gurard(mutex_);
    uint32_t templateIdListLen = templateIdList.size();
    if (templateIdListLen > MAX_TEMPLATEID_LEN) {
        LOG_ERROR("DoVerifyTemplateData fail!");
        return PinResultToCoAuthResult(RESULT_GENERAL_ERROR);
    }
    ResultCode result = DoVerifyTemplateData(&templateIdList[0], templateIdListLen);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("DoVerifyTemplateData fail!");
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
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
