/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "user_auth_funcs.h"

#include <math.h>
#include "securec.h"

#include "auth_level.h"
#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_time.h"
#include "auth_token_signer.h"
#include "context_manager.h"
#include "executor_message.h"
#include "hmac_key.h"
#include "idm_database.h"
#include "idm_session.h"
#include "udid_manager.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

// Used to cache screenLock auth token plain.
IAM_STATIC UnlockAuthResultCache g_unlockAuthResult = {false, 0, 0, {}};
// Used to cache any caller auth token plain.
IAM_STATIC UnlockAuthResultCache g_anyAuthResult = {false, 0, 0, {}};

ResultCode GenerateSolutionFunc(AuthParamHal param, LinkedList **schedules)
{
    if (schedules == NULL) {
        LOG_ERROR("schedules is null");
        return RESULT_BAD_PARAM;
    }
    if (!GetEnableStatus(param.userId, param.authType)) {
        LOG_ERROR("authType is not support %{public}d", param.authType);
        return RESULT_TYPE_NOT_SUPPORT;
    }
    UserAuthContext *authContext = NULL;
    ResultCode result = GenerateAuthContext(param, &authContext);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GenerateAuthContext fail %{public}d", result);
        return result;
    }
    if (authContext == NULL) {
        LOG_ERROR("authContext is null");
        return RESULT_GENERAL_ERROR;
    }
    if (!authContext->isExpiredReturnSuccess && authContext->authExpiredSysTime != NO_CHECK_PIN_EXPIRED_PERIOD) {
        uint64_t nowTime = GetReeTime();
        if (nowTime > authContext->authExpiredSysTime) {
            LOG_ERROR("pin is expired");
            return RESULT_PIN_EXPIRED;
        }
    }
    ResultCode ret = CopySchedules(authContext, schedules);
    if (ret != RESULT_SUCCESS) {
        DestroyContext(authContext);
        return ret;
    }
    return ret;
}

IAM_STATIC void CacheUnlockAuthResult(int32_t userId, uint64_t secureUid, const UserAuthTokenHal *unlockToken)
{
    (void)memset_s(&g_unlockAuthResult, sizeof(UnlockAuthResultCache), 0, sizeof(UnlockAuthResultCache));
    g_unlockAuthResult.isCached = true;
    g_unlockAuthResult.userId = userId;
    g_unlockAuthResult.secureUid = secureUid;
    g_unlockAuthResult.authToken = *unlockToken;
}

IAM_STATIC void CacheAnyAuthResult(int32_t userId, uint64_t secureUid, const UserAuthTokenHal *unlockToken)
{
    (void)memset_s(&g_anyAuthResult, sizeof(UnlockAuthResultCache), 0, sizeof(UnlockAuthResultCache));
    g_anyAuthResult.isCached = true;
    g_anyAuthResult.userId = userId;
    g_anyAuthResult.secureUid = secureUid;
    g_anyAuthResult.authToken = *unlockToken;
}

IAM_STATIC void SetAuthResult(uint64_t credentialId,
    const UserAuthContext *context, const ExecutorResultInfo *info, AuthResult *result)
{
    result->credentialId = credentialId;
    result->userId = context->userId;
    result->authType = context->authType;
    result->freezingTime = info->freezingTime;
    result->remainTimes = info->remainTimes;
    result->result = info->result;
}

IAM_STATIC ResultCode GetExpiredInfoForResult(const UserAuthContext *context, AuthResult *result)
{
    if (context == NULL || result == NULL) {
        LOG_INFO("bad param");
        return RESULT_BAD_PARAM;
    }
    if (context->authIntent == ABANDONED_PIN_AUTH) {
        result->pinExpiredInfo = GetCredentialValidPeriod(context->userId, result->credentialId);
    } else {
        if (context->authExpiredSysTime == NO_CHECK_PIN_EXPIRED_PERIOD) {
            LOG_INFO("pinExpiredPeriod is not set");
            result->pinExpiredInfo = NO_SET_PIN_EXPIRED_PERIOD;
            return RESULT_SUCCESS;
        }
        uint64_t currentTime = GetReeTime();
        if (currentTime < context->authExpiredSysTime) {
            // MAX_JS_NUMBER_VALUE is 2^50.
            const uint64_t MAX_JS_NUMBER_VALUE = 1125899906842624;
            result->pinExpiredInfo = MAX_JS_NUMBER_VALUE;
            if (context->authExpiredSysTime - currentTime < MAX_JS_NUMBER_VALUE) {
                result->pinExpiredInfo = context->authExpiredSysTime - currentTime;
            }
            LOG_INFO("pin is not expired");
            return RESULT_SUCCESS;
        }
        result->pinExpiredInfo = 0;
        if (!context->isExpiredReturnSuccess) {
            LOG_ERROR("pin is expired");
            return RESULT_PIN_EXPIRED;
        }
        LOG_INFO("caller is screenLock or setting");
    }
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode HandleAuthSuccessResult(const UserAuthContext *context, const ExecutorResultInfo *info,
    AuthResult *result, UserAuthTokenHal *authToken)
{
    EnrolledStateHal enrolledState = {};
    if (GetEnrolledState(context->userId, context->authType, &enrolledState) == RESULT_SUCCESS) {
        result->credentialDigest = enrolledState.credentialDigest;
        result->credentialCount = enrolledState.credentialCount;
    }

    if (result->result == RESULT_SUCCESS && context->authType == PIN_AUTH &&
        IsAllZero(&context->collectorUdid[0], UDID_LEN)) {
        if (context->authIntent == ABANDONED_PIN_AUTH) {
            SetOldRootSecret(context->userId, info->oldRootSecret);
        }
        result->rootSecret = CopyBuffer(info->rootSecret);
        if (!IsBufferValid(result->rootSecret)) {
            LOG_ERROR("rootSecret is invalid");
            return RESULT_NO_MEMORY;
        }
        SetCurRootSecret(context->userId, result->rootSecret);
    }
    ResultCode ret = GetExpiredInfoForResult(context, result);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetExpiredInfoForResult failed");
        return ret;
    }
    uint64_t secureUid;
    ret = GetSecureUid(context->userId, &secureUid);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get secure uid failed");
        return RESULT_GENERAL_ERROR;
    }
    if (context->authIntent == UNLOCK) {
        LOG_INFO("cache unlock auth result");
        CacheUnlockAuthResult(context->userId, secureUid, authToken);
    }

    LOG_INFO("cache any auth result");
    CacheAnyAuthResult(context->userId, secureUid, authToken);
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode SetAuthResultMsgToAttribute(Attribute *attribute, AuthResult *result,
    uint64_t scheduleId, Uint8Array authToken)
{
    ResultCode ret = SetAttributeUint64(attribute, ATTR_SCHEDULE_ID, scheduleId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint64 scheduleId failed");
        return ret;
    }
    ret = SetAttributeInt32(attribute, ATTR_RESULT, result->result);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeInt32 result failed");
        return ret;
    }
    ret = SetAttributeInt32(attribute, ATTR_LOCKOUT_DURATION, result->freezingTime);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeInt32 freezingTime failed");
        return ret;
    }
    ret = SetAttributeInt32(attribute, ATTR_REMAIN_ATTEMPTS, result->remainTimes);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeInt32 remainTimes failed");
        return ret;
    }
    ret = SetAttributeInt32(attribute, ATTR_USER_ID, result->userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeInt32 userId failed");
        return ret;
    }
    ret = SetAttributeUint8Array(attribute, ATTR_TOKEN, authToken);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint8Array for authToken fail");
    }
    return ret;
}

IAM_STATIC ResultCode GenerateRemoteAuthResultMsg(AuthResult *result, uint64_t scheduleId, Uint8Array collectorUdid,
    UserAuthTokenHal *authToken)
{
    Attribute *attribute = NULL;
    Uint8Array retInfo = {};
    ResultCode funcRet = RESULT_GENERAL_ERROR;
    do {
        attribute = CreateEmptyAttribute();
        retInfo = (Uint8Array){ Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
        if (attribute == NULL || retInfo.data == NULL) {
            LOG_ERROR("create attribute or malloc failed");
            break;
        }

        Uint8Array authTokenIn = { (uint8_t *)(&authToken), sizeof(UserAuthTokenHal) };
        if (SetAuthResultMsgToAttribute(attribute, result, scheduleId, authTokenIn) != RESULT_SUCCESS) {
            LOG_ERROR("SetAuthResultMsgToAttribute failed");
            break;
        }

        SignParam signParam = {
            .needSignature = true,
            .keyType = KEY_TYPE_CROSS_DEVICE,
            .peerUdid = collectorUdid
        };
        if (GetAttributeExecutorMsg(attribute, &retInfo, signParam) != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeExecutorMsg failed");
            break;
        }
        result->remoteAuthResultMsg = CreateBufferByData(retInfo.data, retInfo.len);
        funcRet = RESULT_SUCCESS;
    } while (0);

    FreeAttribute(&attribute);
    Free(retInfo.data);
    return funcRet;
}

IAM_STATIC ResultCode RequestAuthResultFuncInner(UserAuthContext *userAuthContext,
    ExecutorResultInfo *executorResultInfo, UserAuthTokenHal *authToken, AuthResult *result)
{
    ResultCode ret = RESULT_SUCCESS;
    Uint8Array collectorUdid = { userAuthContext->collectorUdid, sizeof(userAuthContext->collectorUdid) };
    if (!IsLocalUdid(collectorUdid) && !IsAllZero(userAuthContext->collectorUdid, UDID_LEN)) {
        ret = GenerateRemoteAuthResultMsg(result, executorResultInfo->scheduleId, collectorUdid, authToken);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("generate remote auth result failed");
            return ret;
        }
    }

    if (executorResultInfo->result == RESULT_SUCCESS) {
        ret = HandleAuthSuccessResult(userAuthContext, executorResultInfo, result, authToken);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("handle auth success result failed");
            return ret;
        }

        SetPinChangeScence(userAuthContext->userId, userAuthContext->authIntent);
    }
    return ret;
}

ResultCode RequestAuthResultFunc(uint64_t contextId, const Buffer *scheduleResult, UserAuthTokenHal *authToken,
    AuthResult *result)
{
    if (!IsBufferValid(scheduleResult) || authToken == NULL || result == NULL || result->rootSecret != NULL) {
        LOG_ERROR("param is invalid");
        DestroyContextbyId(contextId);
        return RESULT_BAD_PARAM;
    }

    UserAuthContext *userAuthContext = GetContext(contextId);
    if (userAuthContext == NULL) {
        LOG_ERROR("context is not found");
        return RESULT_GENERAL_ERROR;
    }

    ExecutorResultInfo *executorResultInfo = CreateExecutorResultInfo(scheduleResult);
    if (executorResultInfo == NULL) {
        LOG_ERROR("CreateExecutorResultInfo fail");
        DestroyContext(userAuthContext);
        return RESULT_GENERAL_ERROR;
    }

    uint64_t credentialId;
    ResultCode ret = FillInContext(userAuthContext, &credentialId, executorResultInfo, SCHEDULE_MODE_AUTH);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("FillInContext fail");
        goto EXIT;
    }

    if (executorResultInfo->result == RESULT_SUCCESS) {
        ret = GetAuthTokenDataAndSign(userAuthContext, credentialId, SCHEDULE_MODE_AUTH, authToken);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("sign token failed");
            goto EXIT;
        }
    }
    SetAuthResult(credentialId, userAuthContext, executorResultInfo, result);
    if (RequestAuthResultFuncInner(userAuthContext, executorResultInfo, authToken, result) != RESULT_SUCCESS) {
        LOG_ERROR("RequestAuthResultFuncInner failed");
        goto EXIT;
    }

EXIT:
    DestroyExecutorResultInfo(executorResultInfo);
    DestroyContext(userAuthContext);
    return ret;
}

ResultCode GetEnrolledStateFunc(int32_t userId, uint32_t authType, EnrolledStateHal *enrolledStateHal)
{
    if (!GetEnableStatus(userId, authType)) {
        LOG_ERROR("authType is not support %{public}d", authType);
        return RESULT_TYPE_NOT_SUPPORT;
    }
    ResultCode ret = GetEnrolledState(userId, authType, enrolledStateHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetEnrolledState failed");
        return ret;
    }

    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode CheckReuseUnlockTokenValid(const ReuseUnlockParamHal *info, UnlockAuthResultCache authResultCache)
{
    if (!authResultCache.isCached) {
        LOG_ERROR("invalid cached unlock token");
        return RESULT_REUSE_AUTH_RESULT_FAILED;
    }
    if ((authResultCache.authToken.tokenDataPlain.authMode != SCHEDULE_MODE_AUTH)
        || (authResultCache.authToken.tokenDataPlain.tokenType != TOKEN_TYPE_LOCAL_AUTH)) {
        LOG_ERROR("need local auth");
        return RESULT_REUSE_AUTH_RESULT_FAILED;
    }
    uint64_t time = GetSystemTime();
    if (time < authResultCache.authToken.tokenDataPlain.time) {
        LOG_ERROR("bad system time");
        return RESULT_REUSE_AUTH_RESULT_FAILED;
    }
    if ((time - authResultCache.authToken.tokenDataPlain.time) > REUSED_UNLOCK_TOKEN_PERIOD) {
        (void)memset_s(&authResultCache, sizeof(UnlockAuthResultCache), 0, sizeof(UnlockAuthResultCache));
        authResultCache.isCached = false;
        LOG_ERROR("cached unlock token is time out");
        return RESULT_REUSE_AUTH_RESULT_FAILED;
    }
    if ((time - authResultCache.authToken.tokenDataPlain.time) > info->reuseUnlockResultDuration) {
        LOG_ERROR("reuse unlock check reuseUnlockResultDuration fail");
        return RESULT_REUSE_AUTH_RESULT_FAILED;
    }
    if (info->userId != authResultCache.userId) {
        LOG_ERROR("reuse unlock check userId fail");
        return RESULT_REUSE_AUTH_RESULT_FAILED;
    }
    if (info->authTrustLevel > authResultCache.authToken.tokenDataPlain.authTrustLevel) {
        LOG_ERROR("reuse unlock check authTrustLevel fail");
        return RESULT_REUSE_AUTH_RESULT_FAILED;
    }
    if (info->reuseUnlockResultMode == AUTH_TYPE_RELEVANT ||
        info->reuseUnlockResultMode == CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT) {
        for (uint32_t i = 0; i < info->authTypeSize; i++) {
            if (info->authTypes[i] == authResultCache.authToken.tokenDataPlain.authType) {
                return RESULT_SUCCESS;
            }
        }
        LOG_ERROR("reuse unlock check authType fail");
        return RESULT_REUSE_AUTH_RESULT_FAILED;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetReuseUnlockResult(const ReuseUnlockParamHal *info, ReuseUnlockResult *reuseResult)
{
    UnlockAuthResultCache authResultCache = {};
    if (info->reuseUnlockResultMode == AUTH_TYPE_RELEVANT || info->reuseUnlockResultMode == AUTH_TYPE_IRRELEVANT) {
        authResultCache = g_unlockAuthResult;
    } else if (info->reuseUnlockResultMode == CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT ||
        info->reuseUnlockResultMode == CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT) {
        authResultCache = g_anyAuthResult;
    }
    uint64_t secureUid;
    ResultCode ret = GetSecureUid(info->userId, &secureUid);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get secure uid failed");
        return RESULT_GENERAL_ERROR;
    }
    if (secureUid != authResultCache.secureUid) {
        LOG_ERROR("check secureUid failed");
        return RESULT_GENERAL_ERROR;
    }
    ret = CheckReuseUnlockTokenValid(info, authResultCache);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("check unlock token fail");
        return ret;
    }
    *((UserAuthTokenHal *)reuseResult->token) = authResultCache.authToken;
    reuseResult->authType = authResultCache.authToken.tokenDataPlain.authType;
    ((UserAuthTokenHal *)reuseResult->token)->tokenDataPlain.authMode = SCHEDULE_MODE_REUSE_UNLOCK_AUTH_RESULT;
    ((UserAuthTokenHal *)reuseResult->token)->tokenDataPlain.tokenType = TOKEN_TYPE_LOCAL_RESIGN;
    if (memcpy_s(((UserAuthTokenHal *)reuseResult->token)->tokenDataPlain.challenge, CHALLENGE_LEN, info->challenge,
        CHALLENGE_LEN) != EOK) {
        LOG_ERROR("challenge copy failed");
        return RESULT_BAD_COPY;
    }
    ret = GetEnrolledState(info->userId, reuseResult->authType, &reuseResult->enrolledState);
    if (ret == RESULT_NOT_ENROLLED) {
        LOG_ERROR("GetEnrolledState result not enrolled");
        (void)memset_s(&reuseResult->enrolledState, sizeof(EnrolledStateHal), 0, sizeof(EnrolledStateHal));
        ret = RESULT_SUCCESS;
    }
    return ret;
}

ResultCode CheckReuseUnlockResultFunc(const ReuseUnlockParamHal *info, ReuseUnlockResult *reuseResult)
{
    if (info == NULL || reuseResult == NULL || info->reuseUnlockResultDuration == 0 ||
        info->reuseUnlockResultDuration > REUSED_UNLOCK_TOKEN_PERIOD ||
        (info->reuseUnlockResultMode != AUTH_TYPE_RELEVANT && info->reuseUnlockResultMode != AUTH_TYPE_IRRELEVANT &&
        info->reuseUnlockResultMode != CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT &&
        info->reuseUnlockResultMode != CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT)) {
        LOG_ERROR("CheckReuseUnlockResultFunc bad param");
        return RESULT_BAD_PARAM;
    }
    ResultCode ret = GetReuseUnlockResult(info, reuseResult);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get reuse unlock result failed");
        (void)memset_s(reuseResult, sizeof(ReuseUnlockResult), 0, sizeof(ReuseUnlockResult));
        return ret;
    }
    ret = ReuseUnlockTokenSign((UserAuthTokenHal *)reuseResult->token);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("reuse unlock token sign failed");
        (void)memset_s(reuseResult, sizeof(ReuseUnlockResult), 0, sizeof(ReuseUnlockResult));
        return ret;
    }
    return ret;
}

ResultCode SetGlobalConfigParamFunc(GlobalConfigParamHal *param)
{
    if (param == NULL || param->userIdNum > MAX_USER || param->authTypeNum > MAX_AUTH_TYPE_LEN ||
        param->authTypeNum == 0 || (param->type != PIN_EXPIRED_PERIOD && param->type != ENABLE_STATUS)) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    ResultCode ret = SaveGlobalConfigParam(param);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("Save globalConfigParam failed");
    }
    return ret;
}

ResultCode GetAvailableStatusFunc(int32_t userId, int32_t authType, uint32_t authTrustLevel)
{
    if (!GetEnableStatus(userId, authType)) {
        LOG_ERROR("authType is not support %{public}d", authType);
        return RESULT_TYPE_NOT_SUPPORT;
    }
    ResultCode ret = CheckAtlByExecutorAndCred(userId, authType, authTrustLevel);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("CheckAtlByExecutorAndCred failed");
        return ret;
    }

    PinExpiredInfo expiredInfo = {};
    ret = GetPinExpiredInfo(userId, &expiredInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetPinExpiredInfo failed");
        return ret;
    }
    if (expiredInfo.pinExpiredPeriod == NO_CHECK_PIN_EXPIRED_PERIOD) {
        LOG_ERROR("pinExpiredPeriod is not set");
        return RESULT_SUCCESS;
    }
    uint64_t nowTime = GetReeTime();
    if (nowTime > expiredInfo.pinExpiredPeriod + expiredInfo.pinEnrolledSysTime) {
        LOG_ERROR("pin is expired");
        return RESULT_PIN_EXPIRED;
    }
    return RESULT_SUCCESS;
}

ResultCode GenerateScheduleFunc(const Buffer *tlv, Uint8Array remoteUdid, ScheduleInfoParam *scheduleInfo)
{
    if (!IsBufferValid(tlv) || IS_ARRAY_NULL(remoteUdid) || (scheduleInfo == NULL)) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    ResultCode result = CreateScheduleInfo(tlv, remoteUdid, scheduleInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("CreateScheduleInfo failed");
    }
    return result;
}

ResultCode GenerateAuthResultFunc(const Buffer *tlv, AuthResultParam *authResultInfo)
{
    if (!IsBufferValid(tlv) || (authResultInfo == NULL)) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    ResultCode result = CreateAuthResultInfo(tlv, authResultInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("CreateAuthResultInfo failed");
    }
    return result;
}

ResultCode GetExecutorInfoLinkedList(uint32_t authType, uint32_t executorRole, LinkedList *allExecutorInfoList)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(allExecutorInfoList == NULL, RESULT_BAD_PARAM);
    uint8_t localUdidData[UDID_LEN] = { 0 };
    Uint8Array localUdid = { localUdidData, UDID_LEN };
    bool getLocalUdidRet = GetLocalUdid(&localUdid);
    IF_TRUE_LOGE_AND_RETURN_VAL(!getLocalUdidRet, RESULT_GENERAL_ERROR);

    ExecutorCondition condition = {};
    SetExecutorConditionAuthType(&condition, authType);
    SetExecutorConditionExecutorRole(&condition, executorRole);
    SetExecutorConditionDeviceUdid(&condition, localUdid);

    LinkedList *executorList = QueryExecutor(&condition);
    if (executorList == NULL) {
        LOG_ERROR("query executor failed");
        return RESULT_UNKNOWN;
    }
    if (executorList->getSize(executorList) == 0) {
        LOG_ERROR("executor is not found");
        DestroyLinkedList(executorList);
        return RESULT_TYPE_NOT_SUPPORT;
    }
    LinkedListNode *temp = executorList->head;
    while (temp != NULL) {
        ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)temp->data;
        if (executorInfo == NULL) {
            LOG_ERROR("executorInfo is invalid");
            DestroyLinkedList(executorList);
            return RESULT_UNKNOWN;
        }
        ExecutorInfoHal *copiedExecutorInfo = CopyExecutorInfo(executorInfo);
        if (executorInfo == NULL) {
            LOG_ERROR("copiedExecutorInfo is invalid");
            DestroyLinkedList(executorList);
            return RESULT_UNKNOWN;
        }
        if (allExecutorInfoList->insert(allExecutorInfoList, copiedExecutorInfo) != RESULT_SUCCESS) {
            LOG_ERROR("insert executor info failed");
            DestroyLinkedList(executorList);
            return RESULT_GENERAL_ERROR;
        }
        temp = temp->next;
    }
    DestroyLinkedList(executorList);
    return RESULT_SUCCESS;
}

static Buffer *GetSignExecutorInfoFuncInner(Uint8Array peerUdid, LinkedList *executorList,
    Uint8Array executorInfoTlvMsg, Uint8Array *executorInfoArray, uint32_t executorInfoArraySize)
{
    LinkedListNode *temp = executorList->head;
    uint32_t index = 0;
    while (temp != NULL) {
        ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)temp->data;
        if (executorInfo == NULL) {
            LOG_ERROR("executorInfo is invalid");
            return NULL;
        }
        if (index >= executorInfoArraySize) {
            LOG_ERROR("executor size is invalid");
            return NULL;
        }
        ResultCode result = GetExecutorInfoMsg(executorInfo, &executorInfoArray[index]);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("get executor info msg fail");
            return NULL;
        }
        index++;
        temp = temp->next;
    }
    ResultCode result = GetMultiDataSerializedMsg(executorInfoArray, executorInfoArraySize, &executorInfoTlvMsg);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetMultiDataSerializedMsg failed");
        return NULL;
    }
    return GetExecutorInfoTlv(executorInfoTlvMsg, peerUdid);
}

Buffer *GetSignExecutorInfoFunc(Uint8Array peerUdid, LinkedList *executorList)
{
    if (IS_ARRAY_NULL(peerUdid) || executorList == NULL) {
        LOG_ERROR("params is null");
        return NULL;
    }
    if (executorList->getSize(executorList) == 0) {
        LOG_ERROR("executor is unregistered");
        return NULL;
    }
    if (executorList->size > UINT32_MAX / sizeof(Uint8Array)) {
        LOG_ERROR("invalid executorList size");
        return NULL;
    }

    Uint8Array executorInfoTlvMsg = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    IF_TRUE_LOGE_AND_RETURN_VAL(executorInfoTlvMsg.data == NULL, NULL);

    Uint8Array executorInfoArray[executorList->size];
    bool mallocOk = true;
    for (uint32_t i = 0; i < executorList->size; i++) {
        executorInfoArray[i] = (Uint8Array){ Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
        if (executorInfoArray[i].data == NULL) {
            LOG_ERROR("malloc fail");
            mallocOk = false;
            continue;
        }
    }

    Buffer *signedExecutorInfo = NULL;
    if (mallocOk) {
        signedExecutorInfo = GetSignExecutorInfoFuncInner(peerUdid, executorList,
            executorInfoTlvMsg, executorInfoArray, executorList->size);
    }

    Free(executorInfoTlvMsg.data);
    for (uint32_t i = 0; i < executorList->size; i++) {
        Free(executorInfoArray[i].data);
    }

    return signedExecutorInfo;
}

void DestroyAuthResult(AuthResult *authResult)
{
    if (authResult == NULL) {
        return;
    }
    DestoryBuffer(authResult->rootSecret);
    DestoryBuffer(authResult->remoteAuthResultMsg);
    (void)memset_s(authResult, sizeof(AuthResult), 0, sizeof(AuthResult));
}