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

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_time.h"
#include "context_manager.h"
#include "executor_message.h"
#include "idm_database.h"
#include "user_sign_centre.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

// Used to cache screenLock auth token plain.
IAM_STATIC UnlockAuthResultCache g_unlockAuthResult = {false, 0, {}};

ResultCode GenerateSolutionFunc(AuthParamHal param, LinkedList **schedules)
{
    if (schedules == NULL) {
        LOG_ERROR("schedules is null");
        return RESULT_BAD_PARAM;
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
    ResultCode ret = CopySchedules(authContext, schedules);
    if (ret != RESULT_SUCCESS) {
        DestoryContext(authContext);
        return ret;
    }
    return ret;
}

IAM_STATIC void CacheUnlockAuthResult(int32_t userId, const UserAuthTokenHal *unlockToken)
{
    (void)memset_s(&g_unlockAuthResult, sizeof(UnlockAuthResultCache), 0, sizeof(UnlockAuthResultCache));
    g_unlockAuthResult.isCached = true;
    g_unlockAuthResult.userId = userId;
    g_unlockAuthResult.authToken = *unlockToken;
}

IAM_STATIC void SetAuthResult(int32_t userId, uint32_t authType, const ExecutorResultInfo *info, AuthResult *result)
{
    result->userId = userId;
    result->authType = authType;
    result->freezingTime = info->freezingTime;
    result->remainTimes = info->remainTimes;
    result->result = info->result;
}

IAM_STATIC ResultCode HandleAuthSuccessResult(const UserAuthContext *context, const ExecutorResultInfo *info,
    AuthResult *result, UserAuthTokenHal *authToken)
{
    EnrolledStateHal enrolledState = {};
    if (GetEnrolledState(context->userId, context->authType, &enrolledState) == RESULT_SUCCESS) {
        result->credentialDigest = enrolledState.credentialDigest;
        result->credentialCount = enrolledState.credentialCount;
    }
    if (context->isAuthResultCached) {
        LOG_INFO("cache unlock auth result");
        CacheUnlockAuthResult(context->userId, authToken);
    }
    if (result->result == RESULT_SUCCESS && context->authType == PIN_AUTH) {
        result->rootSecret = CopyBuffer(info->rootSecret);
        if (!IsBufferValid(result->rootSecret)) {
            LOG_ERROR("rootSecret is invalid");
            return RESULT_NO_MEMORY;
        }
    }
    return RESULT_SUCCESS;
}

ResultCode RequestAuthResultFunc(uint64_t contextId, const Buffer *scheduleResult, UserAuthTokenHal *authToken,
    AuthResult *result)
{
    if (!IsBufferValid(scheduleResult) || authToken == NULL || result == NULL || result->rootSecret != NULL) {
        LOG_ERROR("param is invalid");
        DestoryContextbyId(contextId);
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
        DestoryContext(userAuthContext);
        return RESULT_GENERAL_ERROR;
    }

    ResultCode ret = RESULT_GENERAL_ERROR;
    if (executorResultInfo->result != RESULT_SUCCESS) {
        ret = RESULT_SUCCESS;
        LOG_ERROR("executor result is not success, result:%{public}d", executorResultInfo->result);
        goto EXIT;
    }

    uint64_t credentialId;
    ret = FillInContext(userAuthContext, &credentialId, executorResultInfo, SCHEDULE_MODE_AUTH);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("FillInContext fail");
        goto EXIT;
    }

    ret = GetTokenDataAndSign(userAuthContext, credentialId, SCHEDULE_MODE_AUTH, authToken);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("sign token failed");
        goto EXIT;
    }
    ret = HandleAuthSuccessResult(userAuthContext, executorResultInfo, result, authToken);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("handle auth success result failed");
    }

EXIT:
    SetAuthResult(userAuthContext->userId, userAuthContext->authType, executorResultInfo, result);
    DestoryExecutorResultInfo(executorResultInfo);
    DestoryContext(userAuthContext);
    return ret;
}

ResultCode GetEnrolledStateFunc(int32_t userId, uint32_t authType, EnrolledStateHal *enrolledStateHal)
{
    ResultCode ret = GetEnrolledState(userId, authType, enrolledStateHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetEnrolledState failed");
        return ret;
    }

    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode CheckReuseUnlockTokenValid(const ReuseUnlockParamHal *info)
{
    if (!g_unlockAuthResult.isCached) {
        LOG_ERROR("invalid cached unlock token");
        return RESULT_GENERAL_ERROR;
    }
    uint64_t time = GetSystemTime();
    if (time < g_unlockAuthResult.authToken.tokenDataPlain.time) {
        LOG_ERROR("bad system time");
        return RESULT_GENERAL_ERROR;
    }
    if ((time - g_unlockAuthResult.authToken.tokenDataPlain.time) > REUSED_UNLOCK_TOKEN_PERIOD) {
        (void)memset_s(&g_unlockAuthResult, sizeof(UnlockAuthResultCache), 0, sizeof(UnlockAuthResultCache));
        g_unlockAuthResult.isCached = false;
        LOG_ERROR("cached unlock token is time out");
        return RESULT_TOKEN_TIMEOUT;
    }
    if ((time - g_unlockAuthResult.authToken.tokenDataPlain.time) > info->reuseUnlockResultDuration) {
        LOG_ERROR("reuse unlock check reuseUnlockResultDuration fail");
        return RESULT_TOKEN_TIMEOUT;
    }
    if (info->userId != g_unlockAuthResult.userId) {
        LOG_ERROR("reuse unlock check userId fail");
        return RESULT_GENERAL_ERROR;
    }
    if (info->authTrustLevel > g_unlockAuthResult.authToken.tokenDataPlain.authTrustLevel) {
        LOG_ERROR("reuse unlock check authTrustLevel fail");
        return RESULT_GENERAL_ERROR;
    }
    if (info->reuseUnlockResultMode == AUTH_TYPE_RELEVANT) {
        for (uint32_t i = 0; i < info->authTypeSize; i++) {
            if (info->authTypes[i] == g_unlockAuthResult.authToken.tokenDataPlain.authType) {
                return RESULT_SUCCESS;
            }
        }
        LOG_ERROR("reuse unlock check authType fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetReuseUnlockResult(const ReuseUnlockParamHal *info, ReuseUnlockResult *reuseResult)
{
    uint32_t ret = CheckReuseUnlockTokenValid(info);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("check unlock token fail");
        return ret;
    }
    *((UserAuthTokenHal *)reuseResult->token) = g_unlockAuthResult.authToken;
    reuseResult->authType = g_unlockAuthResult.authToken.tokenDataPlain.authType;
    ((UserAuthTokenHal *)reuseResult->token)->tokenDataPlain.authMode = SCHEDULE_MODE_REUSE_UNLOCK_AUTH_RESULT;
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
    return RESULT_SUCCESS;
}

ResultCode CheckReuseUnlockResultFunc(const ReuseUnlockParamHal *info, ReuseUnlockResult *reuseResult)
{
    if (info == NULL || reuseResult == NULL || info->reuseUnlockResultDuration == 0 ||
        info->reuseUnlockResultDuration > REUSED_UNLOCK_TOKEN_PERIOD ||
        (info->reuseUnlockResultMode != AUTH_TYPE_RELEVANT && info->reuseUnlockResultMode != AUTH_TYPE_IRRELEVANT)) {
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