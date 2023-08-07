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

ResultCode GenerateSolutionFunc(AuthSolutionHal param, LinkedList **schedules)
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

IAM_STATIC ResultCode SetAuthResult(uint32_t authType, const ExecutorResultInfo *info, AuthResult *result)
{
    result->authType = authType;
    result->freezingTime = info->freezingTime;
    result->remainTimes = info->remainTimes;
    result->result = info->result;
    if (result->result == RESULT_SUCCESS && authType == PIN_AUTH) {
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
        LOG_ERROR("executorResultInfo is null");
        DestoryContext(userAuthContext);
        return RESULT_GENERAL_ERROR;
    }

    ResultCode ret = RESULT_GENERAL_ERROR;
    if (executorResultInfo->result != RESULT_SUCCESS) {
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

EXIT:
    ret = SetAuthResult(userAuthContext->authType, executorResultInfo, result);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("set result failed");
    }

    DestoryExecutorResultInfo(executorResultInfo);
    DestoryContext(userAuthContext);
    return ret;
}