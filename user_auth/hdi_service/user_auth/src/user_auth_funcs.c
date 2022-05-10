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
#include "coauth_sign_centre.h"
#include "context_manager.h"
#include "executor_message.h"
#include "idm_database.h"
#include "user_sign_centre.h"

int32_t GenerateSolutionFunc(AuthSolutionHal param, CoAuthSchedule **schedules, uint32_t *scheduleNum)
{
    if (schedules == NULL || scheduleNum == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    UserAuthContext *authContext = GenerateContext(param);
    if (authContext == NULL) {
        LOG_ERROR("authContext is null");
        return RESULT_GENERAL_ERROR;
    }
    int32_t ret = GetSchedules(authContext, schedules, scheduleNum);
    if (ret != RESULT_SUCCESS) {
        DestoryContext(authContext);
        return ret;
    }
    return ret;
}

static int32_t GetTokenDataAndSign(UserAuthContext *context, UserAuthTokenHal *authToken)
{
    if (context == NULL || authToken == NULL) {
        LOG_ERROR("context or authToken is null");
        return RESULT_BAD_PARAM;
    }
    authToken->authResult = RESULT_SUCCESS;
    authToken->userId = context->userId;
    authToken->authTrustLevel = context->authTrustLevel;
    authToken->authType = context->authType;
    EnrolledInfoHal enrolledInfo;
    int32_t ret = GetEnrolledInfoAuthType(context->userId, authToken->authType, &enrolledInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get enrolledId info failed");
        return ret;
    }
    authToken->enrolledId = enrolledInfo.enrolledId;
    authToken->challenge = context->challenge;
    authToken->time = GetSystemTime();
    return UserAuthTokenSign(authToken);
}

int32_t RequestAuthResultFunc(uint64_t contextId, const Buffer *scheduleResult, UserAuthTokenHal *authToken)
{
    if (!IsBufferValid(scheduleResult) || authToken == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    ExecutorResultInfo *executorResultInfo = CreateExecutorResultInfo(scheduleResult);
    if (!IsExecutorInfoValid(executorResultInfo)) {
        LOG_ERROR("executorResultInfo is null");
        return RESULT_UNKNOWN;
    }

    UserAuthContext *userAuthContext = GetContext(contextId);
    if (userAuthContext == NULL) {
        LOG_ERROR("userAuthContext is null");
        DestoryExecutorResultInfo(executorResultInfo);
        return RESULT_UNKNOWN;
    }
    int32_t ret = ScheduleOnceFinish(userAuthContext, executorResultInfo->scheduleId);
    if (ret != RESULT_SUCCESS) {
        DestoryContext(userAuthContext);
        DestoryExecutorResultInfo(executorResultInfo);
        return ret;
    }

    if (executorResultInfo->result == RESULT_SUCCESS) {
        ret = GetTokenDataAndSign(userAuthContext, authToken);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("sign token failed");
            (void)memset_s(authToken, sizeof(UserAuthTokenHal), 0, sizeof(UserAuthTokenHal));
        }
    } else {
        (void)memset_s(authToken, sizeof(UserAuthTokenHal), 0, sizeof(UserAuthTokenHal));
        authToken->authResult = executorResultInfo->result;
    }
    DestoryExecutorResultInfo(executorResultInfo);
    DestoryContext(userAuthContext);
    return ret;
}

int32_t CancelContextFunc(uint64_t contextId, CoAuthSchedule **schedules, uint32_t *scheduleNum)
{
    UserAuthContext *authContext = GetContext(contextId);
    if (authContext == NULL) {
        LOG_ERROR("get context failed");
        return RESULT_NOT_FOUND;
    }
    int32_t ret = GetSchedules(authContext, schedules, scheduleNum);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule failed");
    }
    DestoryContext(authContext);
    return ret;
}