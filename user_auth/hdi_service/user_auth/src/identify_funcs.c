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

#include "identify_funcs.h"

#include "securec.h"

#include "adaptor_log.h"
#include "context_manager.h"
#include "executor_message.h"
#include "idm_database.h"
#include "auth_level.h"

int32_t DoIdentify(const IdentifyParam param, LinkedList **schedule)
{
    if (schedule == NULL) {
        LOG_ERROR("schedule is null");
        return RESULT_BAD_PARAM;
    }
    UserAuthContext *identifyContext = GenerateIdentifyContext(param);
    if (identifyContext == NULL) {
        LOG_ERROR("authContext is null");
        return RESULT_GENERAL_ERROR;
    }
    int32_t ret = CopySchedules(identifyContext, schedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule failed");
        DestoryContext(identifyContext);
        return ret;
    }
    return ret;
}

int32_t DoUpdateIdentify(uint64_t contextId, const Buffer *scheduleResult, int32_t *userId, UserAuthTokenHal *token,
    int32_t *result)
{
    if (!IsBufferValid(scheduleResult) || token == NULL || userId == NULL || result == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }

    UserAuthContext *identifyContext = GetContext(contextId);
    if (identifyContext == NULL) {
        LOG_ERROR("identifyContext is null");
        return RESULT_UNKNOWN;
    }
    ExecutorResultInfo *executorResultInfo = CreateExecutorResultInfo(scheduleResult);
    if (executorResultInfo == NULL) {
        LOG_ERROR("executorResultInfo is null");
        DestoryContext(identifyContext);
        return RESULT_UNKNOWN;
    }
    *result = executorResultInfo->result;
    if (*result != RESULT_SUCCESS) {
        DestoryContext(identifyContext);
        DestoryExecutorResultInfo(executorResultInfo);
        return RESULT_SUCCESS;
    }
    uint64_t credentialId;
    int32_t ret = FillInContext(identifyContext, &credentialId, executorResultInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get info failed");
        DestoryContext(identifyContext);
        DestoryExecutorResultInfo(executorResultInfo);
        return ret;
    }
    ret = GetTokenDataAndSign(identifyContext, credentialId, SCHEDULE_MODE_IDENTIFY, token);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get token failed");
        (void)memset_s(token, sizeof(UserAuthTokenHal), 0, sizeof(UserAuthTokenHal));
        DestoryContext(identifyContext);
        DestoryExecutorResultInfo(executorResultInfo);
        return ret;
    }
    *userId = identifyContext->userId;
    DestoryContext(identifyContext);
    DestoryExecutorResultInfo(executorResultInfo);
    return RESULT_SUCCESS;
}