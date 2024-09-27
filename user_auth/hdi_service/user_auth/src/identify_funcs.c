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

#include "identify_funcs.h"

#include "securec.h"

#include "adaptor_log.h"
#include "auth_level.h"
#include "auth_token_signer.h"
#include "context_manager.h"
#include "executor_message.h"
#include "idm_database.h"

ResultCode DoIdentify(const IdentifyParam param, LinkedList **schedule)
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
    ResultCode ret = CopySchedules(identifyContext, schedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule failed");
        DestroyContext(identifyContext);
        return ret;
    }
    return ret;
}

ResultCode DoUpdateIdentify(uint64_t contextId, const Buffer *scheduleResult, int32_t *userId,
    UserAuthTokenHal *token, int32_t *result)
{
    if (!IsBufferValid(scheduleResult) || token == NULL || userId == NULL || result == NULL) {
        LOG_ERROR("param is null");
        DestroyContextbyId(contextId);
        return RESULT_BAD_PARAM;
    }

    UserAuthContext *identifyContext = GetContext(contextId);
    if (identifyContext == NULL) {
        LOG_ERROR("identifyContext is null");
        return RESULT_GENERAL_ERROR;
    }
    ExecutorResultInfo *executorResultInfo = CreateExecutorResultInfo(scheduleResult);
    if (executorResultInfo == NULL) {
        LOG_ERROR("executorResultInfo is null");
        DestroyContext(identifyContext);
        return RESULT_GENERAL_ERROR;
    }

    ResultCode ret = RESULT_GENERAL_ERROR;
    *result = executorResultInfo->result;
    if (*result != RESULT_SUCCESS) {
        LOG_ERROR("executor result is not success, result: %{pubilc}d", executorResultInfo->result);
        goto EXIT;
    }
    uint64_t credentialId;
    ret = FillInContext(identifyContext, &credentialId, executorResultInfo, SCHEDULE_MODE_IDENTIFY);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("FillInContext fail");
        goto EXIT;
    }
    ret = GetAuthTokenDataAndSign(identifyContext, credentialId, SCHEDULE_MODE_IDENTIFY, token);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get token failed");
        goto EXIT;
    }
    *userId = identifyContext->userId;

EXIT:
    DestroyExecutorResultInfo(executorResultInfo);
    DestroyContext(identifyContext);
    return ret;
}