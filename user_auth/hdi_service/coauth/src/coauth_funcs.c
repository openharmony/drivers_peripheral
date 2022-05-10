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

#include "coauth_funcs.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "coauth_sign_centre.h"
#include "defines.h"
#include "executor_message.h"
#include "pool.h"

int32_t GetScheduleInfo(uint64_t scheduleId, ScheduleInfoHal *scheduleInfo)
{
    if (scheduleInfo == NULL) {
        LOG_ERROR("scheduleInfo is null");
        return RESULT_BAD_PARAM;
    }
    CoAuthSchedule coAuthSchedule = {};
    coAuthSchedule.scheduleId = scheduleId;
    int32_t ret = GetCoAuthSchedule(&coAuthSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get coAuth schedule failed");
        return ret;
    }
    if (coAuthSchedule.executorSize > MAX_EXECUTOR_SIZE) {
        LOG_ERROR("bad coAuth schedule executor size");
        return RESULT_UNKNOWN;
    }
    scheduleInfo->templateId = coAuthSchedule.templateId;
    scheduleInfo->authSubType = coAuthSchedule.authSubType;
    scheduleInfo->scheduleMode = coAuthSchedule.scheduleMode;

    scheduleInfo->executorInfoNum = coAuthSchedule.executorSize;
    for (uint32_t i = 0; i < coAuthSchedule.executorSize; i++) {
        scheduleInfo->executorInfos[i] = coAuthSchedule.executors[i];
    }

    return ret;
}

static int32_t TokenDataGetAndSign(uint32_t authType, const ExecutorResultInfo *resultInfo,
    ScheduleTokenHal *scheduleToken)
{
    scheduleToken->scheduleResult = RESULT_SUCCESS;
    scheduleToken->scheduleId = resultInfo->scheduleId;
    scheduleToken->authType = authType;
    scheduleToken->authSubType = resultInfo->authSubType;
    scheduleToken->templateId = resultInfo->templateId;
    scheduleToken->capabilityLevel = resultInfo->capabilityLevel;
    scheduleToken->time = GetSystemTime();
    return CoAuthTokenSign(scheduleToken);
}

int32_t ScheduleFinish(const Buffer *executorMsg, ScheduleTokenHal *scheduleToken)
{
    if (!IsBufferValid(executorMsg) || scheduleToken == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }

    scheduleToken->scheduleResult = RESULT_GENERAL_ERROR;
    int32_t ret = RESULT_GENERAL_ERROR;
    ExecutorResultInfo *resultInfo = CreateExecutorResultInfo(executorMsg);
    if (resultInfo == NULL || scheduleToken->scheduleId != resultInfo->scheduleId ||
        resultInfo->result != RESULT_SUCCESS) {
        LOG_ERROR("executor msg is invalid");
        goto EXIT;
    }

    CoAuthSchedule coAuthSchedule = {};
    coAuthSchedule.scheduleId = resultInfo->scheduleId;
    ret = GetCoAuthSchedule(&coAuthSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get coAuth schedule failed");
        goto EXIT;
    }

    Buffer *publicKey = NULL;
    uint32_t index;
    for (index = 0; index < coAuthSchedule.executorSize; index++) {
        ExecutorInfoHal *executor = &coAuthSchedule.executors[index];
        if (executor->executorType == VERIFIER || executor->executorType == ALL_IN_ONE) {
            publicKey = CreateBufferByData(executor->pubKey, PUBLIC_KEY_LEN);
            break;
        }
    }
    if (!IsBufferValid(publicKey)) {
        LOG_ERROR("get publicKey failed");
        goto EXIT;
    }
    ret = Ed25519Verify(publicKey, resultInfo->data, resultInfo->sign);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("verify sign failed");
        DestoryBuffer(publicKey);
        goto EXIT;
    }

    ret = TokenDataGetAndSign(coAuthSchedule.executors[0].authType, resultInfo, scheduleToken);
    DestoryBuffer(publicKey);

EXIT:
    DestoryExecutorResultInfo(resultInfo);
    (void)RemoveCoAuthSchedule(scheduleToken->scheduleId);
    return ret;
}

int32_t RegisterExecutor(const ExecutorInfoHal *registerInfo, uint64_t *executorId)
{
    if (registerInfo == NULL || executorId == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }

    ExecutorInfoHal executorInfo = *registerInfo;
    int32_t ret = RegisterExecutorToPool(&executorInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("register failed");
        return ret;
    }
    *executorId = executorInfo.executorId;
    return RESULT_SUCCESS;
}

int32_t UnRegisterExecutor(uint64_t executorId)
{
    int32_t ret = UnregisterExecutorToPool(executorId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("unregister failed");
    }
    return ret;
}

bool IsExecutorExistFunc(uint32_t authType)
{
    LinkedList *executorsQuery = NULL;
    int32_t ret = QueryExecutor(authType, &executorsQuery);
    if (ret != RESULT_SUCCESS || executorsQuery == NULL) {
        LOG_ERROR("query executor failed");
        return false;
    }

    if (executorsQuery->getSize(executorsQuery) == 0) {
        LOG_ERROR("get size failed");
        DestroyLinkedList(executorsQuery);
        return false;
    }
    DestroyLinkedList(executorsQuery);
    return true;
}