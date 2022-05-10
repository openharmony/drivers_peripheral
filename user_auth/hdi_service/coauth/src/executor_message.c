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

#include "executor_message.h"

#include "securec.h"
#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "coauth.h"
#include "tlv_wrapper.h"
#include "adaptor_memory.h"

static ResultCode ParseExecutorResultAcl(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetUint32Para(body, AUTH_CAPABILITY_LEVEL, &result->capabilityLevel);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("ParseExecutorResult capabilityLevel failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultTemplateId(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetUint64Para(body, AUTH_TEMPLATE_ID, &result->templateId);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("ParseExecutorResult templateId failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultScheduleId(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetUint64Para(body, AUTH_SCHEDULE_ID, &result->scheduleId);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("ParseExecutorResult scheduleId failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultCode(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetInt32Para(body, AUTH_RESULT_CODE, &result->result);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("ParseExecutorResult resultCode failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultAuthSubType(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetUint64Para(body, AUTH_SUBTYPE, &result->authSubType);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("ParseExecutorResult authSubType failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultData(ExecutorResultInfo *result, TlvListNode *body)
{
    result->data = GetBuffPara(body, AUTH_DATA);
    if (result->data == NULL) {
        LOG_ERROR("ParseCoAuthPara data failed");
        return RESULT_GENERAL_ERROR;
    }
    TlvListNode *parseBody = CreateTlvList();
    if (parseBody == NULL) {
        LOG_ERROR("parseBody is null");
        return false;
    }
    int ret = ParseTlvWrapper(result->data->buf, result->data->contentSize, parseBody);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseTlvWrapper failed");
        goto EXIT;
    }
    ret = ParseExecutorResultAcl(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseExecutorResultAcl failed");
        goto EXIT;
    }
    ret = ParseExecutorResultTemplateId(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseExecutorResultTemplateId failed");
        goto EXIT;
    }
    ret = ParseExecutorResultAuthSubType(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseExecutorResultAuthSubType failed");
        goto EXIT;
    }
    ret = ParseExecutorResultCode(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseExecutorResultCode failed");
        goto EXIT;
    }
    ret = ParseExecutorResultScheduleId(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseExecutorResultScheduleId failed");
        goto EXIT;
    }

EXIT:
    DestroyTlvList(parseBody);
    return ret;
}

static ResultCode ParseExecutorResultSign(ExecutorResultInfo *result, TlvListNode *body)
{
    result->sign = GetBuffPara(body, AUTH_SIGNATURE);
    if (result->sign == NULL) {
        LOG_ERROR("ParseCoAuthPara sign failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseRoot(ExecutorResultInfo *result, TlvListNode *body)
{
    Buffer *data = GetBuffPara(body, AUTH_ROOT);
    if (!IsBufferValid(data)) {
        LOG_ERROR("ParseExecutorResult data failed");
        return RESULT_BAD_PARAM;
    }
    TlvListNode *parseBody = CreateTlvList();
    if (parseBody == NULL) {
        LOG_ERROR("parseBody is null");
        DestoryBuffer(data);
        return RESULT_NO_MEMORY;
    }
    int ret = ParseTlvWrapper(data->buf, data->contentSize, parseBody);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseTlvWrapper failed");
        goto EXIT;
    }
    ret = ParseExecutorResultData(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseTlvWrapper failed");
        goto EXIT;
    }
    ret = ParseExecutorResultSign(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseTlvWrapper failed");
        goto EXIT;
    }

EXIT:
    DestoryBuffer(data);
    DestroyTlvList(parseBody);
    return ret;
}

ExecutorResultInfo *CreateExecutorResultInfo(const Buffer *tlv)
{
    if (!IsBufferValid(tlv)) {
        LOG_ERROR("param is invalid");
        return NULL;
    }
    TlvListNode *parseBody = CreateTlvList();
    if (parseBody == NULL) {
        LOG_ERROR("parseBody is null");
        return NULL;
    }

    int ret = ParseTlvWrapper(tlv->buf, tlv->contentSize, parseBody);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseTlvWrapper failed");
        DestroyTlvList(parseBody);
        return NULL;
    }

    ExecutorResultInfo *result = Malloc(sizeof(ExecutorResultInfo));
    if (result == NULL) {
        LOG_ERROR("malloc failed");
        goto EXIT;
    }
    if (memset_s(result, sizeof(ExecutorResultInfo), 0, sizeof(ExecutorResultInfo)) != EOK) {
        LOG_ERROR("set result failed");
        goto EXIT;
    }
    ret = ParseRoot(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseExecutorResult failed");
        goto EXIT;
    }
    DestroyTlvList(parseBody);
    return result;

EXIT:
    DestroyTlvList(parseBody);
    DestoryExecutorResultInfo(result);
    return NULL;
}

void DestoryExecutorResultInfo(ExecutorResultInfo *result)
{
    if (result == NULL) {
        return;
    }
    DestoryBuffer(result->data);
    result->data = NULL;
    DestoryBuffer(result->sign);
    result->sign = NULL;
    Free(result);
}

bool IsExecutorInfoValid(const ExecutorResultInfo *executorResultInfo)
{
    if (executorResultInfo == NULL || !IsBufferValid(executorResultInfo->data) ||
        !IsBufferValid(executorResultInfo->sign)) {
        LOG_ERROR("there is a problem with the data content");
        return false;
    }
    CoAuthSchedule currentSchedule = {};
    currentSchedule.scheduleId = executorResultInfo->scheduleId;
    int32_t ret = GetCoAuthSchedule(&currentSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule info failed");
        return false;
    }
    Buffer *publicKey = NULL;
    for (uint32_t index = 0; index < currentSchedule.executorSize; index++) {
        ExecutorInfoHal *executor = &currentSchedule.executors[index];
        if (executor->executorType == VERIFIER || executor->executorType == ALL_IN_ONE) {
            publicKey = CreateBufferByData(executor->pubKey, PUBLIC_KEY_LEN);
            break;
        }
    }
    if (!IsBufferValid(publicKey)) {
        LOG_ERROR("get publicKey failed");
        return false;
    }
    ret = Ed25519Verify(publicKey, executorResultInfo->data, executorResultInfo->sign);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("verify sign failed");
        DestoryBuffer(publicKey);
        return false;
    }
    DestoryBuffer(publicKey);
    return true;
}
