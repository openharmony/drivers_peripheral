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
#include "adaptor_time.h"
#include "ed25519_key.h"
#include "idm_database.h"

static bool IsExecutorInfoValid(const ExecutorResultInfo *executorResultInfo, const Buffer *data, const Buffer *sign);
static Buffer *CreateExecutorMsg(uint32_t authType, uint32_t authPropertyMode, const TemplateIdArrays *templateIds);

static ResultCode ParseExecutorResultRemainTime(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetInt32Para(body, AUTH_REMAIN_COUNT, &result->remainTimes);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("parse remainTimes failed, ret is %{public}d", ret);
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultFreezingTime(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetInt32Para(body, AUTH_REMAIN_TIME, &result->freezingTime);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("parse freezingTime failed, ret is %{public}d", ret);
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultAcl(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetUint32Para(body, AUTH_CAPABILITY_LEVEL, &result->capabilityLevel);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("parse capabilityLevel failed, ret is %{public}d", ret);
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultTemplateId(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetUint64Para(body, AUTH_TEMPLATE_ID, &result->templateId);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("parse templateId failed, ret is %{public}d", ret);
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultScheduleId(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetUint64Para(body, AUTH_SCHEDULE_ID, &result->scheduleId);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("parse scheduleId failed, ret is %{public}d", ret);
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultCode(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetInt32Para(body, AUTH_RESULT_CODE, &result->result);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("parse resultCode failed, ret is %{public}d", ret);
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultAuthSubType(ExecutorResultInfo *result, TlvListNode *body)
{
    int32_t ret = GetUint64Para(body, AUTH_SUBTYPE, &result->authSubType);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("parse authSubType failed, ret is %{public}d", ret);
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode ParseExecutorResultInfo(const Buffer *data, ExecutorResultInfo *result)
{
    TlvListNode *parseBody = CreateTlvList();
    if (parseBody == NULL) {
        LOG_ERROR("parseBody is null");
        return false;
    }
    int ret = ParseTlvWrapper(data->buf, data->contentSize, parseBody);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseTlvWrapper failed");
        goto EXIT;
    }
    ret = ParseExecutorResultAcl(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        goto EXIT;
    }
    ret = ParseExecutorResultTemplateId(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        goto EXIT;
    }
    ret = ParseExecutorResultAuthSubType(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        goto EXIT;
    }
    ret = ParseExecutorResultCode(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        goto EXIT;
    }
    ret = ParseExecutorResultScheduleId(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        goto EXIT;
    }
    ret = ParseExecutorResultRemainTime(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        goto EXIT;
    }
    ret = ParseExecutorResultFreezingTime(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        goto EXIT;
    }

    // Only pin auth can have rootsecret
    result->rootSecret = GetBuffPara(parseBody->next, AUTH_ROOT_SECRET);

EXIT:
    DestroyTlvList(parseBody);
    return ret;
}

static Buffer *ParseExecutorResultData(TlvListNode *body)
{
    Buffer *data = GetBuffPara(body, AUTH_DATA);
    if (!IsBufferValid(data)) {
        LOG_ERROR("ParseCoAuthPara data failed");
        return NULL;
    }
    return data;
}

static Buffer *ParseExecutorResultSign(TlvListNode *body)
{
    Buffer *sign = GetBuffPara(body, AUTH_SIGNATURE);
    if (!IsBufferValid(sign)) {
        LOG_ERROR("ParseCoAuthPara sign failed");
        return NULL;
    }
    return sign;
}

static ResultCode ParseRoot(ExecutorResultInfo *result, TlvListNode *body)
{
    Buffer *msg = GetBuffPara(body, AUTH_ROOT);
    if (!IsBufferValid(msg)) {
        LOG_ERROR("parse msg failed");
        return RESULT_BAD_PARAM;
    }
    Buffer *data = NULL;
    Buffer *sign = NULL;
    TlvListNode *parseBody = CreateTlvList();
    if (parseBody == NULL) {
        LOG_ERROR("parseBody is null");
        DestoryBuffer(msg);
        return RESULT_NO_MEMORY;
    }
    int32_t ret = ParseTlvWrapper(msg->buf, msg->contentSize, parseBody);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("parse failed");
        goto EXIT;
    }
    data = ParseExecutorResultData(parseBody->next);
    if (!IsBufferValid(data)) {
        LOG_ERROR("parse data failed");
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }
    ret = ParseExecutorResultInfo(data, result);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("parse info failed");
        goto EXIT;
    }
    sign = ParseExecutorResultSign(parseBody->next);
    if (!IsBufferValid(sign)) {
        LOG_ERROR("parse sign failed");
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }
    if (!IsExecutorInfoValid(result, data, sign)) {
        LOG_ERROR("executor info is invalid");
        ret = RESULT_GENERAL_ERROR;
    }
EXIT:
    DestoryBuffer(data);
    DestoryBuffer(sign);
    DestoryBuffer(msg);
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
        goto FAIL;
    }
    if (memset_s(result, sizeof(ExecutorResultInfo), 0, sizeof(ExecutorResultInfo)) != EOK) {
        LOG_ERROR("set result failed");
        goto FAIL;
    }
    ret = ParseRoot(result, parseBody->next);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ParseExecutorResult failed");
        goto FAIL;
    }
    DestroyTlvList(parseBody);
    return result;

FAIL:
    DestroyTlvList(parseBody);
    DestoryExecutorResultInfo(result);
    return NULL;
}

void DestoryExecutorResultInfo(ExecutorResultInfo *result)
{
    if (result == NULL) {
        return;
    }
    if (result->rootSecret != NULL) {
        DestoryBuffer(result->rootSecret);
    }
    Free(result);
}

static bool IsExecutorInfoValid(const ExecutorResultInfo *executorResultInfo, const Buffer *data, const Buffer *sign)
{
    if (executorResultInfo == NULL) {
        LOG_ERROR("there is a problem with the data content");
        return false;
    }
    const CoAuthSchedule *currentSchedule = GetCoAuthSchedule(executorResultInfo->scheduleId);
    if (currentSchedule == NULL) {
        LOG_ERROR("get schedule info failed");
        return false;
    }
    Buffer *publicKey = NULL;
    for (uint32_t index = 0; index < currentSchedule->executorSize; ++index) {
        const ExecutorInfoHal *executor = &((currentSchedule->executors)[index]);
        if (executor->executorRole == VERIFIER || executor->executorRole == ALL_IN_ONE) {
            publicKey = CreateBufferByData(executor->pubKey, PUBLIC_KEY_LEN);
            break;
        }
    }
    if (!IsBufferValid(publicKey)) {
        LOG_ERROR("get publicKey failed");
        return false;
    }
    ResultCode ret = Ed25519Verify(publicKey, data, sign);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("verify sign failed");
        DestoryBuffer(publicKey);
        return false;
    }
    DestoryBuffer(publicKey);
    return true;
}

static Buffer *SerializeExecutorMsgData(uint32_t authType, uint32_t propertyMode, const TemplateIdArrays *templateIds)
{
    if ((propertyMode != PROPERMODE_UNLOCK && propertyMode != PROPERMODE_LOCK) ||
        templateIds->num > MAX_TEMPLATE_OF_SCHEDULE) {
        LOG_ERROR("param is invalid");
        return NULL;
    }
    TlvListNode *parseBody = CreateTlvList();
    if (parseBody == NULL) {
        LOG_ERROR("parseBody is null");
        return NULL;
    }
    int32_t ret = TlvAppendObject(parseBody, AUTH_PROPERTY_MODE, (uint8_t *)&propertyMode, sizeof(uint32_t));
    if (ret != OPERA_SUCC) {
        LOG_ERROR("append propertyMode failed");
        goto FAIL;
    }
    ret = TlvAppendObject(parseBody, AUTH_TYPE, (uint8_t *)&authType, sizeof(authType));
    if (ret != OPERA_SUCC) {
        LOG_ERROR("append authType failed");
        goto FAIL;
    }
    ret = TlvAppendObject(parseBody, AUTH_TEMPLATE_ID_LIST,
        (uint8_t *)templateIds->value, templateIds->num * sizeof(uint64_t));
    if (ret != OPERA_SUCC) {
        LOG_ERROR("append template list failed");
        goto FAIL;
    }
    uint64_t time = GetSystemTime();
    ret = TlvAppendObject(parseBody, AUTH_TIME_STAMP, (uint8_t *)&time, sizeof(uint64_t));
    if (ret != OPERA_SUCC) {
        LOG_ERROR("append time failed");
        goto FAIL;
    }
    Buffer *data = CreateBufferBySize(BUFFER_SIZE);
    if (!IsBufferValid(data)) {
        LOG_ERROR("buf is null");
        goto FAIL;
    }
    ret = SerializeTlvWrapper(parseBody, data->buf, data->maxSize, &data->contentSize);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("serialize tlv failed");
        DestoryBuffer(data);
        goto FAIL;
    }
    DestroyTlvList(parseBody);
    return data;

FAIL:
    DestroyTlvList(parseBody);
    return NULL;
}

static Buffer *SerializeExecutorMsg(const Buffer *data, const Buffer *signatrue)
{
    TlvListNode *parseBody = CreateTlvList();
    if (parseBody == NULL) {
        LOG_ERROR("data parseBody is null");
        return NULL;
    }
    int32_t ret = TlvAppendObject(parseBody, AUTH_DATA, data->buf, data->contentSize);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("append auth data failed");
        goto FAIL;
    }
    if (signatrue != NULL) {
        ret = TlvAppendObject(parseBody, AUTH_SIGNATURE, signatrue->buf, signatrue->contentSize);
        if (ret != OPERA_SUCC) {
            LOG_ERROR("append signature failed");
            goto FAIL;
        }
    }
    Buffer *msgTlvData = CreateBufferBySize(BUFFER_SIZE);
    if (!IsBufferValid(msgTlvData)) {
        LOG_ERROR("buf is null");
        goto FAIL;
    }
    ret = SerializeTlvWrapper(parseBody, msgTlvData->buf, msgTlvData->maxSize, &msgTlvData->contentSize);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("serialize tlv failed");
        DestoryBuffer(msgTlvData);
        goto FAIL;
    }
    return msgTlvData;

FAIL:
    DestroyTlvList(parseBody);
    return NULL;
}

static Buffer *SerializeRootMsg(const Buffer *msg)
{
    TlvListNode *rootParseBody = CreateTlvList();
    if (rootParseBody == NULL) {
        LOG_ERROR("rootParseBody is null");
        return NULL;
    }
    int32_t ret = TlvAppendObject(rootParseBody, AUTH_ROOT, msg->buf, msg->contentSize);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("append msg failed");
        DestroyTlvList(rootParseBody);
        return NULL;
    }
    Buffer *rootMsg = CreateBufferBySize(BUFFER_SIZE);
    if (!IsBufferValid(rootMsg)) {
        LOG_ERROR("buf is null");
        DestroyTlvList(rootParseBody);
        return NULL;
    }
    ret = SerializeTlvWrapper(rootParseBody, rootMsg->buf, rootMsg->maxSize, &rootMsg->contentSize);
    if (ret != OPERA_SUCC) {
        LOG_ERROR("serialize tlv failed");
        DestroyTlvList(rootParseBody);
        DestoryBuffer(rootMsg);
        return NULL;
    }
    DestroyTlvList(rootParseBody);
    return rootMsg;
}

static Buffer *CreateExecutorMsg(uint32_t authType, uint32_t authPropertyMode, const TemplateIdArrays *templateIds)
{
    if (templateIds == NULL) {
        LOG_ERROR("templateIds is null");
        return NULL;
    }

    Buffer *data = SerializeExecutorMsgData(authType, authPropertyMode, templateIds);
    if (!IsBufferValid(data)) {
        LOG_ERROR("data is null");
        return NULL;
    }
    Buffer *signatrue = NULL;
    if (authPropertyMode == PROPERMODE_UNLOCK) {
        signatrue = ExecutorMsgSign(data);
        if (!IsBufferValid(signatrue)) {
            LOG_ERROR("signature is invalid");
            DestoryBuffer(data);
            return NULL;
        }
    }

    Buffer *msg = SerializeExecutorMsg(data, signatrue);
    DestoryBuffer(data);
    DestoryBuffer(signatrue);
    if (!IsBufferValid(msg)) {
        LOG_ERROR("msg is invalid");
        return NULL;
    }
    Buffer *rootMsg = SerializeRootMsg(msg);
    DestoryBuffer(msg);
    return rootMsg;
}

static void DestoryExecutorMsg(void *data)
{
    if (data == NULL) {
        return;
    }
    ExecutorMsg *msg = (ExecutorMsg *)data;
    DestoryBuffer(msg->msg);
    Free(msg);
}

static ResultCode GetExecutorTemplateList(const ExecutorInfoHal *executorNode, TemplateIdArrays *templateIds)
{
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, executorNode->authType);
    SetCredentialConditionExecutorSensorHint(&condition, executorNode->executorSensorHint);
    LinkedList *credList = QueryCredentialLimit(&condition);
    if (credList == NULL) {
        LOG_ERROR("query credential failed");
        DestroyLinkedList(credList);
        return RESULT_UNKNOWN;
    }
    uint32_t credListNum = credList->getSize(credList);
    if (credListNum > MAX_CREDENTIAL) {
        LOG_ERROR("cred num is invalid");
        DestroyLinkedList(credList);
        return RESULT_REACH_LIMIT;
    }
    if (credListNum == 0) {
        templateIds->value = NULL;
        templateIds->num = 0;
        DestroyLinkedList(credList);
        return RESULT_SUCCESS;
    }
    templateIds->value = (uint64_t *)Malloc(sizeof(uint64_t) * credListNum);
    if (templateIds->value == NULL) {
        LOG_ERROR("value malloc failed");
        DestroyLinkedList(credList);
        return RESULT_NO_MEMORY;
    }
    templateIds->num = 0;
    LinkedListNode *temp = credList->head;
    while (temp != NULL) {
        if (temp->data == NULL) {
            LOG_ERROR("link node is invalid");
            DestroyLinkedList(credList);
            Free(templateIds->value);
            templateIds->value = NULL;
            return RESULT_UNKNOWN;
        }
        CredentialInfoHal *credentialHal = (CredentialInfoHal *)temp->data;
        templateIds->value[templateIds->num] = credentialHal->templateId;
        ++(templateIds->num);
        temp = temp->next;
    }
    DestroyLinkedList(credList);
    return RESULT_SUCCESS;
}

static ResultCode AssemblyMessage(const ExecutorInfoHal *executorNode, uint32_t authPropertyMode,
    LinkedList *executorMsg)
{
    TemplateIdArrays templateIds;
    ResultCode ret = GetExecutorTemplateList(executorNode, &templateIds);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get template list failed");
        return ret;
    }
    if (templateIds.num == 0) {
        return RESULT_SUCCESS;
    }
    ExecutorMsg *msg = (ExecutorMsg *)Malloc(sizeof(ExecutorMsg));
    if (msg == NULL) {
        LOG_ERROR("msg is null");
        Free(templateIds.value);
        return RESULT_NO_MEMORY;
    }
    msg->executorIndex = executorNode->executorIndex;
    msg->msg = CreateExecutorMsg(executorNode->authType, authPropertyMode, &templateIds);
    if (msg->msg == NULL) {
        LOG_ERROR("msg's msg is null");
        Free(templateIds.value);
        DestoryExecutorMsg(msg);
        return RESULT_NO_MEMORY;
    }
    ret = executorMsg->insert(executorMsg, msg);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("insert msg failed");
        DestoryExecutorMsg(msg);
    }
    Free(templateIds.value);
    return ret;
}

static ResultCode TraverseExecutor(uint32_t executorRole, uint32_t authPropertyMode, LinkedList *executorMsg)
{
    ExecutorCondition condition = {};
    SetExecutorConditionExecutorRole(&condition, executorRole);
    LinkedList *executors = QueryExecutor(&condition);
    if (executors == NULL) {
        LOG_ERROR("query executor failed");
        return RESULT_UNKNOWN;
    }
    LinkedListNode *temp = executors->head;
    while (temp != NULL) {
        if (temp->data == NULL) {
            LOG_ERROR("list node is invalid");
            DestroyLinkedList(executors);
            return RESULT_UNKNOWN;
        }
        ExecutorInfoHal *executorNode = (ExecutorInfoHal *)temp->data;
        if (executorNode->authType != PIN_AUTH) {
            ResultCode ret = AssemblyMessage(executorNode, authPropertyMode, executorMsg);
            if (ret != RESULT_SUCCESS) {
                LOG_ERROR("assembly message failed");
                DestroyLinkedList(executors);
                return ret;
            }
        }
        temp = temp->next;
    }
    DestroyLinkedList(executors);
    return RESULT_SUCCESS;
}

ResultCode GetExecutorMsgList(uint32_t authPropertyMode, LinkedList **executorMsg)
{
    if (executorMsg == NULL) {
        LOG_ERROR("executorMsg is null");
        return RESULT_BAD_PARAM;
    }
    *executorMsg = CreateLinkedList(DestoryExecutorMsg);
    if (*executorMsg == NULL) {
        LOG_ERROR("create list failed");
        return RESULT_NO_MEMORY;
    }
    ResultCode ret = TraverseExecutor(VERIFIER, authPropertyMode, *executorMsg);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("traverse verifier failed");
        DestroyLinkedList(*executorMsg);
        *executorMsg = NULL;
        return ret;
    }
    ret = TraverseExecutor(ALL_IN_ONE, authPropertyMode, *executorMsg);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("traverse allInOne executor failed");
        DestroyLinkedList(*executorMsg);
        *executorMsg = NULL;
    }
    return ret;
}
