/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "coauth.h"
#include "ed25519_key.h"
#include "idm_database.h"

#define ROOT_SECRET_LEN 32

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

IAM_STATIC ResultCode SignData(const Uint8Array *dataTlv, Uint8Array *signDataTlv)
{
    Buffer data = GetTmpBuffer(dataTlv->data, dataTlv->len, dataTlv->len);
    if (!IsBufferValid(&data)) {
        LOG_ERROR("data is invalid");
        return RESULT_GENERAL_ERROR;
    }
    ResultCode result = RESULT_SUCCESS;
    Buffer *signData = ExecutorMsgSign(&data);
    if (!IsBufferValid(signData)) {
        LOG_ERROR("signData is invalid");
        return RESULT_GENERAL_ERROR;
    }
    if (signData->contentSize != ED25519_FIX_SIGN_BUFFER_SIZE) {
        LOG_ERROR("sign data len invalid");
        result = RESULT_GENERAL_ERROR;
        goto FAIL;
    }

    if (memcpy_s(signDataTlv->data, signDataTlv->len, signData->buf, signData->contentSize) != EOK) {
        LOG_ERROR("copy sign to signDtaTlv failed");
        result = RESULT_GENERAL_ERROR;
        goto FAIL;
    }
    signDataTlv->len = signData->contentSize;
    LOG_INFO("sign data success");

FAIL:
    DestoryBuffer(signData);
    return result;
}

IAM_STATIC ResultCode GetAttributeDataAndSignTlv(const Attribute *attribute, bool needSignature,
    Uint8Array *retDataAndSignTlv)
{
    Attribute *dataAndSignAttribute = CreateEmptyAttribute();
    Uint8Array dataTlv = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    Uint8Array signTlv = { Malloc(ED25519_FIX_SIGN_BUFFER_SIZE), ED25519_FIX_SIGN_BUFFER_SIZE };

    ResultCode result = RESULT_GENERAL_ERROR;
    do {
        if (dataAndSignAttribute == NULL || IS_ARRAY_NULL(dataTlv) || IS_ARRAY_NULL(signTlv)) {
            LOG_ERROR("dataAndSignAttribute or dataTlv or signTlv is NULL");
            break;
        }
        result = GetAttributeSerializedMsg(attribute, &dataTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeSerializedMsg for data fail");
            break;
        }

        result = SetAttributeUint8Array(dataAndSignAttribute, AUTH_DATA, dataTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("SetAttributeUint8Array for data fail");
            break;
        }
        if (needSignature) {
            result = SignData(&dataTlv, &signTlv);
            if (result != RESULT_SUCCESS) {
                LOG_ERROR("SignData fail");
                break;
            }
            result = SetAttributeUint8Array(dataAndSignAttribute, AUTH_SIGNATURE, signTlv);
            if (result != RESULT_SUCCESS) {
                LOG_ERROR("SetAttributeUint8Array for signature fail");
                break;
            }
        }
        result = GetAttributeSerializedMsg(dataAndSignAttribute, retDataAndSignTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeSerializedMsg fail");
            break;
        }
    } while (0);

    Free(signTlv.data);
    Free(dataTlv.data);
    FreeAttribute(&dataAndSignAttribute);
    return result;
}

ResultCode GetAttributeExecutorMsg(const Attribute *attribute, bool needSignature, Uint8Array *retMsg)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, RESULT_GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(retMsg == NULL, RESULT_GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(*retMsg), RESULT_GENERAL_ERROR);

    Attribute *rootAttribute = CreateEmptyAttribute();
    Uint8Array dataAndSignTlv = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };

    ResultCode result = RESULT_GENERAL_ERROR;
    do {
        if (rootAttribute == NULL || IS_ARRAY_NULL(dataAndSignTlv)) {
            LOG_ERROR("rootAttribute or dataAndSignTlv is NULL");
            break;
        }

        result = GetAttributeDataAndSignTlv(attribute, needSignature, &dataAndSignTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeDataAndSignTlv fail");
            break;
        }
        result = SetAttributeUint8Array(rootAttribute, AUTH_ROOT, dataAndSignTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("SetAttributeUint8Array fail");
            break;
        }
        result = GetAttributeSerializedMsg(rootAttribute, retMsg);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeSerializedMsg fail");
            break;
        }
    } while (0);

    Free(dataAndSignTlv.data);
    FreeAttribute(&rootAttribute);
    return result;
}

IAM_STATIC ResultCode Ed25519VerifyData(uint64_t scheduleId, Uint8Array dataTlv, Uint8Array signTlv)
{
    ResultCode result = RESULT_GENERAL_ERROR;
    const CoAuthSchedule *currentSchedule = GetCoAuthSchedule(scheduleId);
    IF_TRUE_LOGE_AND_RETURN_VAL(currentSchedule == NULL, result);
    Buffer *publicKey = NULL;
    for (uint32_t index = 0; index < currentSchedule->executorSize; ++index) {
        const ExecutorInfoHal *executor = &((currentSchedule->executors)[index]);
        if (executor->executorRole == VERIFIER || executor->executorRole == ALL_IN_ONE) {
            publicKey = CreateBufferByData(executor->pubKey, PUBLIC_KEY_LEN);
            break;
        }
    }
    Buffer data = GetTmpBuffer(dataTlv.data, dataTlv.len, dataTlv.len);
    Buffer sign = GetTmpBuffer(signTlv.data, signTlv.len, signTlv.len);
    if (!IsBufferValid(publicKey) || !IsBufferValid(&data) || !IsBufferValid(&sign)) {
        LOG_ERROR("data or sign is invalid");
        goto FAIL;
    }
    result = (ResultCode)Ed25519Verify(publicKey, &data, &sign);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("verify sign failed");
        goto FAIL;
    }
    LOG_INFO("Ed25519 verify success");

FAIL:
    DestoryBuffer(publicKey);
    return result;
}

IAM_STATIC ResultCode VerifyDataTlvSignature(const Attribute *dataAndSignAttribute, const Uint8Array dataTlv)
{
    Attribute *dataAttribute = CreateAttributeFromSerializedMsg(dataTlv);
    Uint8Array signTlv = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };

    ResultCode result = RESULT_GENERAL_ERROR;
    do {
        if (dataAttribute == NULL || IS_ARRAY_NULL(signTlv)) {
            LOG_ERROR("dataAttribute or signTlv is null");
            break;
        }
        result = GetAttributeUint8Array(dataAndSignAttribute, AUTH_SIGNATURE, &signTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeUint8Array fail");
            break;
        }

        uint64_t scheduleId;
        result = GetAttributeUint64(dataAttribute, AUTH_SCHEDULE_ID, &scheduleId);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeUint64 scheduleId fail");
            break;
        }
        result = Ed25519VerifyData(scheduleId, dataTlv, signTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("Ed25519VerifyData fail");
            break;
        }
    } while (0);

    Free(signTlv.data);
    FreeAttribute(&dataAttribute);
    return result;
}

IAM_STATIC Attribute *CreateAttributeFromDataAndSignTlv(const Uint8Array dataAndSignTlv, bool needVerifySignature)
{
    Attribute *dataAndSignAttribute = CreateAttributeFromSerializedMsg(dataAndSignTlv);
    Uint8Array dataTlv = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };

    Attribute *attribute = NULL;
    do {
        if (dataAndSignAttribute == NULL || IS_ARRAY_NULL(dataTlv)) {
            LOG_ERROR("dataAndSignAttribute or dataTlv is null");
            break;
        }
        if (GetAttributeUint8Array(dataAndSignAttribute, AUTH_DATA, &dataTlv) != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeUint8Array fail");
            break;
        }
        if (needVerifySignature) {
            if (VerifyDataTlvSignature(dataAndSignAttribute, dataTlv) != RESULT_SUCCESS) {
                LOG_ERROR("VerifyDataTlvSignature fail");
                break;
            }
        }
        attribute = CreateAttributeFromSerializedMsg(dataTlv);
        if (attribute == NULL) {
            LOG_ERROR("CreateAttributeFromSerializedMsg fail");
            break;
        }
    } while (0);

    Free(dataTlv.data);
    FreeAttribute(&dataAndSignAttribute);
    return attribute;
}

IAM_STATIC Attribute *CreateAttributeFromExecutorMsg(const Uint8Array msg, bool needVerifySignature)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(msg), NULL);

    Attribute *msgAttribute = CreateAttributeFromSerializedMsg(msg);
    Uint8Array dataAndSignTlv = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };

    Attribute *attribute = NULL;
    do {
        if (msgAttribute == NULL || IS_ARRAY_NULL(dataAndSignTlv)) {
            LOG_ERROR("msgAttribute or dataAndSignTlv is null");
            break;
        }

        ResultCode result = GetAttributeUint8Array(msgAttribute, AUTH_ROOT, &dataAndSignTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeUint8Array fail");
            break;
        }

        attribute = CreateAttributeFromDataAndSignTlv(dataAndSignTlv, needVerifySignature);
        if (attribute == NULL) {
            LOG_ERROR("CreateAttributeFromDataAndSignTlv fail");
            break;
        }
    } while (0);

    (void)memset_s(dataAndSignTlv.data, MAX_EXECUTOR_MSG_LEN, 0, MAX_EXECUTOR_MSG_LEN);
    Free(dataAndSignTlv.data);
    FreeAttribute(&msgAttribute);
    return attribute;
}

IAM_STATIC void GetRootSecretFromAttribute(const Attribute *attribute, ExecutorResultInfo *resultInfo)
{
    Uint8Array array = { Malloc(ROOT_SECRET_LEN), ROOT_SECRET_LEN };
    IF_TRUE_LOGE_AND_RETURN(IS_ARRAY_NULL(array));
    ResultCode result = GetAttributeUint8Array(attribute, AUTH_ROOT_SECRET, &(array));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("There is no rootSecret in this attribute");
        goto EXIT;
    }
    if (array.len != ROOT_SECRET_LEN) {
        LOG_ERROR("rootSecret len is invalid");
        goto EXIT;
    }
    resultInfo->rootSecret = CreateBufferByData(array.data, array.len);
    if (!IsBufferValid(resultInfo->rootSecret)) {
        LOG_ERROR("Generate rootSecret buffer failed");
        goto EXIT;
    }
    LOG_INFO("get rootSecret success");

EXIT:
    (void)memset_s(array.data, ROOT_SECRET_LEN, 0, ROOT_SECRET_LEN);
    Free(array.data);
}

IAM_STATIC ResultCode GetExecutorResultInfoFromAttribute(const Attribute *attribute, ExecutorResultInfo *resultInfo)
{
    ResultCode result = RESULT_GENERAL_ERROR;
    result = GetAttributeInt32(attribute, AUTH_RESULT_CODE, &(resultInfo->result));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 result failed");
        return result;
    }
    result = GetAttributeUint64(attribute, AUTH_TEMPLATE_ID, &(resultInfo->templateId));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint64 templateId failed");
        return result;
    }
    result = GetAttributeUint64(attribute, AUTH_SCHEDULE_ID, &(resultInfo->scheduleId));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint64 scheduleId failed");
        return result;
    }
    result = GetAttributeUint64(attribute, AUTH_SUB_TYPE, &(resultInfo->authSubType));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint64 authSubType failed");
        return result;
    }
    result = GetAttributeInt32(attribute, AUTH_REMAIN_COUNT, &(resultInfo->remainTimes));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 remainTimes failed");
        return result;
    }
    result = GetAttributeInt32(attribute, AUTH_REMAIN_TIME, &(resultInfo->freezingTime));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 freezingTime failed");
        return result;
    }
    result = GetAttributeUint32(attribute, AUTH_CAPABILITY_LEVEL, &(resultInfo->capabilityLevel));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint32 capabilityLevel failed");
        return result;
    }

    // Only pin auth has rootSecret
    GetRootSecretFromAttribute(attribute, resultInfo);
    return RESULT_SUCCESS;
}

ExecutorResultInfo *CreateExecutorResultInfo(const Buffer *tlv)
{
    if (!IsBufferValid(tlv)) {
        LOG_ERROR("param is invalid");
        return NULL;
    }

    Uint8Array msg = { tlv->buf, tlv->contentSize };
    Attribute *attribute = CreateAttributeFromExecutorMsg(msg, true);
    if (attribute == NULL) {
        LOG_ERROR("CreateAttributeFromExecutorMsg failed");
        return NULL;
    }

    ExecutorResultInfo *result = Malloc(sizeof(ExecutorResultInfo));
    if (result == NULL) {
        LOG_ERROR("malloc failed");
        FreeAttribute(&attribute);
        return result;
    }
    (void)memset_s(result, sizeof(ExecutorResultInfo), 0, sizeof(ExecutorResultInfo));

    if (GetExecutorResultInfoFromAttribute(attribute, result) != RESULT_SUCCESS) {
        LOG_ERROR("GetExecutorResultInfoFromAttribute failed");
        FreeAttribute(&attribute);
        DestoryExecutorResultInfo(result);
        return NULL;
    }

    FreeAttribute(&attribute);
    return result;
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

IAM_STATIC ResultCode SetExecutorMsgToAttribute(uint32_t authType, uint32_t authPropertyMode,
    const Uint64Array *templateIds, Attribute *attribute)
{
    ResultCode result = SetAttributeUint32(attribute, AUTH_PROPERTY_MODE, authPropertyMode);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint32 propertyMode failed");
        return RESULT_GENERAL_ERROR;
    }
    result = SetAttributeUint32(attribute, AUTH_TYPE, authType);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint32 authType failed");
        return RESULT_GENERAL_ERROR;
    }
    Uint64Array templateIdsIn = { templateIds->data, templateIds->len };
    result = SetAttributeUint64Array(attribute, AUTH_TEMPLATE_ID_LIST, templateIdsIn);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint64Array templateIdsIn failed");
        return RESULT_GENERAL_ERROR;
    }
    uint64_t time = GetSystemTime();
    result = SetAttributeUint64(attribute, AUTH_TIME_STAMP, time);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint64 time failed");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}


IAM_STATIC Buffer *CreateExecutorMsg(uint32_t authType, uint32_t authPropertyMode, const Uint64Array *templateIds)
{
    if (templateIds == NULL) {
        LOG_ERROR("templateIds is null");
        return NULL;
    }
    Buffer *retBuffer = NULL;
    Uint8Array retInfo = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    Attribute *attribute = CreateEmptyAttribute();
    if (attribute == NULL || IS_ARRAY_NULL(retInfo)) {
        LOG_ERROR("generate attribute or retInfo failed");
        goto FAIL;
    }

    ResultCode result = SetExecutorMsgToAttribute(authType, authPropertyMode, templateIds, attribute);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set msg to attribute failed");
        goto FAIL;
    }

    if (authPropertyMode == PROPERTY_MODE_UNFREEZE) {
        result = GetAttributeExecutorMsg(attribute, true, &retInfo);
    } else {
        result = GetAttributeExecutorMsg(attribute, false, &retInfo);
    }
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeExecutorMsg failed");
        goto FAIL;
    }

    retBuffer = CreateBufferByData(retInfo.data, retInfo.len);
    if (!IsBufferValid(retBuffer)) {
        LOG_ERROR("generate result buffer failed");
        goto FAIL;
    }
    LOG_INFO("CreateExecutorMsg success");

FAIL:
    FreeAttribute(&attribute);
    Free(retInfo.data);
    return retBuffer;
}

IAM_STATIC void DestoryExecutorMsg(void *data)
{
    if (data == NULL) {
        return;
    }
    ExecutorMsg *msg = (ExecutorMsg *)data;
    DestoryBuffer(msg->msg);
    Free(msg);
}

IAM_STATIC ResultCode GetExecutorTemplateList(const ExecutorInfoHal *executorNode, Uint64Array *templateIds)
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
        templateIds->data = NULL;
        templateIds->len = 0;
        DestroyLinkedList(credList);
        return RESULT_SUCCESS;
    }
    templateIds->data = (uint64_t *)Malloc(sizeof(uint64_t) * credListNum);
    if (templateIds->data == NULL) {
        LOG_ERROR("data malloc failed");
        DestroyLinkedList(credList);
        return RESULT_NO_MEMORY;
    }
    templateIds->len = 0;
    LinkedListNode *temp = credList->head;
    while (temp != NULL) {
        if (temp->data == NULL) {
            LOG_ERROR("link node is invalid");
            DestroyLinkedList(credList);
            Free(templateIds->data);
            templateIds->data = NULL;
            return RESULT_UNKNOWN;
        }
        CredentialInfoHal *credentialHal = (CredentialInfoHal *)temp->data;
        templateIds->data[templateIds->len] = credentialHal->templateId;
        ++(templateIds->len);
        temp = temp->next;
    }
    DestroyLinkedList(credList);
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode AssemblyMessage(const ExecutorInfoHal *executorNode, uint32_t authPropertyMode,
    LinkedList *executorMsg)
{
    Uint64Array templateIds;
    ResultCode ret = GetExecutorTemplateList(executorNode, &templateIds);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get template list failed");
        return ret;
    }
    if (templateIds.len == 0) {
        return RESULT_SUCCESS;
    }
    ExecutorMsg *msg = (ExecutorMsg *)Malloc(sizeof(ExecutorMsg));
    if (msg == NULL) {
        LOG_ERROR("msg is null");
        Free(templateIds.data);
        return RESULT_NO_MEMORY;
    }
    msg->executorIndex = executorNode->executorIndex;
    msg->msg = CreateExecutorMsg(executorNode->authType, authPropertyMode, &templateIds);
    if (msg->msg == NULL) {
        LOG_ERROR("msg's msg is null");
        Free(templateIds.data);
        DestoryExecutorMsg(msg);
        return RESULT_NO_MEMORY;
    }
    ret = executorMsg->insert(executorMsg, msg);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("insert msg failed");
        DestoryExecutorMsg(msg);
    }
    Free(templateIds.data);
    return ret;
}

IAM_STATIC ResultCode TraverseExecutor(uint32_t executorRole, uint32_t authPropertyMode, LinkedList *executorMsg)
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
