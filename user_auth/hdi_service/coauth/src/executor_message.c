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
#include "hmac_key.h"
#include "idm_database.h"
#include "udid_manager.h"
#include "user_sign_centre.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

IAM_STATIC ResultCode SignData(const Uint8Array *dataTlv, Uint8Array *signDataTlv, SignParam signParam)
{
    Buffer data = GetTmpBuffer(dataTlv->data, dataTlv->len, dataTlv->len);
    if (!IsBufferValid(&data)) {
        LOG_ERROR("data is invalid");
        return RESULT_GENERAL_ERROR;
    }
    ResultCode result = RESULT_SUCCESS;
    Buffer *signData = NULL;
    if (signParam.keyType == KEY_TYPE_CROSS_DEVICE) {
        signData = HmacSign(&data, signParam);
    } else {
        signData = ExecutorMsgSign(&data);
    }
    if (!IsBufferValid(signData)) {
        LOG_ERROR("signData is invalid");
        return RESULT_GENERAL_ERROR;
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

IAM_STATIC ResultCode GetAttributeDataAndSignTlv(const Attribute *attribute, Uint8Array *retDataAndSignTlv,
    SignParam signParam)
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

        result = SetAttributeUint8Array(dataAndSignAttribute, ATTR_DATA, dataTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("SetAttributeUint8Array for data fail");
            break;
        }
        if (signParam.needSignature) {
            result = SignData(&dataTlv, &signTlv, signParam);
            if (result != RESULT_SUCCESS) {
                LOG_ERROR("SignData fail");
                break;
            }
            result = SetAttributeUint8Array(dataAndSignAttribute, ATTR_SIGNATURE, signTlv);
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

ResultCode GetAttributeExecutorMsg(const Attribute *attribute, Uint8Array *retMsg, SignParam signParam)
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

        result = GetAttributeDataAndSignTlv(attribute, &dataAndSignTlv, signParam);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeDataAndSignTlv fail");
            break;
        }
        result = SetAttributeUint8Array(rootAttribute, ATTR_ROOT, dataAndSignTlv);
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

IAM_STATIC ResultCode VerifyDataTlvSignature(const Attribute *dataAndSignAttribute, const Uint8Array dataTlv,
    SignParam signParam)
{
    Attribute *dataAttribute = CreateAttributeFromSerializedMsg(dataTlv);
    Uint8Array signTlv = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };

    ResultCode result = RESULT_GENERAL_ERROR;
    do {
        if (dataAttribute == NULL || IS_ARRAY_NULL(signTlv)) {
            LOG_ERROR("dataAttribute or signTlv is null");
            break;
        }
        result = GetAttributeUint8Array(dataAndSignAttribute, ATTR_SIGNATURE, &signTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeUint8Array fail");
            break;
        }
        if (signParam.keyType == KEY_TYPE_CROSS_DEVICE) {
            Buffer data = GetTmpBuffer(dataTlv.data, dataTlv.len, dataTlv.len);
            Buffer sign = GetTmpBuffer(signTlv.data, signTlv.len, signTlv.len);
            result = HmacVerify(&data, &sign, signParam);
            if (result != RESULT_SUCCESS) {
                LOG_ERROR("HmacVerify fail");
                break;
            }
        } else {
            uint64_t scheduleId;
            result = GetAttributeUint64(dataAttribute, ATTR_SCHEDULE_ID, &scheduleId);
            if (result != RESULT_SUCCESS) {
                LOG_ERROR("GetAttributeUint64 scheduleId fail");
                break;
            }
            result = Ed25519VerifyData(scheduleId, dataTlv, signTlv);
            if (result != RESULT_SUCCESS) {
                LOG_ERROR("Ed25519VerifyData fail");
                break;
            }
        }
    } while (0);

    Free(signTlv.data);
    FreeAttribute(&dataAttribute);
    return result;
}

IAM_STATIC Attribute *CreateAttributeFromDataAndSignTlv(const Uint8Array dataAndSignTlv, SignParam signParam)
{
    Attribute *dataAndSignAttribute = CreateAttributeFromSerializedMsg(dataAndSignTlv);
    Uint8Array dataTlv = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };

    Attribute *attribute = NULL;
    do {
        if (dataAndSignAttribute == NULL || IS_ARRAY_NULL(dataTlv)) {
            LOG_ERROR("dataAndSignAttribute or dataTlv is null");
            break;
        }
        if (GetAttributeUint8Array(dataAndSignAttribute, ATTR_DATA, &dataTlv) != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeUint8Array fail");
            break;
        }
        if (signParam.needSignature) {
            if (VerifyDataTlvSignature(dataAndSignAttribute, dataTlv, signParam) != RESULT_SUCCESS) {
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

IAM_STATIC Attribute *CreateAttributeFromExecutorMsg(const Uint8Array msg, SignParam signParam)
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

        ResultCode result = GetAttributeUint8Array(msgAttribute, ATTR_ROOT, &dataAndSignTlv);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetAttributeUint8Array fail");
            break;
        }

        attribute = CreateAttributeFromDataAndSignTlv(dataAndSignTlv, signParam);
        if (attribute == NULL) {
            LOG_ERROR("CreateAttributeFromDataAndSignTlv fail");
            break;
        }
    } while (0);

    Free(dataAndSignTlv.data);
    FreeAttribute(&msgAttribute);
    return attribute;
}

IAM_STATIC void GetRootSecretFromAttribute(const Attribute *attribute, ExecutorResultInfo *resultInfo)
{
    Uint8Array array = { Malloc(ROOT_SECRET_LEN), ROOT_SECRET_LEN };
    IF_TRUE_LOGE_AND_RETURN(IS_ARRAY_NULL(array));
    ResultCode result = GetAttributeUint8Array(attribute, ATTR_ROOT_SECRET, &(array));
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
    result = GetAttributeInt32(attribute, ATTR_RESULT_CODE, &(resultInfo->result));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 result failed");
        return result;
    }
    result = GetAttributeUint64(attribute, ATTR_TEMPLATE_ID, &(resultInfo->templateId));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint64 templateId failed");
        return result;
    }
    result = GetAttributeUint64(attribute, ATTR_SCHEDULE_ID, &(resultInfo->scheduleId));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint64 scheduleId failed");
        return result;
    }
    result = GetAttributeUint64(attribute, ATTR_PIN_SUB_TYPE, &(resultInfo->authSubType));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint64 authSubType failed");
        return result;
    }
    result = GetAttributeInt32(attribute, ATTR_REMAIN_ATTEMPTS, &(resultInfo->remainTimes));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 remainTimes failed");
        return result;
    }
    result = GetAttributeInt32(attribute, ATTR_LOCKOUT_DURATION, &(resultInfo->freezingTime));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 freezingTime failed");
        return result;
    }
    result = GetAttributeUint32(attribute, ATTR_CAPABILITY_LEVEL, &(resultInfo->capabilityLevel));
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
    SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_EXECUTOR };
    Attribute *attribute = CreateAttributeFromExecutorMsg(msg, signParam);
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
        DestroyExecutorResultInfo(result);
        return NULL;
    }

    FreeAttribute(&attribute);
    return result;
}

void DestroyExecutorResultInfo(ExecutorResultInfo *result)
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
    ResultCode result = SetAttributeUint32(attribute, ATTR_PROPERTY_MODE, authPropertyMode);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint32 propertyMode failed");
        return RESULT_GENERAL_ERROR;
    }
    result = SetAttributeUint32(attribute, ATTR_TYPE, authType);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint32 authType failed");
        return RESULT_GENERAL_ERROR;
    }
    Uint64Array templateIdsIn = { templateIds->data, templateIds->len };
    result = SetAttributeUint64Array(attribute, ATTR_TEMPLATE_ID_LIST, templateIdsIn);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint64Array templateIdsIn failed");
        return RESULT_GENERAL_ERROR;
    }
    uint64_t time = GetSystemTime();
    result = SetAttributeUint64(attribute, ATTR_TIME_STAMP, time);
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
        SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_EXECUTOR };
        result = GetAttributeExecutorMsg(attribute, &retInfo, signParam);
    } else {
        SignParam signParam = { .needSignature = false };
        result = GetAttributeExecutorMsg(attribute, &retInfo, signParam);
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

IAM_STATIC ResultCode GetExecutorTemplateList(
    int32_t userId, const ExecutorInfoHal *executorNode, Uint64Array *templateIds)
{
    CredentialCondition condition = {};
    SetCredentialConditionUserId(&condition, userId);
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

IAM_STATIC ResultCode AssemblyMessage(
    int32_t userId, const ExecutorInfoHal *executorNode, uint32_t authPropertyMode, LinkedList *executorMsg)
{
    Uint64Array templateIds;
    ResultCode ret = GetExecutorTemplateList(userId, executorNode, &templateIds);
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

IAM_STATIC ResultCode TraverseExecutor(
    int32_t userId, uint32_t executorRole, uint32_t authPropertyMode, LinkedList *executorMsg)
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
            ResultCode ret = AssemblyMessage(userId, executorNode, authPropertyMode, executorMsg);
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

ResultCode GetExecutorMsgList(int32_t userId, uint32_t authPropertyMode, LinkedList **executorMsg)
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
    ResultCode ret = TraverseExecutor(userId, ALL_IN_ONE, authPropertyMode, *executorMsg);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("traverse allInOne executor failed");
        DestroyLinkedList(*executorMsg);
        *executorMsg = NULL;
    }
    return ret;
}

IAM_STATIC ResultCode GetExecutorInfoHalFromAttribute(const Attribute *attribute, ExecutorInfoHal *resultInfo)
{
    ResultCode result = RESULT_GENERAL_ERROR;
    result = GetAttributeUint64(attribute, ATTR_EXECUTOR_INDEX, &(resultInfo->executorIndex));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint64 executorIndex failed");
        return result;
    }
    result = GetAttributeUint32(attribute, ATTR_TYPE, &(resultInfo->authType));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint32 authType failed");
        return result;
    }
    result = GetAttributeUint32(attribute, ATTR_EXECUTOR_ROLE, &(resultInfo->executorRole));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint32 executorRole failed");
        return result;
    }
    result = GetAttributeUint32(attribute, ATTR_ESL, &(resultInfo->esl));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint32 esl failed");
        return result;
    }
    Uint8Array pubKeyTlv = { resultInfo->pubKey, PUBLIC_KEY_LEN };
    result = GetAttributeUint8Array(attribute, ATTR_PUBLIC_KEY, &pubKeyTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint8Array pubKey fail");
        return result;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetExecutorInfoHal(Uint8Array tlv, ExecutorInfoHal *executorInfo)
{
    Attribute *attribute = CreateAttributeFromSerializedMsg(tlv);
    if (attribute == NULL) {
        LOG_ERROR("CreateAttributeFromSerializedMsg fail");
        return RESULT_GENERAL_ERROR;
    }

    ResultCode result = GetExecutorInfoHalFromAttribute(attribute, executorInfo);
    FreeAttribute(&attribute);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetExecutorInfoHalFromAttribute failed");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetAuthAttrsFromAttribute(const Attribute *attribute, Uint8Array *authAttrs)
{
    ResultCode result = GetAttributeUint8Array(attribute, ATTR_ATTRS, authAttrs);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint8Array authAttrs fail");
    }
    return result;
}

IAM_STATIC ResultCode GetRemoteExecutorInfoInner(Attribute *attribute, Uint8Array *authAttrs, Uint8Array *subMsgs,
    int *subMsgSize)
{
    if (GetAuthAttrsFromAttribute(attribute, authAttrs) != RESULT_SUCCESS) {
        LOG_ERROR("GetAuthAttrsFromAttribute failed");
        return RESULT_GENERAL_ERROR;
    }
    if (ParseMultiDataSerializedMsg(*authAttrs, subMsgs, subMsgSize) != RESULT_SUCCESS) {
        LOG_ERROR("ParseMultiDataSerializedMsg failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetRemoteExecutorInfo(const Buffer *msg, Uint8Array peerUdid, Uint8Array *subMsgs,
    int *subMsgSize)
{
    Uint8Array msgArray = { msg->buf, msg->contentSize };
    SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_CROSS_DEVICE, .peerUdid = peerUdid};
    Attribute *attribute = CreateAttributeFromExecutorMsg(msgArray, signParam);
    Uint8Array authAttrs = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    if (attribute == NULL || authAttrs.data == NULL) {
        LOG_ERROR("authAttrs malloc failed");
        FreeAttribute(&attribute);
        Free(authAttrs.data);
        return RESULT_GENERAL_ERROR;
    }

    ResultCode result = GetRemoteExecutorInfoInner(attribute, &authAttrs, subMsgs, subMsgSize);

    FreeAttribute(&attribute);
    Free(authAttrs.data);
    return result;
}

static bool CheckRemoteExecutorInfoInner(Uint8Array *subMsgs, int subMsgSize, ExecutorInfoHal *infoToCheck)
{
    for (int i = 0; i < subMsgSize; i++) {
        Uint8Array subMsg = subMsgs[i];
        ExecutorInfoHal executorInfo = {};
        ResultCode result = GetExecutorInfoHal(subMsg, &executorInfo);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("GetExecutorInfoHal failed");
            return false;
        }
        if ((executorInfo.authType == infoToCheck->authType) &&
            (executorInfo.executorRole == infoToCheck->executorRole) &&
            (executorInfo.esl == infoToCheck->esl) &&
            (memcmp(executorInfo.pubKey, infoToCheck->pubKey, PUBLIC_KEY_LEN) == 0)) {
            return true;
        }
    }
    LOG_ERROR("no matching executor info found");
    return false;
}

bool CheckRemoteExecutorInfo(const Buffer *msg, ExecutorInfoHal *infoToCheck)
{
    if (!IsBufferValid(msg) || (infoToCheck == NULL)) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    Uint8Array peerUdid = { infoToCheck->deviceUdid, sizeof(infoToCheck->deviceUdid) };
    Uint8Array subMsgs[MAX_SUB_MSG_NUM] = {0};
    int subMsgSize = MAX_SUB_MSG_NUM;
    ResultCode result = GetRemoteExecutorInfo(msg, peerUdid, &subMsgs[0], &subMsgSize);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetRemoteExecutorInfo failed");
        return false;
    }

    bool checkPass = CheckRemoteExecutorInfoInner(subMsgs, subMsgSize, infoToCheck);

    for (int i = 0; i < MAX_SUB_MSG_NUM; i++) {
        Free(subMsgs[i].data);
    }

    return checkPass;
}

IAM_STATIC ResultCode SetExecutorCollectMsgToAttribute(ScheduleInfoParam *scheduleInfo, const Uint8Array *publicKey,
    const Uint8Array challenge, Attribute *attribute)
{
    Uint8Array localUdid = { scheduleInfo->localUdid, sizeof(scheduleInfo->localUdid) };
    Uint8Array remoteUdid = { scheduleInfo->remoteUdid, sizeof(scheduleInfo->remoteUdid) };

    ResultCode result = SetAttributeUint64(attribute, ATTR_SCHEDULE_ID, scheduleInfo->scheduleId);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint64 scheduleId failed");
        return RESULT_GENERAL_ERROR;
    }

    result = SetAttributeUint8Array(attribute, ATTR_LOCAL_UDID, localUdid);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint8Array for localUdid fail");
        return RESULT_GENERAL_ERROR;
    }
    result = SetAttributeUint8Array(attribute, ATTR_PEER_UDID, remoteUdid);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint8Array for peerUdid fail");
        return RESULT_GENERAL_ERROR;
    }
    Uint8Array publicKeyIn = { publicKey->data, publicKey->len };
    result = SetAttributeUint8Array(attribute, ATTR_PUBLIC_KEY, publicKeyIn);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint8Array for publicKey fail");
        return RESULT_GENERAL_ERROR;
    }
    result = SetAttributeUint8Array(attribute, ATTR_CHALLENGE, challenge);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint8Array for challenge fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC Buffer *CreateExecutorCollectMsg(const Attribute *attributeSchedule, ScheduleInfoParam *scheduleInfo)
{
    uint8_t publicKeyData[PUBLIC_KEY_LEN] = {};
    Uint8Array publicKey = { publicKeyData, PUBLIC_KEY_LEN };
    ResultCode result = GetAttributeUint8Array(attributeSchedule, ATTR_PUBLIC_KEY, &publicKey);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint8Array publicKey fail");
        return NULL;
    }

    uint8_t challengeData[CHALLENGE_LEN] = {};
    Uint8Array challenge = { challengeData, CHALLENGE_LEN };
    ResultCode getChallengeRet = GetAttributeUint8Array(attributeSchedule, ATTR_CHALLENGE, &challenge);
    if (getChallengeRet != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint8Array challenge fail");
        return NULL;
    }

    Buffer *retBuffer = NULL;
    Attribute *attribute = CreateEmptyAttribute();
    Uint8Array retInfo = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    if (attribute == NULL || IS_ARRAY_NULL(retInfo)) {
        LOG_ERROR("attribute is null");
        goto FAIL;
    }
    result = SetExecutorCollectMsgToAttribute(scheduleInfo, &publicKey, challenge, attribute);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set msg to attribute failed");
        goto FAIL;
    }

    SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_EXECUTOR };
    result = GetAttributeExecutorMsg(attribute, &retInfo, signParam);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeExecutorMsg failed");
        goto FAIL;
    }

    retBuffer = CreateBufferByData(retInfo.data, retInfo.len);
    if (!IsBufferValid(retBuffer)) {
        LOG_ERROR("generate result buffer failed");
        goto FAIL;
    }
    LOG_INFO("CreateExecutorCollectMsg success");

FAIL:
    FreeAttribute(&attribute);
    Free(retInfo.data);
    return retBuffer;
}

static ResultCode GetExecutorIndexByCondition(uint32_t authType, uint32_t executorMatcher,
    Uint8Array deviceUdid, uint32_t executorRole, uint64_t *executorIndex)
{
    ExecutorCondition condition = {};
    SetExecutorConditionAuthType(&condition, authType);
    SetExecutorConditionExecutorMatcher(&condition, executorMatcher);
    SetExecutorConditionExecutorRole(&condition, executorRole);
    SetExecutorConditionDeviceUdid(&condition, deviceUdid);

    LinkedList *executorList = QueryExecutor(&condition);
    if (executorList == NULL) {
        LOG_ERROR("query executor failed");
        return RESULT_UNKNOWN;
    }

    if (executorList->getSize(executorList) != 1) {
        LOG_ERROR("executor list len is invalid");
        DestroyLinkedList(executorList);
        return RESULT_TYPE_NOT_SUPPORT;
    }

    LinkedListNode *temp = executorList->head;
    if (temp == NULL) {
        LOG_ERROR("get executorList head failed");
        DestroyLinkedList(executorList);
        return RESULT_UNKNOWN;
    }
    ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)temp->data;
    if (executorInfo == NULL) {
        LOG_ERROR("executorInfo is invalid");
        DestroyLinkedList(executorList);
        return RESULT_UNKNOWN;
    }

    *executorIndex = executorInfo->executorIndex;
    DestroyLinkedList(executorList);
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetScheduleInfoFromAttributeInner(const Attribute *attribute, ScheduleInfoParam *scheduleInfo)
{
    ResultCode result = GetAttributeUint64(attribute, ATTR_SCHEDULE_ID, &(scheduleInfo->scheduleId));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint64 scheduleId failed");
        return result;
    }
    result = GetAttributeUint32(attribute, ATTR_TYPE, &(scheduleInfo->authType));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint32 authType failed");
        return result;
    }
    result = GetAttributeUint32(attribute, ATTR_EXECUTOR_MATCHER, &(scheduleInfo->executorMatcher));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint32 executorMatcher failed");
        return result;
    }
    result = GetAttributeInt32(attribute, ATTR_SCHEDULE_MODE, &(scheduleInfo->scheduleMode));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 scheduleMode failed");
        return result;
    }
    Uint8Array remoteUdid = { scheduleInfo->remoteUdid, UDID_LEN };
    result = GetAttributeUint8Array(attribute, ATTR_VERIFIER_UDID, &remoteUdid);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint8Array remoteUdid failed");
    }
    return result;
}

IAM_STATIC ResultCode GetScheduleInfoFromAttribute(const Attribute *attribute, ScheduleInfoParam *scheduleInfo)
{
    ResultCode result = GetScheduleInfoFromAttributeInner(attribute, scheduleInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetScheduleInfoFromAttributeInner failed");
        return result;
    }
    uint32_t executorRole;
    result = GetAttributeUint32(attribute, ATTR_EXECUTOR_ROLE, &executorRole);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint32 scheduleMode failed");
        return result;
    }

    Uint8Array collectorUdid = { scheduleInfo->localUdid, UDID_LEN };
    result = GetAttributeUint8Array(attribute, ATTR_COLLECTOR_UDID, &collectorUdid);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint8Array localUdid failed");
        return result;
    }

    if (!IsLocalUdid(collectorUdid)) {
        LOG_ERROR("collector udid is not local udid");
        return RESULT_GENERAL_ERROR;
    }

    result = GetExecutorIndexByCondition(scheduleInfo->authType, scheduleInfo->executorMatcher,
        collectorUdid, executorRole, &scheduleInfo->executorIndex);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetExecutorIndex failed");
        return result;
    }

    scheduleInfo->executorMessages = CreateExecutorCollectMsg(attribute, scheduleInfo);
    if (!IsBufferValid(scheduleInfo->executorMessages)) {
        LOG_ERROR("create executorMessages failed");
        result = RESULT_GENERAL_ERROR;
    }
    return result;
}

ResultCode CreateScheduleInfo(const Buffer *tlv, Uint8Array peerUdid, ScheduleInfoParam *scheduleInfo)
{
    if (!IsBufferValid(tlv) || IS_ARRAY_NULL(peerUdid) || (scheduleInfo == NULL)) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }

    Uint8Array msg = { tlv->buf, tlv->contentSize };
    SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_CROSS_DEVICE, .peerUdid =  peerUdid };
    Attribute *attribute = CreateAttributeFromExecutorMsg(msg, signParam);
    if (attribute == NULL) {
        LOG_ERROR("CreateAttributeFromExecutorMsg failed");
        return RESULT_GENERAL_ERROR;
    }

    ResultCode result = GetScheduleInfoFromAttribute(attribute, scheduleInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetScheduleInfoFromAttribute failed");
    }
    FreeAttribute(&attribute);
    return result;
}

IAM_STATIC ResultCode GetAuthResultInfoFromAttribute(const Attribute *attribute, AuthResultParam *authResultInfo)
{
    ResultCode result = GetAttributeInt32(attribute, ATTR_RESULT, &(authResultInfo->result));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 result failed");
        return result;
    }
    result = GetAttributeInt32(attribute, ATTR_LOCKOUT_DURATION, &(authResultInfo->lockoutDuration));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 lockoutDuration failed");
        return result;
    }
    result = GetAttributeInt32(attribute, ATTR_REMAIN_ATTEMPTS, &(authResultInfo->remainAttempts));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 remainAttempts failed");
        return result;
    }
    result = GetAttributeInt32(attribute, ATTR_USER_ID, &(authResultInfo->userId));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeInt32 userId failed");
        return result;
    }

    uint8_t tokenData[AUTH_TOKEN_LEN] = {};
    Uint8Array tokenArray = { tokenData, AUTH_TOKEN_LEN };
    result = GetAttributeUint8Array(attribute, ATTR_TOKEN, &tokenArray);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeUint8Array token fail");
        return result;
    }
    authResultInfo->token = CreateBufferByData(tokenArray.data, tokenArray.len);
    if (!IsBufferValid(authResultInfo->token)) {
        LOG_ERROR("CreateBuffer token fail");
        return RESULT_BAD_COPY;
    }
    return RESULT_SUCCESS;
}

ResultCode CreateAuthResultInfo(const Buffer *tlv, AuthResultParam *authResultInfo)
{
    if (!IsBufferValid(tlv) || (authResultInfo == NULL)) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }

    Uint8Array msg = { tlv->buf, tlv->contentSize };
    Uint8Array peerUdid = { .data = authResultInfo->remoteUdid, .len = UDID_LEN };
    SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_CROSS_DEVICE, .peerUdid = peerUdid };
    Attribute *attribute = CreateAttributeFromExecutorMsg(msg, signParam);
    if (attribute == NULL) {
        LOG_ERROR("CreateAttributeFromExecutorMsg failed");
        return RESULT_GENERAL_ERROR;
    }

    ResultCode result = GetAuthResultInfoFromAttribute(attribute, authResultInfo);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAuthResultInfoFromAttribute failed");
    }
    FreeAttribute(&attribute);
    return result;
}

IAM_STATIC ResultCode SetExecutorInfoMsgToAttribute(ExecutorInfoHal *executorInfo, Attribute *attribute)
{
    ResultCode result = SetAttributeUint64(attribute, ATTR_EXECUTOR_INDEX, executorInfo->executorIndex);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint64 executorIndex failed");
        return RESULT_GENERAL_ERROR;
    }
    result = SetAttributeUint32(attribute, ATTR_TYPE, executorInfo->authType);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint32 authType failed");
        return RESULT_GENERAL_ERROR;
    }
    result = SetAttributeUint32(attribute, ATTR_EXECUTOR_ROLE, executorInfo->executorRole);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint32 executorRole failed");
        return RESULT_GENERAL_ERROR;
    }
    result = SetAttributeUint32(attribute, ATTR_ESL, executorInfo->esl);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint32 esl failed");
        return RESULT_GENERAL_ERROR;
    }
    Uint8Array publicKeyIn = { executorInfo->pubKey, PUBLIC_KEY_LEN };
    result = SetAttributeUint8Array(attribute, ATTR_PUBLIC_KEY, publicKeyIn);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint8Array for pubKey fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

ResultCode GetExecutorInfoMsg(ExecutorInfoHal *executorInfo, Uint8Array *retMsg)
{
    ResultCode result = RESULT_GENERAL_ERROR;
    Attribute *attribute = CreateEmptyAttribute();
    if (attribute == NULL) {
        LOG_ERROR("CreateEmptyAttribute failed");
        return RESULT_GENERAL_ERROR;
    }
    result = SetExecutorInfoMsgToAttribute(executorInfo, attribute);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set msg to attribute failed");
        goto FAIL;
    }
    result = GetAttributeSerializedMsg(attribute, retMsg);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeSerializedMsg fail");
        goto FAIL;
    }

FAIL:
    FreeAttribute(&attribute);
    return result;
}

Buffer *GetExecutorInfoTlv(Uint8Array attrsTlv, Uint8Array peerUdid)
{
    if (IS_ARRAY_NULL(attrsTlv) || IS_ARRAY_NULL(peerUdid)) {
        LOG_ERROR("attrsTlv is NULL");
        return NULL;
    }

    Buffer *retBuffer = NULL;
    Attribute *attribute = CreateEmptyAttribute();
    Uint8Array retInfo = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN };
    if (attribute == NULL || IS_ARRAY_NULL(retInfo)) {
        LOG_ERROR("attribute or retInfo is NULL");
        goto FAIL;
    }
    ResultCode result = SetAttributeUint8Array(attribute, ATTR_ATTRS, attrsTlv);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("SetAttributeUint8Array for attrs fail");
        goto FAIL;
    }

    SignParam signParam = { .needSignature = true, .keyType = KEY_TYPE_CROSS_DEVICE, .peerUdid = peerUdid };
    result = GetAttributeExecutorMsg(attribute, &retInfo, signParam);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeExecutorMsg failed");
        goto FAIL;
    }

    retBuffer = CreateBufferByData(retInfo.data, retInfo.len);
    if (!IsBufferValid(retBuffer)) {
        LOG_ERROR("generate result buffer failed");
        goto FAIL;
    }
    LOG_INFO("GetExecutorInfoTlv success");

FAIL:
    FreeAttribute(&attribute);
    Free(retInfo.data);
    return retBuffer;
}
