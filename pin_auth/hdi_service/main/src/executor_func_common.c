/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "executor_func_common.h"

#include <inttypes.h>

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "attribute.h"

int32_t SetBufferToAttribute(Attribute *attribute, AttributeKey key, Buffer *buf)
{
    if ((attribute == NULL) || !IsBufferValid(buf)) {
        LOG_ERROR("SetBufferToAttribute bad param!");
        return RESULT_BAD_PARAM;
    }
    Uint8Array uint8Array = {
        .data = buf->buf,
        .len = buf->contentSize,
    };
    return SetAttributeUint8Array(attribute, key, uint8Array);
}

static Buffer *GetBufferFromAttributeBase(const Attribute *attribute, AttributeKey key, bool checkSize, uint32_t size)
{
    if (attribute == NULL) {
        LOG_ERROR("GetBufferFromAttributeBase bad param!");
        return NULL;
    }
    uint32_t len = 0;
    int32_t result = GetAttributeLength(attribute, key, &len);
    if ((result != RESULT_SUCCESS) || (checkSize && (len != size))) {
        LOG_ERROR("get attribute:%{public}d length:%{public}u fail!", key, len);
        return NULL;
    }

    Buffer *buffer = CreateBufferBySize(len);
    IF_TRUE_LOGE_AND_RETURN_VAL(buffer == NULL, NULL);

    Uint8Array uint8Array = {
        .data = buffer->buf,
        .len = buffer->maxSize,
    };
    result = GetAttributeUint8Array(attribute, key, &uint8Array);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get attrbute %{public}d fail!", key);
        DestroyBuffer(buffer);
        return NULL;
    }
    buffer->contentSize = uint8Array.len;
    return buffer;
}

Buffer *GetBufferFromAttribute(const Attribute *attribute, AttributeKey key, uint32_t size)
{
    return GetBufferFromAttributeBase(attribute, key, true, size);
}

Attribute *GetAttributeDataBase(uint64_t scheduleId, RemotePinMsgId msgId)
{
    Attribute *attribute = CreateEmptyAttribute();
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, NULL);

    int32_t result = SetAttributeUint64(attribute, ATTR_SCHEDULE_ID, scheduleId);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set schedule id fail!");
        FreeAttribute(&attribute);
        return NULL;
    }

    if (msgId != REMOTE_PIN_MSG_NONE) {
        result = SetAttributeUint64(attribute, ATTR_TIME_STAMP, GetRtcTime());
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("set time stamp fail!");
            FreeAttribute(&attribute);
            return NULL;
        }

        result = SetAttributeUint32(attribute, PIN_ATTR_MSG_ID, msgId);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("set msg id fail!");
            FreeAttribute(&attribute);
            return NULL;
        }
    }

    return attribute;
}

static int32_t GetRootMsg(const Attribute *data, const KeyPair *keyPair, Uint8Array *rootMsg)
{
    Uint8Array dataMsg = {
        .data = rootMsg->data,
        .len = rootMsg->len
    };
    int32_t result = GetAttributeSerializedMsg(data, &dataMsg);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetAttributeSerializedMsg fail!");
        return result;
    }

    Buffer dataBuf = GetTmpBuffer(dataMsg.data, dataMsg.len, dataMsg.len);
    Buffer *sign = NULL;
    Attribute *attribute = NULL;
    result = Ed25519Sign(keyPair, &dataBuf, &sign);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("Ed25519Sign fail!");
        goto EXIT;
    }
    attribute = CreateEmptyAttribute();
    if (attribute == NULL) {
        LOG_ERROR("get root fail!");
        result = RESULT_GENERAL_ERROR;
        goto EXIT;
    }

    result = SetBufferToAttribute(attribute, ATTR_DATA, &dataBuf);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set data fail!");
        goto EXIT;
    }
    result = SetBufferToAttribute(attribute, ATTR_SIGNATURE, sign);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set sign fail!");
        goto EXIT;
    }

    result = GetAttributeSerializedMsg(attribute, rootMsg);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get serialized root fail!");
        goto EXIT;
    }

EXIT:
    DestroyBuffer(sign);
    FreeAttribute(&attribute);
    return result;
}

int32_t FormatTlvMsg(const Attribute *data, const KeyPair *keyPair, uint8_t *msg, uint32_t *msgSize)
{
    if ((data == NULL) || !IsEd25519KeyPairValid(keyPair) || (msg == NULL) || (msgSize == NULL)) {
        LOG_ERROR("FormatTlvMsg check param fail!");
        return RESULT_BAD_PARAM;
    }
    Uint8Array uint8Array = {
        .data = msg,
        .len = *msgSize,
    };
    int32_t result = GetRootMsg(data, keyPair, &uint8Array);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("GetRootMsg fail!");
        return result;
    }
    Attribute *attribute = CreateEmptyAttribute();
    if (attribute == NULL) {
        LOG_ERROR("create root attribute fail!");
        result = RESULT_GENERAL_ERROR;
        goto EXIT;
    }
    result = SetAttributeUint8Array(attribute, ATTR_ROOT, uint8Array);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("set root fail!");
        goto EXIT;
    }

    uint8Array.data = msg;
    uint8Array.len = *msgSize;
    result = GetAttributeSerializedMsg(attribute, &uint8Array);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get serialized tlv fail!");
        goto EXIT;
    }
    *msgSize = uint8Array.len;

EXIT:
    FreeAttribute(&attribute);
    return result;
}

static Attribute *GetRootAttributeFromTlv(const uint8_t *msg, uint32_t msgSize)
{
    Uint8Array uint8Array = {
        .data = (uint8_t *)msg,
        .len = msgSize,
    };
    Attribute *attributeTlv = CreateAttributeFromSerializedMsg(uint8Array);
    if (attributeTlv == NULL) {
        LOG_ERROR("create root tlv fail!");
        return NULL;
    }
    Buffer *root = GetBufferFromAttributeBase(attributeTlv, ATTR_ROOT, false, 0);
    FreeAttribute(&attributeTlv);
    if (root == NULL) {
        LOG_ERROR("get root buffer fail!");
        return NULL;
    }

    uint8Array.data = root->buf;
    uint8Array.len = root->contentSize;
    Attribute *attributeRoot = CreateAttributeFromSerializedMsg(uint8Array);
    DestroyBuffer(root);
    return attributeRoot;
}

static bool CheckScheduleIdOfAttribute(uint64_t scheduleId, const Attribute *data)
{
    uint64_t dataScheduleId = 0;
    int32_t result = GetAttributeUint64(data, ATTR_SCHEDULE_ID, &dataScheduleId);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get schedule id fail");
        return false;
    }
    if (dataScheduleId != scheduleId) {
        LOG_ERROR("data schedule:%{public}x not match current schedule:%{public}x",
            (uint16_t)dataScheduleId, (uint16_t)scheduleId);
        return false;
    }
    return true;
}

int32_t VerifyAndGetDataAttribute(
    uint64_t scheduleId, Attribute **data, const Buffer *pubKey, const uint8_t *msg, uint32_t msgSize)
{
    if ((data == NULL) || !IsBufferValid(pubKey) || (msg == NULL)) {
        LOG_ERROR("VerifyAndGetDataAttribute check param fail!");
        return RESULT_BAD_PARAM;
    }

    Attribute *attributeRoot = GetRootAttributeFromTlv(msg, msgSize);
    if (attributeRoot == NULL) {
        LOG_ERROR("get root fail!");
        return RESULT_GENERAL_ERROR;
    }

    Buffer *dataBuf = GetBufferFromAttributeBase(attributeRoot, ATTR_DATA, false, 0);
    Buffer *signBuf = GetBufferFromAttributeBase(attributeRoot, ATTR_SIGNATURE, false, 0);
    FreeAttribute(&attributeRoot);
    if ((dataBuf == NULL) || (signBuf == NULL)) {
        LOG_ERROR("get data or sign buffer fail!");
        DestroyBuffer(dataBuf);
        DestroyBuffer(signBuf);
        return RESULT_GENERAL_ERROR;
    }

    int32_t result = Ed25519Verify(pubKey, dataBuf, signBuf);
    DestroyBuffer(signBuf);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("verify data signature fail!");
        DestroyBuffer(dataBuf);
        return RESULT_GENERAL_ERROR;
    }

    Uint8Array uint8Array = {
        .data = dataBuf->buf,
        .len = dataBuf->contentSize,
    };
    *data = CreateAttributeFromSerializedMsg(uint8Array);
    DestroyBuffer(dataBuf);
    if ((*data) == NULL) {
        LOG_ERROR("create data fail!");
        return RESULT_GENERAL_ERROR;
    }

    if (!CheckScheduleIdOfAttribute(scheduleId, *data)) {
        LOG_ERROR("CheckScheduleIdOfAttribute fail!");
        FreeAttribute(data);
        *data = NULL;
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

int32_t CheckAttributeDataBase(const Attribute *data, uint64_t scheduleId, RemotePinMsgId msgId, uint64_t *timeStamp)
{
    if ((data == NULL) || (timeStamp == NULL)) {
        LOG_ERROR("CheckAttributeDataBase check param fail!");
        return RESULT_BAD_PARAM;
    }

    if (!CheckScheduleIdOfAttribute(scheduleId, data)) {
        LOG_ERROR("CheckScheduleIdOfAttribute fail!");
        return RESULT_BAD_MATCH;
    }

    uint32_t dataMsgId = 0;
    int32_t result = GetAttributeUint32(data, PIN_ATTR_MSG_ID, &dataMsgId);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get msg id fail");
        return result;
    }
    if (dataMsgId != msgId) {
        LOG_ERROR("data msgId:%{public}u not match current msgId:%{public}u", dataMsgId, msgId);
        return RESULT_BAD_MATCH;
    }

    uint64_t dataTimeStamp = 0;
    result = GetAttributeUint64(data, ATTR_TIME_STAMP, &dataTimeStamp);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get time stamp fail");
        return result;
    }
    if (dataTimeStamp <= (*timeStamp)) {
        LOG_ERROR("data time:%{public}" PRIu64 " not match current time:%{public}" PRIu64,
            dataTimeStamp, (*timeStamp));
        return RESULT_BAD_MATCH;
    }
    (*timeStamp) = dataTimeStamp;

    return RESULT_SUCCESS;
}

static ResultCode GetSubTypeAndFreezeTime(
    uint64_t *subType, uint64_t templateId, uint32_t *freezeTime, uint32_t *count)
{
    ResultCode ret = GetSubType(templateId, subType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetSubType fail.");
        return ret;
    }
    uint64_t startFreezeTime = INIT_START_FREEZE_TIMES;
    ret = GetAntiBruteInfo(templateId, count, &startFreezeTime);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetAntiBruteInfo fail.");
        return ret;
    }

    ret = ComputeFreezeTime(templateId, freezeTime, *count, startFreezeTime);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ComputeFreezeTime fail.");
        return ret;
    }
    return RESULT_SUCCESS;
}

int32_t DoQueryPinInfo(uint64_t templateId, PinCredentialInfos *pinCredentialInfo)
{
    if (pinCredentialInfo == NULL || templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("check DoQueryPin param fail!");
        return RESULT_BAD_PARAM;
    }
    uint32_t authErrorCount = INIT_AUTH_ERROR_COUNT;
    ResultCode ret = GetSubTypeAndFreezeTime(&(pinCredentialInfo->subType), templateId,
        &(pinCredentialInfo->freezeTime), &authErrorCount);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetSubTypeAndFreezeTime fail.");
        return ret;
    }
    ret = GetCredentialLength(templateId, &(pinCredentialInfo->credentialLength));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetCredentialLength fail.");
        return ret;
    }
    pinCredentialInfo->nextFailLockoutDuration = GetNextFailLockoutDuration(authErrorCount);
    if (pinCredentialInfo->freezeTime > 0) {
        pinCredentialInfo->remainTimes = 0;
    } else {
        ret = GetRemainTimes(templateId, &(pinCredentialInfo->remainTimes), authErrorCount);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("GetRemainTimes fail.");
            return ret;
        }
    }
    return ret;
}

bool SetResultDataInfo(Attribute *attribute, int32_t resultCode, uint64_t templateId, Buffer *rootSecret)
{
    if ((attribute == NULL) || ((rootSecret != NULL) && !IsBufferValid(rootSecret))) {
        LOG_ERROR("SetResultDataInfo check param fail");
        return false;
    }

    PinCredentialInfos pinCredentialInfo;
    int32_t queryPinResult = DoQueryPinInfo(templateId, &pinCredentialInfo);
    IF_TRUE_LOGE_AND_RETURN_VAL(queryPinResult != RESULT_SUCCESS, false);

    int32_t setResultCodeResult = SetAttributeInt32(attribute, ATTR_RESULT_CODE, resultCode);
    IF_TRUE_LOGE_AND_RETURN_VAL(setResultCodeResult != RESULT_SUCCESS, false);

    int32_t setTemplateIdResult = SetAttributeUint64(attribute, ATTR_TEMPLATE_ID, templateId);
    IF_TRUE_LOGE_AND_RETURN_VAL(setTemplateIdResult != RESULT_SUCCESS, false);

    int32_t setSubTypeResult = SetAttributeUint64(attribute, ATTR_PIN_SUB_TYPE, pinCredentialInfo.subType);
    IF_TRUE_LOGE_AND_RETURN_VAL(setSubTypeResult != RESULT_SUCCESS, false);

    if (pinCredentialInfo.remainTimes > INT32_MAX) {
        pinCredentialInfo.remainTimes = 0;
    }
    int32_t setRemainAttempts = SetAttributeInt32(
        attribute, ATTR_REMAIN_ATTEMPTS, (int32_t)pinCredentialInfo.remainTimes);
    IF_TRUE_LOGE_AND_RETURN_VAL(setRemainAttempts != RESULT_SUCCESS, false);

    if (pinCredentialInfo.freezeTime > INT32_MAX) {
        pinCredentialInfo.freezeTime = INT32_MAX;
    }
    int32_t setLockoutDuration = SetAttributeInt32(
        attribute, ATTR_LOCKOUT_DURATION, (int32_t)pinCredentialInfo.freezeTime);
    IF_TRUE_LOGE_AND_RETURN_VAL(setLockoutDuration != RESULT_SUCCESS, false);

    int32_t setAcl = SetAttributeUint32(attribute, ATTR_ACL, PIN_CAPABILITY_LEVEL);
    IF_TRUE_LOGE_AND_RETURN_VAL(setAcl != RESULT_SUCCESS, false);

    if (rootSecret != NULL && resultCode == SUCCESS) {
        int32_t setRootSecret = SetBufferToAttribute(attribute, ATTR_ROOT_SECRET, rootSecret);
        IF_TRUE_LOGE_AND_RETURN_VAL(setRootSecret != RESULT_SUCCESS, false);
    }

    return true;
}

int32_t PinResultToFwkResult(int32_t pinResult)
{
    switch (pinResult) {
        case RESULT_SUCCESS:
            return SUCCESS;
        case RESULT_BAD_PARAM:
            return INVALID_PARAMETERS;
        case RESULT_COMPARE_FAIL:
            return FAIL;
        case RESULT_BUSY:
            return BUSY;
        case RESULT_PIN_FREEZE:
            return LOCKED;
        default:
            return GENERAL_ERROR;
    }
}
