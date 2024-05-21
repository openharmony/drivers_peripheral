/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "attribute.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

#define SUCCESS RESULT_SUCCESS
#define GENERAL_ERROR RESULT_GENERAL_ERROR
#define INVALID_PARAMETERS RESULT_BAD_PARAM

AttributeKey g_attributeKeyArray[] = {
    ATTR_RESULT_CODE,
    ATTR_SIGNATURE,
    ATTR_IDENTIFY_MODE,
    ATTR_TEMPLATE_ID,
    ATTR_TEMPLATE_ID_LIST,
    ATTR_REMAIN_ATTEMPTS,
    ATTR_LOCKOUT_DURATION,
    ATTR_SCHEDULE_ID,
    ATTR_DATA,
    ATTR_PIN_SUB_TYPE,
    ATTR_SCHEDULE_MODE,
    ATTR_PROPERTY_MODE,
    ATTR_TYPE,
    ATTR_CREDENTIAL_ID,
    ATTR_CONTROLLER,
    ATTR_CALLER_UID,
    ATTR_RESULT,
    ATTR_CAPABILITY_LEVEL,
    ATTR_ALGORITHM_INFO,
    ATTR_TIME_STAMP,
    ATTR_ROOT_SECRET,
    ATTR_ROOT,
    ATTR_ATTRS,
    ATTR_EXECUTOR_INDEX,
    ATTR_PUBLIC_KEY,
    ATTR_EXECUTOR_MATCHER,
    ATTR_LOCAL_UDID,
    ATTR_PEER_UDID,
    ATTR_LOCKOUT_DURATION,
    ATTR_REMAIN_ATTEMPTS,
    ATTR_USER_ID,
    ATTR_TOKEN,
    ATTR_EXECUTOR_ROLE,
    ATTR_ESL,
    ATTR_VERIFIER_UDID,
    ATTR_COLLECTOR_UDID,
    ATTR_CHALLENGE,
    ATTR_EXPIRED_SYS_TIME,
};

#define ARRAY_LENGTH(array) (uint32_t)(sizeof(array) / sizeof((array)[0]))
#define ATTRIBUTE_LEN (ARRAY_LENGTH(g_attributeKeyArray))

typedef struct {
    Uint8Array *values[ATTRIBUTE_LEN];
} AttributeImpl;

IAM_STATIC uint32_t Ntohl32(uint32_t in)
{
    return in;
}

IAM_STATIC uint32_t Htonl32(uint32_t in)
{
    return in;
}

IAM_STATIC uint64_t Ntohl64(uint64_t in)
{
    return in;
}

IAM_STATIC uint64_t Htonl64(uint64_t in)
{
    return in;
}

IAM_STATIC void Ntohl64Array(Uint64Array *array)
{
    for (uint32_t i = 0; i < array->len; i++) {
        array->data[i] = Ntohl64(array->data[i]);
    }
}

IAM_STATIC void Htonl64Array(Uint64Array *array)
{
    for (uint32_t i = 0; i < array->len; i++) {
        array->data[i] = Htonl64(array->data[i]);
    }
}

IAM_STATIC ResultCode GetAttributeIndex(AttributeKey key, uint32_t *index)
{
    for (uint32_t i = 0; i < ATTRIBUTE_LEN; ++i) {
        if (g_attributeKeyArray[i] == key) {
            *index = i;
            return SUCCESS;
        }
    }

    return GENERAL_ERROR;
}

IAM_STATIC ResultCode ReadDataFromMsg(const Uint8Array msg, uint32_t *readIndex, Uint8Array *retData)
{
    if (msg.len <= *readIndex) {
        LOG_ERROR("msg length is not enough");
        return GENERAL_ERROR;
    }

    if (msg.len - *readIndex < retData->len) {
        LOG_ERROR("remain data length is not enough");
        return GENERAL_ERROR;
    }

    if (memcpy_s(retData->data, retData->len, msg.data + *readIndex, retData->len) != EOK) {
        LOG_ERROR("memcpy_s fail");
        return GENERAL_ERROR;
    }

    *readIndex += retData->len;
    return SUCCESS;
}

IAM_STATIC ResultCode ReadUint32FromMsg(const Uint8Array msg, uint32_t *readIndex, uint32_t *retValue)
{
    uint32_t netOrderValue;
    Uint8Array uint8Data = { (uint8_t *)&netOrderValue, sizeof(netOrderValue) };
    ResultCode result = ReadDataFromMsg(msg, readIndex, &uint8Data);
    if (result != SUCCESS) {
        LOG_ERROR("read data fail");
        return GENERAL_ERROR;
    }

    *retValue = Ntohl32(netOrderValue);
    return SUCCESS;
}

IAM_STATIC ResultCode WriteDataToMsg(Uint8Array *msg, uint32_t *writeIndex, const Uint8Array data)
{
    if (msg->len <= *writeIndex) {
        LOG_ERROR("msg length is not enough");
        return GENERAL_ERROR;
    }

    if (msg->len - *writeIndex < data.len) {
        LOG_ERROR("remain data size is not enough");
        return GENERAL_ERROR;
    }

    if (memcpy_s(msg->data + *writeIndex, msg->len - *writeIndex, data.data, data.len) != EOK) {
        LOG_ERROR("memcpy_s fail");
        return GENERAL_ERROR;
    }

    *writeIndex += data.len;
    return SUCCESS;
}

IAM_STATIC ResultCode WriteUInt32ToMsg(Uint8Array *msg, uint32_t *writeIndex, uint32_t value)
{
    uint32_t netOrderValue = Htonl32(value);
    ResultCode result =
        WriteDataToMsg(msg, writeIndex, (Uint8Array){ (uint8_t *)&netOrderValue, sizeof(netOrderValue) });
    if (result != SUCCESS) {
        LOG_ERROR("write data fail");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

IAM_STATIC ResultCode ParseAttributeSerializedMsgInner(Attribute *attribute, const Uint8Array msg,
    const Uint8Array *readBuffer)
{
    uint32_t readIndex = 0;
    while (readIndex < msg.len) {
        uint32_t type;
        ResultCode readTypeResult = ReadUint32FromMsg(msg, &readIndex, &type);
        IF_TRUE_LOGE_AND_RETURN_VAL(readTypeResult != SUCCESS, GENERAL_ERROR);

        uint32_t length;
        ResultCode readLengthResult = ReadUint32FromMsg(msg, &readIndex, &length);
        IF_TRUE_LOGE_AND_RETURN_VAL(readLengthResult != SUCCESS, GENERAL_ERROR);
        IF_TRUE_LOGE_AND_RETURN_VAL(length > readBuffer->len, GENERAL_ERROR);

        Uint8Array readData = { readBuffer->data, length };
        if (length > 0) {
            ResultCode readDataResult = ReadDataFromMsg(msg, &readIndex, &readData);
            IF_TRUE_LOGE_AND_RETURN_VAL(readDataResult != SUCCESS, GENERAL_ERROR);
        }

        ResultCode setAttrResult = SetAttributeUint8Array(attribute, type, readData);
        IF_TRUE_LOGE_AND_RETURN_VAL(setAttrResult != SUCCESS, GENERAL_ERROR);
    }

    return SUCCESS;
}

IAM_STATIC ResultCode ParseAttributeSerializedMsg(Attribute *attribute, const Uint8Array msg)
{
    Uint8Array *readBuffer = CreateUint8ArrayBySize(MAX_EXECUTOR_MSG_LEN);
    IF_TRUE_LOGE_AND_RETURN_VAL(readBuffer == NULL, GENERAL_ERROR);

    ResultCode result = ParseAttributeSerializedMsgInner(attribute, msg, readBuffer);
    if (result != SUCCESS) {
        LOG_ERROR("ParseAttributeSerializedMsgInner fail");
    }
    DestroyUint8Array(&readBuffer);

    return result;
}

ResultCode ParseMultiDataSerializedMsg(const Uint8Array msg, Uint8Array *subMsgData, int *subMsgSize)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(subMsgSize == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(subMsgData == NULL, GENERAL_ERROR);

    uint32_t readIndex = 0;
    uint32_t subMsgIndex = 0;
    while (readIndex < msg.len) {
        uint32_t length;
        ResultCode readLengthResult = ReadUint32FromMsg(msg, &readIndex, &length);
        IF_TRUE_LOGE_AND_RETURN_VAL(readLengthResult != SUCCESS, GENERAL_ERROR);

        if (length > 0) {
            IF_TRUE_LOGE_AND_RETURN_VAL(subMsgIndex >= *subMsgSize, GENERAL_ERROR);
            // subMsgData is freed in outer function
            subMsgData[subMsgIndex] = (Uint8Array){ Malloc(length), length };
            IF_TRUE_LOGE_AND_RETURN_VAL(subMsgData[subMsgIndex].data == NULL, GENERAL_ERROR);
            ResultCode readDataResult = ReadDataFromMsg(msg, &readIndex, &subMsgData[subMsgIndex]);
            IF_TRUE_LOGE_AND_RETURN_VAL(readDataResult != SUCCESS, GENERAL_ERROR);
            subMsgIndex++;
        }
    }

    *subMsgSize = subMsgIndex;
    return SUCCESS;
}

Attribute *CreateEmptyAttribute(void)
{
    AttributeImpl *attribute = Malloc(sizeof(AttributeImpl));
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, NULL);
    (void)memset_s(attribute, sizeof(AttributeImpl), 0, sizeof(AttributeImpl));

    return attribute;
}

Attribute *CreateAttributeFromSerializedMsg(const Uint8Array msg)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(msg), NULL);

    Attribute *attribute = CreateEmptyAttribute();
    if (attribute == NULL) {
        LOG_ERROR("CreateEmptyAttribute failed");
        return NULL;
    }

    ResultCode result = ParseAttributeSerializedMsg(attribute, msg);
    if (result != SUCCESS) {
        LOG_ERROR("ParseAttributeSerializedMsg failed");
        FreeAttribute((Attribute **)&attribute);
        return NULL;
    }

    return attribute;
}

ResultCode GetAttributeSerializedMsg(const Attribute *attributePublic, Uint8Array *retMsg)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attributePublic == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(retMsg == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(*retMsg), INVALID_PARAMETERS);

    const AttributeImpl *attribute = (const AttributeImpl *)attributePublic;
    uint32_t writeIndex = 0;
    for (uint32_t i = 0; i < ATTRIBUTE_LEN; i++) {
        Uint8Array *array = attribute->values[i];
        if (array == NULL) {
            continue;
        }

        ResultCode writeTypeResult = WriteUInt32ToMsg(retMsg, &writeIndex, g_attributeKeyArray[i]);
        IF_TRUE_LOGE_AND_RETURN_VAL(writeTypeResult != SUCCESS, GENERAL_ERROR);

        ResultCode writeLengthResult = WriteUInt32ToMsg(retMsg, &writeIndex, array->len);
        IF_TRUE_LOGE_AND_RETURN_VAL(writeLengthResult != SUCCESS, GENERAL_ERROR);

        if (array->len == 0) {
            continue;
        }
        ResultCode writeDataResult =
            WriteDataToMsg(retMsg, &writeIndex, *array);
        IF_TRUE_LOGE_AND_RETURN_VAL(writeDataResult != SUCCESS, GENERAL_ERROR);
    }

    retMsg->len = writeIndex;
    return SUCCESS;
}

void FreeAttribute(Attribute **attribute)
{
    IF_TRUE_LOGE_AND_RETURN(attribute == NULL);
    IF_TRUE_LOGE_AND_RETURN(*attribute == NULL);
    AttributeImpl *impl = (AttributeImpl *)*attribute;
    for (uint32_t i = 0; i < ATTRIBUTE_LEN; ++i) {
        DestroyUint8Array(&impl->values[i]);
    }

    IAM_FREE_AND_SET_NULL(*attribute);
}

ResultCode GetAttributeUint32(const Attribute *attribute, AttributeKey key, uint32_t *value)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(value == NULL, INVALID_PARAMETERS);

    uint32_t netOrderValue;
    Uint8Array uint32Data = { (uint8_t *)&netOrderValue, sizeof(netOrderValue) };
    ResultCode getAttrResult = GetAttributeUint8Array(attribute, key, &uint32Data);
    IF_TRUE_LOGE_AND_RETURN_VAL(getAttrResult != SUCCESS, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(uint32Data.len != sizeof(netOrderValue), GENERAL_ERROR);

    *value = Ntohl32(netOrderValue);
    return SUCCESS;
}

ResultCode SetAttributeUint32(Attribute *attribute, AttributeKey key, const uint32_t value)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, INVALID_PARAMETERS);

    uint32_t netOrderValue = Htonl32(value);
    ResultCode result =
        SetAttributeUint8Array(attribute, key, (Uint8Array) { (uint8_t *)&netOrderValue, sizeof(netOrderValue) });
    IF_TRUE_LOGE_AND_RETURN_VAL(result != SUCCESS, GENERAL_ERROR);

    return result;
}

ResultCode GetAttributeInt32(const Attribute *attribute, AttributeKey key, int32_t *retValue)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(retValue == NULL, INVALID_PARAMETERS);

    return GetAttributeUint32(attribute, key, (uint32_t *)retValue);
}

ResultCode SetAttributeInt32(Attribute *attribute, AttributeKey key, const int32_t value)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, INVALID_PARAMETERS);

    return SetAttributeUint32(attribute, key, (uint32_t)value);
}

ResultCode GetAttributeUint64(const Attribute *attribute, AttributeKey key, uint64_t *retValue)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(retValue == NULL, INVALID_PARAMETERS);

    uint64_t netOrderValue;
    Uint8Array uint64Data = { (uint8_t *)&netOrderValue, sizeof(netOrderValue) };
    ResultCode getAttrResult = GetAttributeUint8Array(attribute, key, &uint64Data);
    IF_TRUE_LOGE_AND_RETURN_VAL(getAttrResult != SUCCESS, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(uint64Data.len != sizeof(netOrderValue), GENERAL_ERROR);

    *retValue = Ntohl64(netOrderValue);
    return SUCCESS;
}

ResultCode SetAttributeUint64(Attribute *attribute, AttributeKey key, const uint64_t value)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, INVALID_PARAMETERS);

    uint64_t netOrderValue = Htonl64(value);
    ResultCode setAttrResult =
        SetAttributeUint8Array(attribute, key, (Uint8Array){ (uint8_t *)&netOrderValue, sizeof(netOrderValue) });
    IF_TRUE_LOGE_AND_RETURN_VAL(setAttrResult != SUCCESS, GENERAL_ERROR);

    return SUCCESS;
}

ResultCode GetAttributeUint8Array(const Attribute *attributePub, AttributeKey key, Uint8Array *retData)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attributePub == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(retData == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(*retData), INVALID_PARAMETERS);

    const AttributeImpl *attribute = (const AttributeImpl *)attributePub;

    uint32_t attributeIndex;
    ResultCode getAttrIndexResult = GetAttributeIndex(key, &attributeIndex);
    IF_TRUE_LOGE_AND_RETURN_VAL(getAttrIndexResult != SUCCESS, GENERAL_ERROR);

    if (attribute->values[attributeIndex] == NULL) {
        LOG_ERROR("data is not set");
        return GENERAL_ERROR;
    }

    if (attribute->values[attributeIndex]->data != NULL && attribute->values[attributeIndex]->len != 0) {
        errno_t memcpyRet = memcpy_s(retData->data, retData->len, attribute->values[attributeIndex]->data,
            attribute->values[attributeIndex]->len);
        IF_TRUE_LOGE_AND_RETURN_VAL(memcpyRet != EOK, GENERAL_ERROR);
    } else {
        LOG_INFO("the current data is an empty array");
    }
    retData->len = attribute->values[attributeIndex]->len;

    return SUCCESS;
}

ResultCode SetAttributeUint8Array(Attribute *attributePub, AttributeKey key, const Uint8Array data)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attributePub == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(!IS_ARRAY_VALID(data), INVALID_PARAMETERS);

    AttributeImpl *attribute = (AttributeImpl *)attributePub;

    uint32_t attributeIndex;
    ResultCode getAttrIndexResult = GetAttributeIndex(key, &attributeIndex);
    IF_TRUE_LOGE_AND_RETURN_VAL(getAttrIndexResult != SUCCESS, GENERAL_ERROR);

    DestroyUint8Array(&attribute->values[attributeIndex]);
    attribute->values[attributeIndex] = CreateUint8ArrayByData(data.data, data.len);
    if (attribute->values[attributeIndex] == NULL) {
        LOG_ERROR("CreateUint8ArrayByData fail");
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

ResultCode GetAttributeUint64Array(const Attribute *attribute, AttributeKey key, Uint64Array *retData)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(retData == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(*retData), INVALID_PARAMETERS);

    Uint8Array uint64ArrayData = { (uint8_t *)retData->data, retData->len * sizeof(uint64_t) };
    ResultCode getAttrResult = GetAttributeUint8Array(attribute, key, &uint64ArrayData);
    IF_TRUE_LOGE_AND_RETURN_VAL(getAttrResult != SUCCESS, GENERAL_ERROR);
    if (uint64ArrayData.len % sizeof(uint64_t) != 0) {
        LOG_ERROR("uint8 length %u is incorrect", uint64ArrayData.len);
        return GENERAL_ERROR;
    }
    Ntohl64Array(retData);

    retData->len = uint64ArrayData.len / sizeof(uint64_t);
    return SUCCESS;
}

ResultCode SetAttributeUint64Array(Attribute *attribute, AttributeKey key, const Uint64Array data)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(!IS_ARRAY_VALID(data), INVALID_PARAMETERS);

    Uint64Array *netOrderData = CreateUint64ArrayByData(data.data, data.len);
    IF_TRUE_LOGE_AND_RETURN_VAL(netOrderData == NULL, GENERAL_ERROR);

    ResultCode result = GENERAL_ERROR;
    do {
        Htonl64Array(netOrderData);
        if (netOrderData->len > UINT32_MAX / sizeof(uint64_t)) {
            LOG_ERROR("netOrderData->len is invalid");
            break;
        }
        result = SetAttributeUint8Array(attribute, key,
            (Uint8Array) { (uint8_t *)netOrderData->data, netOrderData->len * sizeof(uint64_t) });
        if (result != SUCCESS) {
            LOG_ERROR("SetAttributeUint8Array fail");
            break;
        }
    } while (0);

    DestroyUint64Array(&netOrderData);
    return result;
}

ResultCode GetMultiDataSerializedMsg(Uint8Array *sourceArrayMsg, uint32_t size, Uint8Array *retMsg)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(sourceArrayMsg == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(retMsg == NULL, INVALID_PARAMETERS);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(*retMsg), INVALID_PARAMETERS);

    uint32_t writeIndex = 0;
    for (uint32_t i = 0; i < size; i++) {
        IF_TRUE_LOGE_AND_RETURN_VAL(sourceArrayMsg[i].data == NULL, GENERAL_ERROR);
        Uint8Array sourceMsg = sourceArrayMsg[i];
        if (sourceMsg.len == 0) {
            continue;
        }
        ResultCode writeLengthResult = WriteUInt32ToMsg(retMsg, &writeIndex, sourceMsg.len);
        IF_TRUE_LOGE_AND_RETURN_VAL(writeLengthResult != SUCCESS, GENERAL_ERROR);

        ResultCode writeDataResult = WriteDataToMsg(retMsg, &writeIndex, sourceMsg);
        IF_TRUE_LOGE_AND_RETURN_VAL(writeDataResult != SUCCESS, GENERAL_ERROR);
    }
    retMsg->len = writeIndex;
    return SUCCESS;
}
