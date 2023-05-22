/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <arpa/inet.h>
#include "securec.h"

#include "buffer.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "executor_message.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

#define VARIABLE_LENGTH UINT32_MAX
#define SUCCESS RESULT_SUCCESS
#define GENERAL_ERROR RESULT_GENERAL_ERROR

typedef struct {
    AttributeKey key;
    uint32_t size;
} AttributeKeySizePair;

AttributeKeySizePair g_attributeKeySizePairs[] = {
    { AUTH_RESULT_CODE, sizeof(int32_t) },
    { AUTH_SIGNATURE, VARIABLE_LENGTH },
    { AUTH_IDENTIFY_MODE, sizeof(uint32_t) },
    { AUTH_TEMPLATE_ID, sizeof(uint64_t) },
    { AUTH_TEMPLATE_ID_LIST, VARIABLE_LENGTH },
    { AUTH_REMAIN_COUNT, sizeof(int32_t) },
    { AUTH_REMAIN_TIME, sizeof(uint32_t) },
    { AUTH_CALLER_NAME, VARIABLE_LENGTH },
    { AUTH_SCHEDULE_ID, sizeof(uint64_t) },
    { AUTH_SCHEDULE_VERSION, sizeof(uint32_t) },
    { AUTH_LOCK_OUT_TEMPLATE, VARIABLE_LENGTH },
    { AUTH_UNLOCK_TEMPLATE, VARIABLE_LENGTH },
    { AUTH_DATA, VARIABLE_LENGTH },
    { AUTH_SUB_TYPE, sizeof(uint64_t) },
    { AUTH_SCHEDULE_MODE, sizeof(int32_t) },
    { AUTH_PROPERTY_MODE, sizeof(uint32_t) },
    { AUTH_TYPE, sizeof(int32_t) },
    { AUTH_CREDENTIAL_ID, sizeof(uint64_t) },
    { AUTH_CONTROLLER, sizeof(uint64_t) },
    { AUTH_CALLER_UID, sizeof(uint64_t) },
    { AUTH_RESULT, VARIABLE_LENGTH },
    { AUTH_CAPABILITY_LEVEL, sizeof(uint32_t) },
    { AUTH_ALGORITHM_INFO, sizeof(uint64_t) },
    { AUTH_TIME_STAMP, sizeof(uint64_t) },
    { AUTH_ROOT_SECRET, VARIABLE_LENGTH },
    { AUTH_ROOT, VARIABLE_LENGTH },
};

#define ARRAY_LENGTH(array) (uint32_t)(sizeof(array) / sizeof((array)[0]))
#define ATTRIBUTE_LEN (ARRAY_LENGTH(g_attributeKeySizePairs))

typedef struct {
    Buffer *values[ATTRIBUTE_LEN];
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
    for (uint32_t i = 0; i < ATTRIBUTE_LEN; i++) {
        if (g_attributeKeySizePairs[i].key == key) {
            *index = i;
            return SUCCESS;
        }
    }

    return GENERAL_ERROR;
}

IAM_STATIC bool IsAttributeSizeValid(uint32_t actualSize, uint32_t attributeIndex)
{
    uint32_t expectedSize = g_attributeKeySizePairs[attributeIndex].size;
    if (expectedSize == VARIABLE_LENGTH) {
        if (actualSize == 0) {
            LOG_ERROR("check fail, attribute %u actual size is 0", attributeIndex);
            return false;
        }
        return true;
    }

    if (actualSize != expectedSize) {
        LOG_ERROR("check fail, attribute %u actual size %u expected size %u", attributeIndex, actualSize, expectedSize);
        return false;
    }

    return true;
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
    const Uint8Array readBuffer)
{
    uint32_t readIndex = 0;
    while (readIndex < msg.len) {
        uint32_t type;
        ResultCode readTypeResult = ReadUint32FromMsg(msg, &readIndex, &type);
        IF_TRUE_LOGE_AND_RETURN_VAL(readTypeResult != SUCCESS, GENERAL_ERROR);

        uint32_t length;
        ResultCode readLengthResult = ReadUint32FromMsg(msg, &readIndex, &length);
        IF_TRUE_LOGE_AND_RETURN_VAL(readLengthResult != SUCCESS, GENERAL_ERROR);
        IF_TRUE_LOGE_AND_RETURN_VAL(length > readBuffer.len, GENERAL_ERROR);

        Uint8Array readData = { readBuffer.data, length };
        ResultCode readDataResult = ReadDataFromMsg(msg, &readIndex, &readData);
        IF_TRUE_LOGE_AND_RETURN_VAL(readDataResult != SUCCESS, GENERAL_ERROR);

        ResultCode setAttrResult = SetAttributeUint8Array(attribute, type, readData);
        IF_TRUE_LOGE_AND_RETURN_VAL(setAttrResult != SUCCESS, GENERAL_ERROR);
    }

    return SUCCESS;
}

IAM_STATIC ResultCode ParseAttributeSerializedMsg(Attribute *attribute, const Uint8Array msg)
{
    Uint8Array readBuffer = { Malloc(MAX_EXECUTOR_MSG_LEN), MAX_EXECUTOR_MSG_LEN};
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(readBuffer), GENERAL_ERROR);

    ResultCode result = ParseAttributeSerializedMsgInner(attribute, msg, readBuffer);
    if (result != SUCCESS) {
        LOG_ERROR("ParseAttributeSerializedMsgInner fail");
    }
    Free(readBuffer.data);
    readBuffer.data = NULL;

    return result;
}

ResultCode GetAttributeSerializedMsg(const Attribute *attributePublic, Uint8Array *retMsg)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attributePublic == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(retMsg == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(*retMsg), GENERAL_ERROR);

    const AttributeImpl *attribute = (const AttributeImpl *)attributePublic;
    uint32_t writeIndex = 0;
    for (uint32_t i = 0; i < ATTRIBUTE_LEN; i++) {
        Buffer *currBuffer = attribute->values[i];
        if (!IsBufferValid(currBuffer)) {
            continue;
        }

        ResultCode writeTypeResult = WriteUInt32ToMsg(retMsg, &writeIndex, g_attributeKeySizePairs[i].key);
        IF_TRUE_LOGE_AND_RETURN_VAL(writeTypeResult != SUCCESS, GENERAL_ERROR);

        ResultCode writeLengthResult = WriteUInt32ToMsg(retMsg, &writeIndex, currBuffer->contentSize);
        IF_TRUE_LOGE_AND_RETURN_VAL(writeLengthResult != SUCCESS, GENERAL_ERROR);

        ResultCode writeDataResult =
            WriteDataToMsg(retMsg, &writeIndex, (Uint8Array){ currBuffer->buf, currBuffer->contentSize });
        IF_TRUE_LOGE_AND_RETURN_VAL(writeDataResult != SUCCESS, GENERAL_ERROR);
    }

    retMsg->len = writeIndex;
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

void FreeAttribute(Attribute **attribute)
{
    IF_TRUE_LOGE_AND_RETURN(attribute == NULL);
    IF_TRUE_LOGE_AND_RETURN(*attribute == NULL);
    AttributeImpl *impl = (AttributeImpl *)*attribute;
    for (uint32_t i = 0; i < ATTRIBUTE_LEN; i++) {
        DestoryBuffer(impl->values[i]);
        impl->values[i] = NULL;
    }

    Free(*attribute);
    *attribute = NULL;
}

ResultCode GetAttributeUint32(const Attribute *attribute, AttributeKey key, uint32_t *value)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(value == NULL, GENERAL_ERROR);

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
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, GENERAL_ERROR);

    uint32_t netOrderValue = Htonl32(value);
    ResultCode result =
        SetAttributeUint8Array(attribute, key, (Uint8Array) { (uint8_t *)&netOrderValue, sizeof(netOrderValue) });
    IF_TRUE_LOGE_AND_RETURN_VAL(result != SUCCESS, GENERAL_ERROR);

    return result;
}

ResultCode GetAttributeInt32(const Attribute *attribute, AttributeKey key, int32_t *retValue)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(retValue == NULL, GENERAL_ERROR);

    return GetAttributeUint32(attribute, key, (uint32_t *)retValue);
}

ResultCode SetAttributeInt32(Attribute *attribute, AttributeKey key, const int32_t value)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, GENERAL_ERROR);

    return SetAttributeUint32(attribute, key, (uint32_t)value);
}

ResultCode GetAttributeUint64(const Attribute *attribute, AttributeKey key, uint64_t *retValue)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(retValue == NULL, GENERAL_ERROR);

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
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, GENERAL_ERROR);

    uint64_t netOrderValue = Htonl64(value);
    ResultCode setAttrResult =
        SetAttributeUint8Array(attribute, key, (Uint8Array){ (uint8_t *)&netOrderValue, sizeof(netOrderValue) });
    IF_TRUE_LOGE_AND_RETURN_VAL(setAttrResult != SUCCESS, GENERAL_ERROR);

    return SUCCESS;
}

ResultCode GetAttributeUint8Array(const Attribute *attributePub, AttributeKey key, Uint8Array *retData)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attributePub == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(retData == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(*retData), GENERAL_ERROR);

    const AttributeImpl *attribute = (const AttributeImpl *)attributePub;

    uint32_t attributeIndex;
    ResultCode getAttrIndexResult = GetAttributeIndex(key, &attributeIndex);
    IF_TRUE_LOGE_AND_RETURN_VAL(getAttrIndexResult != SUCCESS, GENERAL_ERROR);
    bool isRetLenValid = IsAttributeSizeValid(retData->len, attributeIndex);
    IF_TRUE_LOGE_AND_RETURN_VAL(!isRetLenValid, GENERAL_ERROR);

    if (!IsBufferValid(attribute->values[attributeIndex])) {
        LOG_ERROR("Data is not set");
        return GENERAL_ERROR;
    }

    bool isValueLenValid = IsAttributeSizeValid(attribute->values[attributeIndex]->contentSize, attributeIndex);
    IF_TRUE_LOGE_AND_RETURN_VAL(!isValueLenValid, GENERAL_ERROR);

    if (memcpy_s(retData->data, retData->len, attribute->values[attributeIndex]->buf,
            attribute->values[attributeIndex]->contentSize) != EOK) {
        LOG_ERROR("memcpy_s failed");
        return GENERAL_ERROR;
    }

    retData->len = attribute->values[attributeIndex]->contentSize;
    return SUCCESS;
}

ResultCode SetAttributeUint8Array(Attribute *attributePub, AttributeKey key, const Uint8Array data)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attributePub == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(data), GENERAL_ERROR);

    AttributeImpl *attribute = (AttributeImpl *)attributePub;

    uint32_t attributeIndex;
    ResultCode getAttrIndexResult = GetAttributeIndex(key, &attributeIndex);
    IF_TRUE_LOGE_AND_RETURN_VAL(getAttrIndexResult != SUCCESS, GENERAL_ERROR);
    bool isAttributeVaild = IsAttributeSizeValid(data.len, attributeIndex);
    IF_TRUE_LOGE_AND_RETURN_VAL(!isAttributeVaild, GENERAL_ERROR);

    if (IsBufferValid(attribute->values[attributeIndex])) {
        DestoryBuffer(attribute->values[attributeIndex]);
    }

    attribute->values[attributeIndex] = CreateBufferByData(data.data, data.len);
    if (!IsBufferValid(attribute->values[attributeIndex])) {
        LOG_ERROR("create buffer fail");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

ResultCode GetAttributeUint64Array(const Attribute *attribute, AttributeKey key, Uint64Array *retData)
{
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(retData == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(*retData), GENERAL_ERROR);

    Uint8Array uint64ArrayData = { (uint8_t *)retData->data, retData->len * sizeof(uint64_t) };
    ResultCode setAttrResult = GetAttributeUint8Array(attribute, key, &uint64ArrayData);
    IF_TRUE_LOGE_AND_RETURN_VAL(setAttrResult != SUCCESS, GENERAL_ERROR);
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
    IF_TRUE_LOGE_AND_RETURN_VAL(attribute == NULL, GENERAL_ERROR);
    IF_TRUE_LOGE_AND_RETURN_VAL(IS_ARRAY_NULL(data), GENERAL_ERROR);

    uint32_t byteLen = data.len * sizeof(uint64_t);
    Uint64Array netOrderData = { Malloc(byteLen), data.len };
    IF_TRUE_LOGE_AND_RETURN_VAL(netOrderData.data == NULL, GENERAL_ERROR);

    ResultCode result = GENERAL_ERROR;
    do {
        if (memcpy_s(netOrderData.data, byteLen, data.data, byteLen) != EOK) {
            LOG_ERROR("memcpy_s fail");
            break;
        }
        Htonl64Array(&netOrderData);
        result = SetAttributeUint8Array(attribute, key,
            (Uint8Array) { (uint8_t *)netOrderData.data, netOrderData.len * sizeof(uint64_t) });
        if (result != SUCCESS) {
            LOG_ERROR("SetAttributeUint8Array fail");
            break;
        }
    } while (0);
    Free(netOrderData.data);
    netOrderData.data = NULL;

    return SUCCESS;
}
