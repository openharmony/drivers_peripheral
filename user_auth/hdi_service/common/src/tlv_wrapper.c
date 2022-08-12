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

#include "tlv_wrapper.h"

#include <string.h>

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"

static int32_t PutTlvObject(TlvListNode *head, int32_t type, uint32_t length, const void *value)
{
    if ((head == NULL) || (value == NULL) || (length > MAX_BUFFER_SIZE)) {
        return PARAM_ERR;
    }

    TlvType *tlv = (TlvType *)Malloc(sizeof(TlvType));
    if (tlv == NULL) {
        return MALLOC_FAIL;
    }

    tlv->type = type;
    tlv->length = length;
    tlv->value = NULL;
    if (length > 0) {
        tlv->value = (uint8_t *)Malloc(length);
        if (tlv->value == NULL) {
            Free(tlv);
            tlv = NULL;
            return MALLOC_FAIL;
        }

        if (memcpy_s(tlv->value, length, value, length) != EOK) {
            Free(tlv->value);
            tlv->value = NULL;
            Free(tlv);
            tlv = NULL;
            return MEMCPY_ERR;
        }
    }

    TlvObject object;
    object.value = tlv;
    int32_t ret = AddTlvNode(head, &object);
    if (ret != OPERA_SUCC) {
        if (object.value != NULL) {
            Free(object.value->value);
            object.value->value = NULL;
            Free(object.value);
            object.value = NULL;
        }
    }
    return ret;
}

int32_t ParseGetHeadTag(const TlvListNode *node, int32_t *tag)
{
    if (node == NULL || tag == NULL) {
        return PARAM_ERR;
    }
    TlvType *tlv = node->data.value;
    if (tlv == NULL) {
        return TAG_NOT_EXIST;
    }
    *tag = tlv->type;
    return OPERA_SUCC;
}

int32_t ParseTlvWrapper(const uint8_t *buffer, uint32_t bufferSize, TlvListNode *head)
{
    if (buffer == NULL || bufferSize == 0 || bufferSize > MAX_BUFFER_SIZE || head == NULL) {
        return PARAM_ERR;
    }

    uint32_t offset = 0;
    while (offset < bufferSize) {
        if ((bufferSize - offset) < TLV_HEADER_LEN) {
            LOG_ERROR("bufferSize = %{public}u, offset = %{public}u", bufferSize, offset);
            return OPERA_FAIL;
        }
        int32_t type = (int32_t)Ntohl(*(int32_t *)(buffer + offset));
        offset += sizeof(int32_t);
        uint32_t length = Ntohl(*(int32_t *)(buffer + offset));
        offset += sizeof(int32_t);
        if (length > (bufferSize - offset)) {
            LOG_ERROR("bufferSize = %{public}u, offset = %{public}u, length = %{public}u", bufferSize, offset, length);
            return OPERA_FAIL;
        }
        int32_t ret = PutTlvObject(head, type, length, buffer + offset);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        offset += length;
    }

    return OPERA_SUCC;
}

static uint8_t *GetTlvValue(TlvListNode *node, int32_t msgType, uint32_t *len)
{
    if ((node == NULL) || (len == NULL)) {
        LOG_ERROR("GetTlvValue input invalid");
        return NULL;
    }
    TlvType *tlv = node->data.value;
    if (tlv == NULL) {
        LOG_ERROR("GetTlvValue tlv is NULL");
        return NULL;
    }
    int32_t type = tlv->type;
    *len = tlv->length;
    if ((type != msgType) || (*len == 0)) {
        LOG_ERROR("GetTlvValue return type = %d, len  = %u, msgType = %d", type, *len, msgType);
        return NULL;
    }

    return tlv->value;
}

int32_t ParseUint64Para(TlvListNode *node, int32_t msgType, uint64_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseUint64Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(uint64_t))) {
        LOG_ERROR("ParseUint64Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = Ntohll(*(uint64_t *)val);
    return OPERA_SUCC;
}

int32_t ParseInt64Para(TlvListNode *node, int32_t msgType, int64_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseInt64Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(int64_t))) {
        LOG_ERROR("ParseInt64Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = (int64_t)Ntohll(*(uint64_t *)val);
    return OPERA_SUCC;
}

int32_t ParseUint32Para(TlvListNode *node, int32_t msgType, uint32_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseUint32Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(uint32_t))) {
        LOG_ERROR("ParseUint32Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = Ntohl(*(uint32_t *)val);
    return OPERA_SUCC;
}

int32_t ParseInt32Para(TlvListNode *node, int32_t msgType, int32_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseInt32Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(int32_t))) {
        LOG_ERROR("ParseInt32Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = (int32_t)Ntohl(*(uint32_t *)val);
    return OPERA_SUCC;
}

Buffer *ParseBuffPara(TlvListNode *node, int32_t msgType)
{
    if (node == NULL) {
        LOG_ERROR("ParseBuffPara parameter check failed");
        return NULL;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if (val == NULL) {
        LOG_ERROR("ParseBuffPara GetTlvValue failed");
        return NULL;
    }
    Buffer *buff = CreateBufferByData(val, len);
    if (buff == NULL) {
        LOG_ERROR("ParseBuffPara CreateBufferByData failed");
        return NULL;
    }
    return buff;
}

int32_t ParseUint8Para(TlvListNode *node, int32_t msgType, uint8_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseUint8Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(uint8_t))) {
        LOG_ERROR("ParseUint8Para GetTlvValue failed");
        return PARAM_ERR;
    }
    *retVal = *val;
    return OPERA_SUCC;
}

int32_t GetUint64Para(TlvListNode *head, int32_t msgType, uint64_t *retVal)
{
    if ((head == NULL) || (retVal == NULL)) {
        LOG_ERROR("GetUint64Para parameter check failed");
        return PARAM_ERR;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int32_t nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        if (nodeType == msgType) {
            return ParseUint64Para(node, msgType, retVal);
        }
        node = node->next;
    }
    return PARAM_ERR;
}

int32_t GetUint32Para(TlvListNode *head, int32_t msgType, uint32_t *retVal)
{
    if ((head == NULL) || (retVal == NULL)) {
        LOG_ERROR("GetUint32Para parameter check failed");
        return PARAM_ERR;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int32_t nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        if (nodeType == msgType) {
            return ParseUint32Para(node, msgType, retVal);
        }
        node = node->next;
    }
    return PARAM_ERR;
}

int32_t GetInt32Para(TlvListNode *head, int32_t msgType, int32_t *retVal)
{
    if ((head == NULL) || (retVal == NULL)) {
        LOG_ERROR("GetInt32Para parameter check failed");
        return PARAM_ERR;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int32_t nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        if (nodeType == msgType) {
            return ParseInt32Para(node, msgType, retVal);
        }
        node = node->next;
    }
    return PARAM_ERR;
}

Buffer *GetBuffPara(TlvListNode *head, int32_t msgType)
{
    if (head == NULL) {
        LOG_ERROR("GetBuffPara parameter check failed");
        return NULL;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int32_t nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return NULL;
        }
        if (nodeType == msgType) {
            return ParseBuffPara(node, msgType);
        }
        node = node->next;
    }
    return NULL;
}

int32_t TlvAppendObject(TlvListNode *head, int32_t type, const uint8_t *buffer, uint32_t length)
{
    if (head == NULL || buffer == NULL || length == 0 || length > MAX_BUFFER_SIZE) {
        LOG_ERROR("param is invalid");
        return PARAM_ERR;
    }
    return PutTlvObject(head, type, length, buffer);
}

int32_t SerializeTlvWrapper(TlvListNode *head, uint8_t *buffer, uint32_t maxSize, uint32_t *contentSize)
{
    if (head == NULL || buffer == NULL || contentSize == NULL || maxSize == 0) {
        LOG_ERROR("param is invalid");
        return PARAM_ERR;
    }
    uint32_t offset = 0;
    TlvListNode *node = head->next;
    while (node != NULL) {
        TlvType *tlv = node->data.value;
        if (tlv == NULL) {
            LOG_ERROR("tlv is NULL");
            return PARAM_ERR;
        }
        int32_t type = (int32_t)Ntohl(tlv->type);
        if ((offset > UINT32_MAX - sizeof(int32_t) || offset + sizeof(int32_t) > maxSize) ||
            (memcpy_s(buffer + offset, sizeof(int32_t), &type, sizeof(int32_t)) != EOK)) {
            LOG_ERROR("copy type failed");
            return MEMCPY_ERR;
        }
        offset += sizeof(int32_t);
        uint32_t len = Ntohl(tlv->length);
        if ((offset > UINT32_MAX - sizeof(int32_t)) || (offset + sizeof(int32_t)) > maxSize ||
            (memcpy_s(buffer + offset, sizeof(int32_t), &len, sizeof(int32_t)) != EOK)) {
            LOG_ERROR("copy len failed");
            return MEMCPY_ERR;
        }
        offset += sizeof(int32_t);
        if ((offset > UINT32_MAX - tlv->length) || (offset + tlv->length > maxSize) ||
            ((tlv->length != 0) && (memcpy_s(buffer + offset, maxSize - offset, tlv->value, tlv->length) != EOK))) {
            LOG_ERROR("copy value failed");
            return MEMCPY_ERR;
        }
        offset += tlv->length;
        node = node->next;
    }

    *contentSize = offset;
    return OPERA_SUCC;
}