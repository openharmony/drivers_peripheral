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

#include "tlv_base.h"

#include "securec.h"

#include "adaptor_memory.h"

#define TO_RIGHT_END 24
#define TO_RIGHT 8
#define TO_LEFT_END 24
#define TO_LEFT 8

// short convert endian
uint16_t Ntohs(uint16_t data)
{
    return data;
}

// uint32 convert endian
uint32_t Ntohl(uint32_t data)
{
    return data;
}

// uint64 convert endian
uint64_t Ntohll(uint64_t data)
{
    return data;
}

TlvListNode *CreateTlvList(void)
{
    TlvListNode *node = (TlvListNode *)Malloc(sizeof(TlvListNode));
    if (node == NULL) {
        return NULL;
    }
    node->data.value = NULL;
    node->next = NULL;
    return node;
}

TlvType *CreateTlvType(int32_t type, uint32_t length, const void *value)
{
    if (value == NULL || length == 0) {
        return NULL;
    }
    TlvType *tlv = (TlvType *)Malloc(sizeof(TlvType));
    if (tlv == NULL) {
        return NULL;
    }

    tlv->type = type;
    tlv->length = length;
    tlv->value = (uint8_t *)Malloc(length);
    if (tlv->value == NULL) {
        Free(tlv);
        return NULL;
    }

    if (memcpy_s(tlv->value, length, value, length) != EOK) {
        Free(tlv->value);
        tlv->value = NULL;
        Free(tlv);
        return NULL;
    }
    return tlv;
}

int32_t DestroyTlvList(TlvListNode *head)
{
    if (head == NULL) {
        return PARAM_ERR;
    }
    TlvListNode *currNode = head->next;
    while (currNode != NULL) {
        TlvListNode *nextNode = currNode->next;
        TlvType *tlv = currNode->data.value;
        if (tlv != NULL) {
            if (tlv->value != NULL) {
                Free(tlv->value);
            }
            tlv->value = NULL;
            Free(tlv);
            tlv = NULL;
        }
        Free(currNode);
        currNode = nextNode;
    }
    Free(head);
    return OPERA_SUCC;
}

int32_t AddTlvNode(TlvListNode *head, const TlvObject *object)
{
    if (head == NULL || object == NULL) {
        return PARAM_ERR;
    }

    TlvListNode *node = (TlvListNode *)Malloc(sizeof(TlvListNode));
    if (node == NULL) {
        return MALLOC_FAIL;
    }
    node->data = *object;
    node->next = NULL;
    TlvListNode *temp = head->next;
    if (temp == NULL) {
        head->next = node;
    } else {
        while (temp->next != NULL) {
            temp = temp->next;
        }
        temp->next = node;
    }
    return OPERA_SUCC;
}