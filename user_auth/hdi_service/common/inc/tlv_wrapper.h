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

#ifndef TLV_WRAPPER_H
#define TLV_WRAPPER_H

#include <stdint.h>

#include "tlv_base.h"
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BUFFER_SIZE 512000
#define TLV_HEADER_LEN (sizeof(int32_t) + sizeof(uint32_t))

int32_t ParseTlvWrapper(const uint8_t *buffer, uint32_t bufferSize, TlvListNode *head);
int32_t ParseGetHeadTag(const TlvListNode *node, int32_t *tag);

int32_t ParseUint64Para(TlvListNode *node, int32_t msgType, uint64_t *retVal);
int32_t ParseInt64Para(TlvListNode *node, int32_t msgType, int64_t *retVal);
int32_t ParseUint32Para(TlvListNode *node, int32_t msgType, uint32_t *retVal);
int32_t ParseInt32Para(TlvListNode *node, int32_t msgType, int32_t *retVal);
Buffer *ParseBuffPara(TlvListNode *node, int32_t msgType);
int32_t ParseUint8Para(TlvListNode *node, int32_t msgType, uint8_t *retVal);

int32_t GetUint64Para(TlvListNode *head, int32_t msgType, uint64_t *retVal);
int32_t GetUint32Para(TlvListNode *head, int32_t msgType, uint32_t *retVal);
int32_t GetInt32Para(TlvListNode *head, int32_t msgType, int32_t *retVal);
Buffer *GetBuffPara(TlvListNode *head, int32_t msgType);

int32_t TlvAppendObject(TlvListNode *head, int32_t type, const uint8_t *buffer, uint32_t length);
int32_t SerializeTlvWrapper(TlvListNode *head, uint8_t *buffer, uint32_t maxSize, uint32_t *contentSize);

#ifdef __cplusplus
}
#endif

#endif // TLV_WRAPPER_H