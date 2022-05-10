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

#ifndef TLV_BASE_H
#define TLV_BASE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OPERA_SUCC = 0,
    PARAM_ERR = 1001,
    MALLOC_FAIL = 1002,
    MEMCPY_ERR = 1003,
    MEMSET_ERR = 1004,
    OPERA_FAIL = 1005,
    TAG_NOT_EXIST = 1006,
} ErrCode;

typedef struct {
    int32_t type;
    uint32_t length;
    uint8_t *value;
} TlvType;

typedef struct {
    TlvType *value;
} TlvObject;

typedef struct tagTlvListNode {
    TlvObject data;
    struct tagTlvListNode *next;
} TlvListNode;


typedef union {
    uint64_t u64;
    uint32_t u32[2];
} SwapUint64;

// short convert endian
uint16_t Ntohs(uint16_t data);

// uint32 convert endian
uint32_t Ntohl(uint32_t data);

// uint64 convert endian
uint64_t Ntohll(uint64_t data);

TlvListNode *CreateTlvList(void);
int32_t DestroyTlvList(TlvListNode *list);
TlvType *CreateTlvType(int32_t type, uint32_t length, const void *value);
int32_t AddTlvNode(TlvListNode *list, const TlvObject *object);

#ifdef __cplusplus
}
#endif

#endif // TLV_BASE_H