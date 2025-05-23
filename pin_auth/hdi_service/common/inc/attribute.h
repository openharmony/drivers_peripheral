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

#ifndef ATTRIBUTE_H
#define ATTRIBUTE_H

#include "c_array.h"
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* Root tag */
    ATTR_ROOT = 100000,
    /* Result code */
    ATTR_RESULT_CODE = 100001,
    /* Tag of signature data in TLV */
    ATTR_SIGNATURE = 100004,
    /* Tag of templateId data in TLV */
    ATTR_TEMPLATE_ID = 100006,
    /* Tag of templateId list data in TLV */
    ATTR_TEMPLATE_ID_LIST = 100007,
    /* Expected attribute, tag of remain count in TLV */
    ATTR_REMAIN_ATTEMPTS = 100009,
    /* Remain time */
    ATTR_LOCKOUT_DURATION = 100010,
    /* Session id, required when decode in C */
    ATTR_SCHEDULE_ID = 100014,
    /* Tag of data */
    ATTR_DATA = 100020,
    /** Pin subtype, the value type is int32_t. */
    ATTR_PIN_SUB_TYPE = 100021,
    /* capability level */
    ATTR_ACL = 100029,
    /* time stamp */
    ATTR_TIME_STAMP = 100031,
    /* root secret */
    ATTR_ROOT_SECRET = 100032,
    ATTR_LOCAL_UDID = 100063,
    ATTR_PEER_UDID = 100064,
    ATTR_PUBLIC_KEY = 100065,
    ATTR_CHALLENGE = 100066,
    /* old pin root secret */
    ATTR_OLD_ROOT_SECRET = 100068,
    ATTR_AUTH_PURPOSE = 100069,

    PIN_ATTR_MSG_ID = 200001,
    PIN_ATTR_ALGO_VERSION = 200004,
    PIN_ATTR_ALGO_PARAM = 200005,
    PIN_ATTR_KEK_SALT = 200100,
    PIN_ATTR_KEK_IV = 200101,
    PIN_ATTR_KEK_SECRET = 200102,
    PIN_ATTR_KEK_TAG = 200103,
} AttributeKey;

typedef void Attribute;

Attribute *CreateEmptyAttribute(void);
Attribute *CreateAttributeFromSerializedMsg(const Uint8Array msg);
void FreeAttribute(Attribute **attribute);

ResultCode GetAttributeSerializedMsg(const Attribute *attribute, Uint8Array *retMsg);

ResultCode GetAttributeLength(const Attribute *attribute, AttributeKey key, uint32_t *len);
ResultCode GetAttributeUint32(const Attribute *attribute, AttributeKey key, uint32_t *retValue);
ResultCode SetAttributeUint32(Attribute *attribute, AttributeKey key, const uint32_t value);
ResultCode GetAttributeInt32(const Attribute *attribute, AttributeKey key, int32_t *retValue);
ResultCode SetAttributeInt32(Attribute *attribute, AttributeKey key, const int32_t value);
ResultCode GetAttributeUint64(const Attribute *attribute, AttributeKey key, uint64_t *retValue);
ResultCode SetAttributeUint64(Attribute *attribute, AttributeKey key, const uint64_t value);
ResultCode GetAttributeUint8Array(const Attribute *attribute, AttributeKey key, Uint8Array *retData);
ResultCode SetAttributeUint8Array(Attribute *attribute, AttributeKey key, const Uint8Array data);
ResultCode GetAttributeUint64Array(const Attribute *attribute, AttributeKey key, Uint64Array *retData);
ResultCode SetAttributeUint64Array(Attribute *attribute, AttributeKey key, const Uint64Array data);

#ifdef __cplusplus
}
#endif

#endif // ATTRIBUTE_H