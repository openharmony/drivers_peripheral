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
    /* Identify mode */
    ATTR_IDENTIFY_MODE = 100005,
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
    /* Tag of auth subType */
    ATTR_PIN_SUB_TYPE = 100021,
    /* Tag of auth schedule mode */
    ATTR_SCHEDULE_MODE = 100022,
    /* Tag of property */
    ATTR_PROPERTY_MODE = 100023,
    /* Tag of auth type */
    ATTR_TYPE = 100024,
    /* Tag of cred id */
    ATTR_CREDENTIAL_ID = 100025,
    /* Controller */
    ATTR_CONTROLLER = 100026,
    /* calleruid */
    ATTR_CALLER_UID = 100027,
    /* result */
    ATTR_RESULT = 100028,
    /* capability level */
    ATTR_CAPABILITY_LEVEL = 100029,
    /* algorithm setinfo */
    ATTR_ALGORITHM_INFO = 100030,
    /* time stamp */
    ATTR_TIME_STAMP = 100031,
    /* root secret */
    ATTR_ROOT_SECRET = 100032,
    /* attrs */
    ATTR_ATTRS = 100033,
    /* pin expired sys time */
    ATTR_EXPIRED_SYS_TIME = 100034,
    /* executor matcher */
    ATTR_EXECUTOR_MATCHER = 100036,
    /* user id */
    ATTR_USER_ID = 100041,
    /* token */
    ATTR_TOKEN = 100042,
    /* executor role */
    ATTR_EXECUTOR_ROLE = 100043,
    /* esl */
    ATTR_ESL = 100044,
    /* VERIFIER udid */
    ATTR_VERIFIER_UDID = 100045,
    /* COLLECTOR udid */
    ATTR_COLLECTOR_UDID = 100046,
    /* local udid */
    ATTR_LOCAL_UDID = 100063,
    /* peer udid */
    ATTR_PEER_UDID = 100064,
    /* public key */
    ATTR_PUBLIC_KEY = 100065,
    /* Challenge */
    ATTR_CHALLENGE = 100066,
    /* executor index */
    ATTR_EXECUTOR_INDEX = 100067,
} AttributeKey;

#define MAX_SUB_MSG_NUM 10

typedef void Attribute;

#define MAX_EXECUTOR_MSG_LEN 2048

Attribute *CreateEmptyAttribute(void);
Attribute *CreateAttributeFromSerializedMsg(const Uint8Array msg);
void FreeAttribute(Attribute **attribute);

ResultCode GetAttributeSerializedMsg(const Attribute *attribute, Uint8Array *retMsg);

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

ResultCode ParseMultiDataSerializedMsg(const Uint8Array msg, Uint8Array *subMsgData, int *subMsgSize);
ResultCode GetMultiDataSerializedMsg(Uint8Array *sourceArrayMsg, uint32_t size, Uint8Array *retMsg);

#ifdef __cplusplus
}
#endif

#endif // ATTRIBUTE_H