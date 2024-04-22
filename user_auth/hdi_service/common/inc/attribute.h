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

#ifndef ATTRIBUTE_H
#define ATTRIBUTE_H

#include "c_array.h"
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* Root tag */
    AUTH_ROOT = 100000,
    /* Result code */
    AUTH_RESULT_CODE = 100001,
    /* Tag of signature data in TLV */
    AUTH_SIGNATURE = 100004,
    /* Identify mode */
    AUTH_IDENTIFY_MODE = 100005,
    /* Tag of templateId data in TLV */
    AUTH_TEMPLATE_ID = 100006,
    /* Tag of templateId list data in TLV */
    AUTH_TEMPLATE_ID_LIST = 100007,
    /* Expected attribute, tag of remain count in TLV */
    AUTH_REMAIN_COUNT = 100009,
    /* Remain time */
    AUTH_REMAIN_TIME = 100010,
    /* Session id, required when decode in C */
    AUTH_SCHEDULE_ID = 100014,
    /* Package name */
    AUTH_CALLER_NAME = 100015,
    /* Schedule version */
    AUTH_SCHEDULE_VERSION = 100016,
    /* Tag of lock out template in TLV */
    AUTH_LOCK_OUT_TEMPLATE = 100018,
    /* Tag of unlock template in TLV */
    AUTH_UNLOCK_TEMPLATE = 100019,
    /* Tag of data */
    AUTH_DATA = 100020,
    /* Tag of auth subType */
    AUTH_SUB_TYPE = 100021,
    /* Tag of auth schedule mode */
    AUTH_SCHEDULE_MODE = 100022,
    /* Tag of property */
    AUTH_PROPERTY_MODE = 100023,
    /* Tag of auth type */
    AUTH_TYPE = 100024,
    /* Tag of cred id */
    AUTH_CREDENTIAL_ID = 100025,
    /* Controller */
    AUTH_CONTROLLER = 100026,
    /* calleruid */
    AUTH_CALLER_UID = 100027,
    /* result */
    AUTH_RESULT = 100028,
    /* capability level */
    AUTH_CAPABILITY_LEVEL = 100029,
    /* algorithm setinfo */
    AUTH_ALGORITHM_INFO = 100030,
    /* time stamp */
    AUTH_TIME_STAMP = 100031,
    /* root secret */
    AUTH_ROOT_SECRET = 100032,
    /* user id */
    AUTH_USER_ID = 300000,
    /* user type */
    AUTH_USER_TYPE = 300009,
} AttributeKey;

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

#ifdef __cplusplus
}
#endif

#endif // ATTRIBUTE_H