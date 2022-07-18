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

#ifndef USERIAM_EXECUTOR_MESSAGE_H
#define USERIAM_EXECUTOR_MESSAGE_H

#include <stdint.h>

#include "buffer.h"
#include "defines.h"
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BUFFER_SIZE 2048
typedef enum AuthAttributeType {
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
    AUTH_SUBTYPE = 100021,
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
    ALGORITHM_INFO = 100030,
    /* time stamp */
    AUTH_TIME_STAMP = 100031,
    /* root secret */
    AUTH_ROOT_SECRET = 100032,
} AuthAttributeType; // the new tag must be consistent with userauth SA

typedef struct ExecutorResultInfo {
    int32_t result;
    uint64_t scheduleId;
    uint64_t templateId;
    uint64_t authSubType;
    uint32_t capabilityLevel;
    int32_t freezingTime;
    int32_t remainTimes;
    Buffer *rootSecret;
} ExecutorResultInfo;

typedef struct ExecutorMsg {
    uint64_t executorIndex;
    Buffer *msg;
} ExecutorMsg;

ExecutorResultInfo *CreateExecutorResultInfo(const Buffer *executorResultInfo);
void DestoryExecutorResultInfo(ExecutorResultInfo *result);
ResultCode GetExecutorMsgList(uint32_t authPropertyMode, LinkedList **executorMsg);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_EXECUTOR_MESSAGE_H