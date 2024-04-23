/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "attribute.h"
#include "buffer.h"
#include "defines.h"
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

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

ExecutorResultInfo *CreateExecutorResultInfo(const Buffer *tlv);
ResultCode GetAttributeExecutorMsg(const Attribute *attribute, bool needSignature, Uint8Array *retMsg,
    bool needUserType);
void DestoryExecutorResultInfo(ExecutorResultInfo *result);
ResultCode GetExecutorMsgList(int32_t userId, uint32_t authPropertyMode, LinkedList **executorMsg);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_EXECUTOR_MESSAGE_H