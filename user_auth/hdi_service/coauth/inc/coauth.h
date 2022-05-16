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

#ifndef USERIAM_COAUTH_H
#define USERIAM_COAUTH_H

#include "pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INVALID_SESSION_ID 0
#define MAX_EXECUTOR_SIZE 2

typedef enum ScheduleMode {
    SCHEDULE_MODE_ENROLL = 0,
    SCHEDULE_MODE_AUTH = 1,
} ScheduleMode;

typedef union AssociateId {
    uint64_t contextId;
    uint64_t challenge;
} AssociateId;

typedef struct CoAuthSchedule {
    uint64_t scheduleId;
    ScheduleMode scheduleMode;
    AssociateId associateId;
    uint64_t templateId;
    uint64_t authSubType;
    uint32_t executorSize;
    ExecutorInfoHal executors[MAX_EXECUTOR_SIZE];
} CoAuthSchedule;

ResultCode InitCoAuth(void);
void DestoryCoAuth(void);

CoAuthSchedule *GenerateAuthSchedule(uint64_t contextId, uint32_t authType, uint64_t authSubType,
    uint64_t templateId);
CoAuthSchedule *GenerateIdmSchedule(uint64_t challenge, uint32_t authType, uint64_t authSubType);

ResultCode AddCoAuthSchedule(CoAuthSchedule *coAuthSchedule);
ResultCode RemoveCoAuthSchedule(uint64_t scheduleId);
ResultCode GetCoAuthSchedule(CoAuthSchedule *coAuthSchedule);
void DestroyCoAuthSchedule(CoAuthSchedule *coAuthSchedule);

#ifdef __cplusplus
}
#endif

#endif
