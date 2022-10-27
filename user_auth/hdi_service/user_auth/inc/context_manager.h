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

#ifndef USERIAM_CONTEXT_MANAGER_H
#define USERIAM_CONTEXT_MANAGER_H

#include "coauth.h"
#include "linked_list.h"
#include "executor_message.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_MAX_SCHEDULING_NUM 5

typedef struct UserAuthContext {
    uint64_t contextId;
    int32_t userId;
    uint8_t challenge[CHALLENGE_LEN];
    uint32_t authType;
    uint32_t authTrustLevel;
    uint32_t collectorSensorHint;
    LinkedList *scheduleList;
} UserAuthContext;

typedef struct {
    uint64_t contextId;
    int32_t userId;
    uint8_t challenge[CHALLENGE_LEN];
    uint32_t authType;
    uint32_t authTrustLevel;
    uint32_t executorSensorHint;
} AuthSolutionHal;

typedef struct IdentifyParam {
    uint64_t contextId;
    uint8_t challenge[CHALLENGE_LEN];
    uint32_t authType;
    uint32_t executorSensorHint;
} IdentifyParam;

ResultCode InitUserAuthContextList();
void DestoryUserAuthContextList(void);
ResultCode GenerateAuthContext(AuthSolutionHal params, UserAuthContext **context);
UserAuthContext *GenerateIdentifyContext(IdentifyParam params);

UserAuthContext *GetContext(uint64_t contextId);
ResultCode ScheduleOnceFinish(UserAuthContext *context, uint64_t scheduleId);
void DestoryContext(UserAuthContext *context);
int32_t DestoryContextbyId(uint64_t contextId);
ResultCode CopySchedules(UserAuthContext *context, LinkedList **schedules);
int32_t FillInContext(UserAuthContext *context, uint64_t *credentialId, ExecutorResultInfo *info);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_CONTEXT_MANAGER_H