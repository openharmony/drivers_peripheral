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

#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_MAX_SCHEDULING_NUM 5

typedef struct UserAuthContext {
    uint64_t contextId;
    int32_t userId;
    uint64_t challenge;
    uint32_t authType;
    uint32_t authTrustLevel;
    LinkedList *scheduleList;
} UserAuthContext;

typedef struct {
    uint64_t contextId;
    int32_t userId;
    uint64_t challenge;
    uint32_t authType;
    uint32_t authTrustLevel;
} AuthSolutionHal;

ResultCode InitUserAuthContextList();
void DestoryUserAuthContextList(void);
UserAuthContext *GenerateContext(AuthSolutionHal params);

UserAuthContext *GetContext(uint64_t contextId);
ResultCode ScheduleOnceFinish(UserAuthContext *context, uint64_t scheduleId);
void DestoryContext(UserAuthContext *context);
ResultCode GetSchedules(UserAuthContext *context, CoAuthSchedule **schedules, uint32_t *scheduleNum);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_CONTEXT_MANAGER_H