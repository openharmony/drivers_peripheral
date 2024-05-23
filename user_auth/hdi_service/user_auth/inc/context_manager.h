/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
#include "executor_message.h"
#include "linked_list.h"

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
    uint64_t authExpiredSysTime;
    bool isAuthResultCached;
    bool isExpiredReturnSuccess;
    uint8_t localUdid[UDID_LEN];
    uint8_t collectorUdid[UDID_LEN];
} UserAuthContext;

typedef struct {
    uint64_t contextId;
    int32_t userId;
    uint8_t challenge[CHALLENGE_LEN];
    uint32_t authType;
    uint32_t authTrustLevel;
    uint32_t executorSensorHint;
    bool isAuthResultCached;
    bool isExpiredReturnSuccess;
    uint8_t localUdid[UDID_LEN];
    uint8_t collectorUdid[UDID_LEN];
} AuthParamHal;

typedef struct IdentifyParam {
    uint64_t contextId;
    uint8_t challenge[CHALLENGE_LEN];
    uint32_t authType;
    uint32_t executorSensorHint;
} IdentifyParam;

typedef struct {
    uint64_t scheduleId;
    uint32_t scheduleMode;
    uint64_t authExpiredSysTime;
} ExecutorExpiredInfo;

ResultCode InitUserAuthContextList(void);
void DestoryUserAuthContextList(void);
ResultCode GenerateAuthContext(AuthParamHal params, UserAuthContext **context);
UserAuthContext *GenerateIdentifyContext(IdentifyParam params);

UserAuthContext *GetContext(uint64_t contextId);
ResultCode ScheduleOnceFinish(UserAuthContext *context, uint64_t scheduleId);
void DestroyContext(UserAuthContext *context);
ResultCode DestroyContextbyId(uint64_t contextId);
ResultCode CopySchedules(UserAuthContext *context, LinkedList **schedules);
ResultCode FillInContext(UserAuthContext *context, uint64_t *credentialId, ExecutorResultInfo *info,
    uint32_t authMode);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_CONTEXT_MANAGER_H