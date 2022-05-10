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

#ifndef COAUTH_FUNCS_H
#define COAUTH_FUNCS_H

#include "buffer.h"

#include "coauth.h"
#include "coauth_sign_centre.h"
#include "pool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ExecutorInfoHal executorInfos[MAX_EXECUTOR_SIZE];
    uint32_t executorInfoNum;
    uint64_t templateId;
    uint64_t authSubType;
    uint32_t scheduleMode;
} ScheduleInfoHal;

int32_t GetScheduleInfo(uint64_t scheduleId, ScheduleInfoHal *scheduleInfo);
int32_t ScheduleFinish(const Buffer *executorMsg, ScheduleTokenHal *scheduleToken);

int32_t RegisterExecutor(const ExecutorInfoHal *executorInfo, uint64_t *executorId);
int32_t UnRegisterExecutor(uint64_t executorId);

bool IsExecutorExistFunc(uint32_t authType);

#ifdef __cplusplus
}
#endif

#endif // COAUTH_FUNCS_H
