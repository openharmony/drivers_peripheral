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

#ifndef AUTH_RESOURCE_POOL_H
#define AUTH_RESOURCE_POOL_H

#include "buffer.h"
#include "c_array.h"
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PUBLIC_KEY_LEN 32
#define INVALID_EXECUTOR_INDEX 0
#define CHALLENGE_LEN 32

typedef enum ExecutorRole {
    COLLECTOR = 1,
    VERIFIER = 2,
    ALL_IN_ONE = 3,
} ExecutorRole;

typedef struct ExecutorInfoHal {
    uint64_t executorIndex;
    uint32_t authType;
    uint32_t executorSensorHint;
    uint32_t executorRole;
    uint32_t executorMatcher;
    uint32_t esl;
    uint32_t maxTemplateAcl;
    uint8_t pubKey[PUBLIC_KEY_LEN];
    uint8_t deviceUdid[UDID_LEN];
} ExecutorInfoHal;

typedef enum ExecutorConditionTag {
    EXECUTOR_CONDITION_INDEX = 1,
    EXECUTOR_CONDITION_AUTH_TYPE = 2, // 1 << 1
    EXECUTOR_CONDITION_SENSOR_HINT = 4, // 1 << 2
    EXECUTOR_CONDITION_ROLE = 8, // 1 << 3
    EXECUTOR_CONDITION_MATCHER = 16, // 1 << 4
    EXECUTOR_CONDITION_UDID = 32, // 1 << 5
} ExecutorConditionTag;

typedef struct ExecutorCondition {
    uint64_t conditonFactor;
    uint64_t executorIndex;
    uint32_t authType;
    uint32_t executorSensorHint;
    uint32_t executorRole;
    uint32_t executorMatcher;
    uint8_t deviceUdid[UDID_LEN];
} ExecutorCondition;

ResultCode InitResourcePool(void);
void DestroyResourcePool(void);
ResultCode RegisterExecutorToPool(ExecutorInfoHal *executorInfo);
ResultCode UnregisterExecutorToPool(uint64_t executorIndex);

LinkedList *QueryExecutor(const ExecutorCondition *condition);
ResultCode QueryCollecterMatcher(uint32_t authType, uint32_t executorSensorHint, uint32_t *matcher);
uint64_t QueryCredentialExecutorIndex(uint32_t authType, uint32_t executorSensorHint);
ExecutorInfoHal *CopyExecutorInfo(ExecutorInfoHal *src);

void SetExecutorConditionExecutorIndex(ExecutorCondition *condition, uint64_t executorIndex);
void SetExecutorConditionAuthType(ExecutorCondition *condition, uint32_t authType);
void SetExecutorConditionSensorHint(ExecutorCondition *condition, uint32_t executorSensorHint);
void SetExecutorConditionExecutorRole(ExecutorCondition *condition, uint32_t executorRole);
void SetExecutorConditionExecutorMatcher(ExecutorCondition *condition, uint32_t executorMatcher);
void SetExecutorConditionDeviceUdid(ExecutorCondition *condition, Uint8Array deviceUdid);

#ifdef __cplusplus
}
#endif

#endif
