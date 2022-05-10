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
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PUBLIC_KEY_LEN 32

typedef enum ExecutorType {
    COLLECTOR = 1,
    VERIFIER = 2,
    ALL_IN_ONE = 3,
} ExecutorType;

typedef struct ExecutorInfoHal {
    uint64_t executorId;
    uint32_t authType;
    uint64_t authAbility;
    uint32_t esl;
    uint32_t executorType;
    uint8_t pubKey[PUBLIC_KEY_LEN];
} ExecutorInfoHal;

ResultCode InitResourcePool(void);
void DestroyResourcePool(void);
ResultCode RegisterExecutorToPool(ExecutorInfoHal *executorInfo);
ResultCode UnregisterExecutorToPool(uint64_t executorId);
ResultCode QueryExecutor(uint32_t authType, LinkedList **result);
ExecutorInfoHal *CopyExecutorInfo(ExecutorInfoHal *src);

#ifdef __cplusplus
}
#endif

#endif
