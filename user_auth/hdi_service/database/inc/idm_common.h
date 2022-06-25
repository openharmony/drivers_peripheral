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

#ifndef IDM_COMMON_H
#define IDM_COMMON_H

#include <stdint.h>
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_USER 1000
#define MAX_CREDENTIAL 100

typedef struct {
    uint64_t credentialId;
    uint64_t templateId;
    uint32_t authType;
    uint32_t executorSensorHint;
    uint32_t executorMatcher;
    uint32_t capabilityLevel;
} CredentialInfoHal;

typedef struct {
    uint32_t authType;
    uint64_t enrolledId;
} EnrolledInfoHal;

typedef struct {
    int32_t userId;
    uint64_t secUid;
    uint64_t pinSubType;
    LinkedList *credentialInfoList;
    LinkedList *enrolledInfoList;
} UserInfo;

void DestroyUserInfoNode(void *userInfo);
void DestroyCredentialNode(void *credential);
void DestroyEnrolledNode(void *enrolled);
UserInfo *InitUserInfoNode(void);

#ifdef __cplusplus
}
#endif

#endif // IDM_COMMON_H