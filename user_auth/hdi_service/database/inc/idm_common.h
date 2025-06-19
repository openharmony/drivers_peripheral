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

#ifndef IDM_COMMON_H
#define IDM_COMMON_H

#include <stdint.h>
#include "linked_list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_USER 5
#define MAX_CREDENTIAL 100
#define ROOT_SECRET_LEN 32
#define NO_CHECK_PIN_EXPIRED_PERIOD 0
#define MAX_GLOBAL_CONFIG_NUM (1 + MAX_AUTH_TYPE_LEN * 1)
#define NO_SET_PIN_EXPIRED_PERIOD (-1)
#define MAX_CREDENTIAL_NUM_OF_ENROLL 2

#define ABANDON_PIN_VALID_PERIOD (96 * 3600 * 1000)

typedef struct {
    uint64_t credentialId;
    uint64_t templateId;
    uint32_t authType;
    uint32_t executorSensorHint;
    uint32_t executorMatcher;
    uint32_t capabilityLevel;
    uint32_t credentialType;
    bool isAbandoned;
    uint64_t enrolledSysTime;
    uint64_t abandonedSysTime;
} CredentialInfoHal;

typedef struct {
    uint32_t authType;
    uint64_t enrolledId;
} EnrolledInfoHal;

typedef struct {
    int32_t userId;
    uint64_t secUid;
    uint64_t pinSubType;
    uint64_t cachePinSubType;
    LinkedList *credentialInfoList;
    LinkedList *enrolledInfoList;
    int32_t userType;
} UserInfo;

typedef struct {
    int32_t userId;
    uint64_t secUid;
    uint32_t pinSubType;
    uint32_t enrollNum;
    EnrolledInfoHal enrolledInfo[MAX_ENROLL_OUTPUT];
} UserInfoResult;

typedef struct {
    uint64_t credentialDigest;
    uint16_t credentialCount;
} EnrolledStateHal;

enum GlobalConfigTypeHal : int32_t {
    PIN_EXPIRED_PERIOD = 1,
    ENABLE_STATUS = 2,
};

union GlobalConfigValueHal {
    int64_t pinExpiredPeriod;
    bool enableStatus;
};

typedef struct {
    int32_t type;
    union GlobalConfigValueHal value;
    int32_t userIds[MAX_USER];
    uint32_t userIdNum;
    uint32_t authTypes[MAX_AUTH_TYPE_LEN];
    uint32_t authTypeNum;
} GlobalConfigParamHal;

typedef struct {
    int32_t type;
    union GlobalConfigValueHal value;
    int32_t userIds[MAX_USER];
    uint32_t userIdNum;
    uint32_t authType;
} GlobalConfigInfo;

typedef struct {
    uint64_t pinEnrolledSysTime;
    int64_t pinExpiredPeriod;
} PinExpiredInfo;

void DestroyUserInfoNode(void *userInfo);
void DestroyCredentialNode(void *credential);
void DestroyEnrolledNode(void *enrolled);
UserInfo *InitUserInfoNode(void);

#ifdef __cplusplus
}
#endif

#endif // IDM_COMMON_H