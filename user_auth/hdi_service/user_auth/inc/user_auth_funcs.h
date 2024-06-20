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

#ifndef USER_AUTH_FUNCS_H
#define USER_AUTH_FUNCS_H

#include "buffer.h"

#include "context_manager.h"
#include "idm_common.h"
#include "user_sign_centre.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REUSED_UNLOCK_TOKEN_PERIOD (5 * 60 * 1000)
#define NO_SET_PIN_EXPIRED_PERIOD (-1)

typedef struct AuthResult {
    int32_t userId;
    uint32_t authType;
    int32_t freezingTime;
    int32_t remainTimes;
    int32_t result;
    Buffer *rootSecret;
    uint64_t credentialDigest;
    uint16_t credentialCount;
    int64_t pinExpiredInfo;
    Buffer *remoteAuthResultMsg;
} AuthResult;

typedef struct {
    int32_t userId;
    uint32_t authTrustLevel;
    uint32_t authTypes[MAX_AUTH_TYPE_LEN];
    uint32_t authTypeSize;
    uint8_t challenge[CHALLENGE_LEN];
    uint64_t reuseUnlockResultDuration;
    uint32_t reuseUnlockResultMode;
} ReuseUnlockParamHal;

typedef struct {
    int32_t authType;
    uint8_t token[AUTH_TOKEN_LEN];
    EnrolledStateHal enrolledState;
} ReuseUnlockResult;

typedef enum ReuseMode {
    AUTH_TYPE_RELEVANT = 1,
    AUTH_TYPE_IRRELEVANT = 2,
} ReuseMode;

typedef struct {
    bool isCached;
    int32_t userId;
    UserAuthTokenHal authToken;
} __attribute__((__packed__)) UnlockAuthResultCache;

ResultCode GenerateSolutionFunc(AuthParamHal param, LinkedList **schedules);
ResultCode RequestAuthResultFunc(uint64_t contextId, const Buffer *scheduleResult, UserAuthTokenHal *authToken,
    AuthResult *result);
ResultCode GetEnrolledStateFunc(int32_t userId, uint32_t authType, EnrolledStateHal *enrolledStateHal);
ResultCode CheckReuseUnlockResultFunc(const ReuseUnlockParamHal *info, ReuseUnlockResult *reuseResult);
ResultCode SetGlobalConfigParamFunc(GlobalConfigParamHal *param);
ResultCode GetAvailableStatusFunc(int32_t userId, int32_t authType, uint32_t authTrustLevel);

ResultCode GenerateScheduleFunc(const Buffer *tlv, Uint8Array remoteUdid, ScheduleInfoParam *scheduleInfo);
ResultCode GenerateAuthResultFunc(const Buffer *tlv, AuthResultParam *authResultInfo);
ResultCode GetExecutorInfoLinkedList(uint32_t authType, uint32_t executorRole, LinkedList *allExecutorInfoList);
Buffer *GetSignExecutorInfoFunc(Uint8Array peerUdid, LinkedList *executorList);
void DestroyAuthResult(AuthResult *authResult);

#ifdef __cplusplus
}
#endif

#endif // USER_AUTH_FUNCS_H