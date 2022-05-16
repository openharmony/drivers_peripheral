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

#ifndef COAUTH_SIGN_CENTRE_H
#define COAUTH_SIGN_CENTRE_H

#include <stdint.h>

#include "buffer.h"
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_SIGN_LEN 32
#define COAUTH_TOKEN_LEN sizeof(ScheduleTokenHal)
#define COAUTH_TOKEN_DATA_LEN (COAUTH_TOKEN_LEN - SHA256_SIGN_LEN)
#define SHA256_KEY_LEN 32
#define TOKEN_VERSION 0

typedef struct {
    uint32_t scheduleResult;
    uint64_t scheduleId;
    uint32_t authType;
    uint64_t authSubType;
    uint64_t templateId;
    uint32_t scheduleMode;
    uint32_t capabilityLevel;
    uint32_t version;
    uint64_t time;
    uint8_t sign[SHA256_SIGN_LEN];
} ScheduleTokenHal;

ResultCode CoAuthTokenSign(ScheduleTokenHal *userAuthToken);
ResultCode CoAuthTokenVerify(const ScheduleTokenHal *userAuthToken);

#ifdef __cplusplus
}
#endif

#endif // COAUTH_SIGN_CENTRE_H