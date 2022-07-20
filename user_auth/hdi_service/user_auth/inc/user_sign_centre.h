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

#ifndef USERIAM_USER_SIGN_CENTRE_H
#define USERIAM_USER_SIGN_CENTRE_H

#include <stdint.h>

#include "buffer.h"
#include "defines.h"
#include "context_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_SIGN_LEN 32
#define AUTH_TOKEN_LEN sizeof(UserAuthTokenHal)
#define AUTH_TOKEN_DATA_LEN (AUTH_TOKEN_LEN - SHA256_SIGN_LEN)
#define SHA256_KEY_LEN 32
#define TOKEN_VERSION 0

typedef struct {
    uint32_t version;
    uint8_t challenge[CHALLENGE_LEN];
    uint64_t secureUid;
    uint64_t enrolledId;
    uint64_t credentialId;
    uint64_t time;
    uint32_t authTrustLevel;
    uint32_t authType;
    uint32_t authMode;
    uint32_t securityLevel;
    uint8_t sign[SHA256_SIGN_LEN];
} __attribute__((__packed__)) UserAuthTokenHal;

ResultCode GetTokenDataAndSign(const UserAuthContext *context,
    uint64_t credentialId, uint32_t authMode, UserAuthTokenHal *authToken);
ResultCode UserAuthTokenSign(UserAuthTokenHal *userAuthToken);
ResultCode UserAuthTokenVerify(const UserAuthTokenHal *userAuthToken);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_USER_SIGN_CENTRE_H