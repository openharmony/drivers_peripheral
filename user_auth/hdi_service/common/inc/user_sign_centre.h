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

#ifndef USERIAM_USER_SIGN_CENTRE_H
#define USERIAM_USER_SIGN_CENTRE_H

#include <stdint.h>

#include "adaptor_algorithm.h"
#include "buffer.h"
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AUTH_TOKEN_LEN sizeof(UserAuthTokenHal)
#define AUTH_TOKEN_DATA_LEN (AUTH_TOKEN_LEN - SHA256_DIGEST_SIZE)
#define AUTH_TOKEN_CIPHER_LEN sizeof(TokenDataToEncrypt)
#define TOKEN_VERSION 0
#define UDID_LEN 64

typedef struct {
    uint8_t challenge[CHALLENGE_LEN];
    uint64_t time;
    uint32_t authTrustLevel;
    uint32_t authType;
    uint32_t authMode;
    uint32_t securityLevel;
    uint32_t tokenType;
} __attribute__((__packed__)) TokenDataPlain;

typedef struct {
    int32_t userId;
    uint64_t secureUid;
    uint64_t enrolledId;
    uint64_t credentialId;
    uint8_t collectorUdid[UDID_LEN];
    uint8_t verifierUdid[UDID_LEN];
} __attribute__((__packed__)) TokenDataToEncrypt;

typedef struct {
    uint32_t version;
    TokenDataPlain tokenDataPlain;
    uint8_t tokenDataCipher[AUTH_TOKEN_CIPHER_LEN];
    uint8_t tag[AES_GCM_TAG_SIZE];
    uint8_t iv[AES_GCM_IV_SIZE];
    uint8_t sign[SHA256_DIGEST_SIZE];
} __attribute__((__packed__)) UserAuthTokenHal;

typedef struct {
    TokenDataPlain tokenDataPlain;
    TokenDataToEncrypt tokenDataToEncrypt;
} __attribute__((__packed__)) UserAuthTokenPlain;

ResultCode UserAuthTokenSign(UserAuthTokenPlain *tokenPlain, UserAuthTokenHal *authToken);
ResultCode UserAuthTokenVerify(UserAuthTokenHal *userAuthToken, UserAuthTokenPlain *tokenPlain);
ResultCode ReuseUnlockTokenSign(UserAuthTokenHal *reuseToken);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_USER_SIGN_CENTRE_H