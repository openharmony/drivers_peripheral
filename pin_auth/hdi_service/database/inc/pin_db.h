/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef PIN_DB_H
#define PIN_DB_H

#include "defines.h"
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define MAX_USER_NAME_LEN 32
#define INVALID_TEMPLATE_ID 0xFFFFFFFFFFFFFFFF
#define PIN_DB_TWO_PARAMS 2
#define MAX_RANDOM_TIME 10
#define DEFAULT_FILE_HEAD "/data/service/el1/public/pinauth/"
#define MAX_UINT_LEN 21
#define MAX_CRYPTO_INFO_SIZE 100
#define CURRENT_VERSION 0
#define PIN_INDEX_NAME "/data/service/el1/public/pinauth/PinIndexDb"
#define MAX_FILE_NAME_LEN 256
#define CRYPTO_SUFFIX "_CryptoInfo"
#define ANTI_BRUTE_SUFFIX "_BruteForceCount"
#define SALT_SUFFIX "_salt"
#define SECRET_SUFFIX "_secret"
#define SALT_PREFIX "hkdf_salt"
#define CREDENTIAL_PREFIX "template_encryption_key"
#define INIT_AUTH_ERROR_COUNT 0
#define INIT_START_FREEZE_TIMES 0
#define DEFAULT_VALUE 1
#define REMAINING_TIMES_FREEZE 1
#define FIRST_ANTI_BRUTE_COUNT 5
#define SECOND_ANTI_BRUTE_COUNT 8
#define THIRD_ANTI_BRUTE_COUNT 11
#define ANTI_BRUTE_COUNT_FREQUENCY 3
#define ANTI_BRUTE_INTERVAL_COUNT 2
#define ATTI_BRUTE_FIRST_STAGE 100
#define ATTI_BRUTE_SECOND_STAGE 140
#define ONE_MIN_TIME 60
#define TEN_MIN_TIME 600
#define THIRTY_MIN_TIME 1800
#define ONE_HOUR_TIME 3600
#define ONE_DAY_TIME 86400
#define FIRST_EXPONENTIAL_PARA 30
#define SECOND_EXPONENTIAL_PARA 2
#define THIRD_EXPONENTIAL_PARA 10
#define MS_OF_S 1000ull
#define CONST_PIN_DATA_LEN 64U
#define CONST_PIN_DATA_EXPAND_LEN 92U
#define CONST_SALT_LEN 32U
#define CONST_PUB_KEY_LEN 32U
#define CONST_CREDENTIAL_PREFIX_LEN 32U
#define CONST_EXPAND_DATA_LEN 128U
#define RESULT_TLV_LEN 240U

typedef struct {
    uint64_t templateId;
    uint64_t subType;
} __attribute__((__packed__)) PinIndex;

typedef struct {
    uint32_t version;
    uint32_t pinIndexLen;
    PinIndex *pinIndex;
    bool isLoaded;
} __attribute__((__packed__)) PinDb;

typedef struct {
    uint32_t authErrorConut;
    uint64_t startFreezeTime;
} __attribute__((__packed__)) AntiBruteInfo;

typedef struct {
    uint64_t scheduleId;
    uint64_t subType;
    uint8_t salt[CONST_SALT_LEN];
    uint8_t pinData[CONST_PIN_DATA_LEN];
} __attribute__((__packed__)) PinEnrollParam;

void InitPinDb(void);
void DestroyPinDb(void);

ResultCode AddPin(PinEnrollParam *pinEnrollParam, uint64_t *templateId, Buffer *outRootSecret);
ResultCode DoGetSalt(uint64_t templateId, uint8_t *salt, uint32_t *saltLen);
ResultCode DelPinById(uint64_t templateId);
ResultCode AuthPinById(const uint8_t *inputData, const uint32_t inputDataLen, uint64_t templateId,
    Buffer *outRootSecret);
ResultCode ComputeFreezeTime(uint64_t templateId, uint32_t *remainingFT, uint32_t count, uint64_t startFreezeTime);
ResultCode GetRemainTimes(uint64_t templateId, uint32_t *remainingAuthTimes, uint32_t authErrorConut);
ResultCode GetSubType(uint64_t templateId, uint64_t *subType);
ResultCode GetAntiBruteInfo(uint64_t templateId, uint32_t *authErrorConut, uint64_t *startFreezeTime);
ResultCode VerifyTemplateDataPin(const uint64_t *templateIdList, uint32_t templateIdListLen);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif  // PIN_DB_H