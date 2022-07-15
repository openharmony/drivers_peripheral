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

#ifndef PINAUTHTA_FUNC_H
#define PINAUTHTA_FUNC_H

#include "pin_db.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define TAG_AND_LEN_BYTE 8
#define TAG_ANG_LEN_T 12
#define TAG_AND_LEN_S 16
#define SIGN_DATA_LEN 64
#define PIN_RET_TYPE_LEN 8
#define PIN_RET_DATA_LEN 72
#define PIN_CAPABILITY_LEVEL 3
#define ED25519_FIX_PUBKEY_BUFFER_SIZE 32
#define ED25519_FIX_PRIKEY_BUFFER_SIZE 64
#define PIN_EXECUTOR_SECURITY_LEVEL 2
#define PIN_AUTH_AIBNILITY 7
#define ROOT_SECRET_LEN 32U

typedef enum {
    /* Root tag */
    AUTH_ROOT = 100000,
    /* Result code */
    AUTH_RESULT_CODE = 100001,
    /* Tag of signature data in TLV */
    AUTH_SIGNATURE = 100004,
    /* Identify mode */
    AUTH_IDENTIFY_MODE = 100005,
    /* Tag of templateId data in TLV */
    AUTH_TEMPLATE_ID = 100006,
    /* Tag of templateId list data in TLV */
    AUTH_TEMPLATE_ID_LIST = 100007,
    /* Expected attribute, tag of remain count in TLV */
    AUTH_REMAIN_COUNT = 100009,
    /* Remain time */
    AUTH_REMAIN_TIME = 100010,
    /* Session id, required when decode in C */
    AUTH_SCHEDULE_ID = 100014,
    /* Package name */
    AUTH_CALLER_NAME = 100015,
    /* Schedule version */
    AUTH_SCHEDULE_VERSION = 100016,
    /* Tag of lock out template in TLV */
    AUTH_LOCK_OUT_TEMPLATE = 100018,
    /* Tag of unlock template in TLV */
    AUTH_UNLOCK_TEMPLATE = 100019,
    /* Tag of data */
    AUTH_DATA = 100020,
    /* Tag of auth subType */
    AUTH_SUBTYPE = 100021,
    /* Tag of auth schedule mode */
    AUTH_SCHEDULE_MODE = 100022,
    /* Tag of property */
    AUTH_PROPERTY_MODE = 100023,
    /* Tag of auth type */
    AUTH_TYPE = 100024,
    /* Tag of cred id */
    AUTH_CREDENTIAL_ID = 100025,
    /* Controller */
    AUTH_CONTROLLER = 100026,
    /* calleruid */
    AUTH_CALLER_UID = 100027,
    /* result */
    AUTH_RESULT = 100028,
    /* capability level */
    AUTH_CAPABILITY_LEVEL = 100029,
    /* algorithm setinfo */
    ALGORITHM_INFO = 100030,
    /* time stamp */
    AUTH_TIME_STAMP = 100031,
    /* root secret */
    AUTH_ROOT_SECRET = 100032,
} AuthAttributeType;

typedef struct {
    uint64_t scheduleId;
    uint64_t templateId;
    uint8_t pinData[CONST_PIN_DATA_LEN];
} PinAuthParam;

typedef struct {
    uint64_t subType;
    uint64_t templateId;
} QueryCredential;

typedef struct {
    uint64_t subType;
    uint32_t remainTimes;
    uint32_t freezeTime;
} PinCredentialInfos;

typedef struct {
    uint32_t esl;
    uint8_t pubKey[CONST_PUB_KEY_LEN];
} PinExecutorInfo;

ResultCode DoEnrollPin(PinEnrollParam *pinEnrollParam, Buffer *retTlv);
ResultCode DoAuthPin(PinAuthParam *pinAuthParam, Buffer *data);
ResultCode DoQueryPinInfo(uint64_t templateId, PinCredentialInfos *pinCredentialInfo);
ResultCode DoDeleteTemplate(uint64_t templateId);
ResultCode GenerateRetTlv(uint32_t result, uint64_t scheduleId, uint64_t templatedId, Buffer *retTlv,
    Buffer *rootSecret);
ResultCode GenerateKeyPair();
ResultCode DoGetExecutorInfo(PinExecutorInfo *pinExecutorInfo);
ResultCode DoVerifyTemplateData(const uint64_t *templateIdList, uint32_t templateIdListLen);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // PINAUTHTA_FUNC_H
