/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef PINAUTHTA_EXECUTOR_FUNC_COMMON_H
#define PINAUTHTA_EXECUTOR_FUNC_COMMON_H

#include "adaptor_algorithm.h"
#include "attribute.h"
#include "buffer.h"
#include "pin_db.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define PIN_CAPABILITY_LEVEL 3
#define PIN_EXECUTOR_SECURITY_LEVEL 2

#define CONST_FWK_UDID_SIZE 64

#define CONST_KEK_SALT_SIZE 32

#define CONST_KEK_AAD "remote_pin_aes_aad"
#define CONST_KEK_AAD_SIZE 18

#define CONST_CHALLENGE_LEN 32

enum ExecutorRole {
    SCHEDULER = 0,
    COLLECTOR = 1,
    VERIFIER = 2,
    ALL_IN_ONE = 3,
};

typedef enum RemotePinMsgId {
    REMOTE_PIN_MSG_NONE = 0,
    REMOTE_PIN_COLLECTOR_SYNC = 1,
    REMOTE_PIN_VERIFIER_ACK = 2,
    REMOTE_PIN_COLLECTOR_ACK = 3,
} RemotePinMsgId;

typedef struct PinExecutorInfo {
    uint32_t esl;
    uint8_t pubKey[ED25519_FIX_PUBKEY_BUFFER_SIZE];
    uint32_t maxTemplateAcl;
} PinExecutorInfo;

typedef struct {
    uint64_t subType;
    uint32_t remainTimes;
    uint32_t freezeTime;
    int32_t nextFailLockoutDuration;
    uint32_t credentialLength;
} PinCredentialInfos;

typedef struct AlgoParamOut {
    uint32_t algoVersion;
    uint64_t subType;
    uint8_t algoParameter[CONST_SALT_LEN];
    uint8_t challenge[CONST_CHALLENGE_LEN];
} AlgoParamOut;

int32_t SetBufferToAttribute(Attribute *attribute, AttributeKey key, Buffer *buf);
Buffer *GetBufferFromAttribute(const Attribute *attribute, AttributeKey key, uint32_t size);
Attribute *GetAttributeDataBase(uint64_t scheduleId, RemotePinMsgId msgId);
int32_t FormatTlvMsg(const Attribute *data, const KeyPair *keyPair, uint8_t *msg, uint32_t *msgSize);
int32_t VerifyAndGetDataAttribute(
    uint64_t scheduleId, Attribute **data, const Buffer *pubKey, const uint8_t *msg, uint32_t msgSize);
int32_t CheckAttributeDataBase(const Attribute *data, uint64_t scheduleId, RemotePinMsgId msgId, uint64_t *timeStamp);
int32_t DoQueryPinInfo(uint64_t templateId, PinCredentialInfos *pinCredentialInfo);
bool SetResultDataInfo(Attribute *attribute, int32_t resultCode, uint64_t templateId, Buffer *rootSecret);
int32_t PinResultToFwkResult(int32_t pinResult);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // PINAUTHTA_EXECUTOR_FUNC_COMMON_H
