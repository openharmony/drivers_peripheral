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

#ifndef PINAUTHTA_VERIFIER_FUNC_H
#define PINAUTHTA_VERIFIER_FUNC_H

#include "executor_func_common.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct VerifierMsg {
    uint8_t *msgIn;
    uint32_t msgInSize;
    uint8_t *msgOut;
    uint32_t msgOutSize;
    bool isAuthEnd;
    int32_t authResult;
} VerifierMsg;

ResultCode GenerateVerifierKeyPair(void);
void DestroyVerifierKeyPair(void);
ResultCode DoGetVerifierExecutorInfo(PinExecutorInfo *pinExecutorInfo);
int32_t DoSetVerifierFwkParam(const uint8_t *fwkPubKey, uint32_t fwkPubKeySize);
int32_t DoVerifierAuth(uint64_t scheduleId, uint64_t templateId, VerifierMsg *verifierMsg);
int32_t DoCancelVerifierAuth();
int32_t DoSendMessageToVerifier(uint64_t scheduleId, VerifierMsg *verifierMsg);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // PINAUTHTA_VERIFIER_FUNC_H
