/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef PINAUTHTA_ALL_IN_ONE_FUNC_H
#define PINAUTHTA_ALL_IN_ONE_FUNC_H

#include "executor_func_common.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define TAG_AND_LEN_BYTE 8
#define ROOT_SECRET_LEN 32U

typedef struct {
    uint64_t scheduleId;
    uint64_t templateId;
    uint8_t pinData[CONST_PIN_DATA_LEN];
} PinAuthParam;

typedef struct {
    uint64_t subType;
    uint64_t templateId;
} QueryCredential;

ResultCode DoGetAllInOneExecutorInfo(PinExecutorInfo *pinExecutorInfo);
ResultCode DoEnrollPin(PinEnrollParam *pinEnrollParam, Buffer *retTlv);
ResultCode DoAllInOneAuth(uint64_t scheduleId, uint64_t templateId,
    const uint8_t *extraInfo, uint32_t extraInfoSize, AlgoParamOut *algoParam);
ResultCode DoAuthPin(PinAuthParam *pinAuthParam, Buffer *retTlv, ResultCode *compareRet);
ResultCode DoDeleteTemplate(uint64_t templateId);
ResultCode GenerateAllInOneKeyPair(void);
void DestroyAllInOneKeyPair(void);
ResultCode DoSetAllInOneFwkParam(
    const uint64_t *templateIdList, uint32_t templateIdListLen, const uint8_t *fwkPubKey, uint32_t fwkPubKeySize);
ResultCode DoWriteAntiBruteInfoToFile(uint64_t templateId);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // PINAUTHTA_ALL_IN_ONE_FUNC_H
