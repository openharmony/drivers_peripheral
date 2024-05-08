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

#ifndef PINAUTHTA_COLLECTOR_FUNC_H
#define PINAUTHTA_COLLECTOR_FUNC_H

#include "executor_func_common.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int32_t GenerateCollectorKeyPair(void);
void DestroyCollectorKeyPair(void);
int32_t DoGetCollectorExecutorInfo(PinExecutorInfo *pinExecutorInfo);
int32_t DoSetCollectorFwkParam(const uint8_t *fwkPubKey, uint32_t fwkPubKeySize);
int32_t DoCollect(
    uint64_t scheduleId, const uint8_t *extraInfo, uint32_t extraInfoSize, uint8_t *msg, uint32_t *msgSize);
int32_t DoCancelCollect();
int32_t DoSendMessageToCollector(uint64_t scheduleId, const uint8_t *msg, uint32_t msgSize, AlgoParamOut *algoParam);
int32_t DoSetDataToCollector(
    uint64_t scheduleId, uint8_t *pinData, const uint32_t pinDataSize, uint8_t *msg, uint32_t *msgSize);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // PINAUTHTA_COLLECTOR_FUNC_H
