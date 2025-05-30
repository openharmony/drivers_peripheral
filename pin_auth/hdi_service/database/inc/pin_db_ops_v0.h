/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef PIN_DB_OPS_V0_H
#define PIN_DB_OPS_V0_H

#include <stdint.h>

#include "pin_db_ops_base.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define DB_VERSION_0 0

typedef struct {
    uint64_t templateId;
    uint64_t subType;
} __attribute__((__packed__)) PinInfoV0;

typedef struct {
    uint32_t authErrorCount;
    uint64_t startFreezeTime;
} __attribute__((__packed__)) AntiBruteInfoV0;

typedef struct {
    PinInfoV0 pinInfo;
    AntiBruteInfoV0 antiBruteInfo;
} __attribute__((__packed__)) PinIndexV0;

typedef struct {
    uint32_t version;
    uint32_t pinIndexLen;
    PinIndexV0 *pinIndex;
} __attribute__((__packed__)) PinDbV0;

void *GetPinDbV0(uint8_t *data, uint32_t dataLen);
void FreePinDbV0(void **pinDb);

void GetMaxLockedAntiBruteInfo(AntiBruteInfoV0 *antiBruteInfoV0);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif  // PIN_DB_OPS_V0_H