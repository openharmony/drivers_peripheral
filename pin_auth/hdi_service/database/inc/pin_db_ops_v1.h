/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PIN_DB_OPS_V1_H
#define PIN_DB_OPS_V1_H

#include "pin_db_ops_base.h"
#include "pin_db_ops_v0.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define DB_VERSION_1 1
#define ALGORITHM_VERSION_0 0
#define ALGORITHM_VERSION_1 1
#define PIN_LENGTH_DEFAULT 0

typedef struct {
    uint32_t algoVersion;
    uint64_t templateId;
    uint64_t subType;
    uint32_t pinLength;
} __attribute__((__packed__)) PinInfoV1;

typedef struct {
    PinInfoV1 pinInfo;
    AntiBruteInfoV0 antiBruteInfo;
} __attribute__((__packed__)) PinIndexV1;

typedef struct {
    uint32_t dbVersion;
    uint32_t pinIndexLen;
    PinIndexV1 *pinIndex;
} __attribute__((__packed__)) PinDbV1;

void *UpdatePinDbFrom0To1(void *pinDbV0);
void *GetPinDbV1(uint8_t *data, uint32_t dataLen);
void FreePinDbV1(void **pinDb);
ResultCode WritePinDbV1(void *pinDb);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif  // PIN_DB_OPS_V1_H