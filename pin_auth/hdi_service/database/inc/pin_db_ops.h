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

#ifndef PIN_DB_OPS_H
#define PIN_DB_OPS_H

#include "defines.h"
#include "pin_db_ops_v1.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef PinDbV1 PinDb;
typedef PinIndexV1 PinIndex;
typedef PinInfoV1 PinInfo;

PinDbV1 *ReadPinDb(void);
ResultCode WritePinDb(PinDbV1 *pinDbV1);
void FreePinDb(PinDbV1 **pinDbV1);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif  // PIN_DB_OPS_H