/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef UDID_MANAGER_H
#define UDID_MANAGER_H

#include <stdint.h>

#include "buffer.h"
#include "c_array.h"
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

bool SetLocalUdid(const char* udid);
bool GetLocalUdid(Uint8Array *udid);
Buffer GetLocalUdidTmpBuffer();
bool IsLocalUdid(Uint8Array udid);

#ifdef __cplusplus
}
#endif

#endif // UDID_MANAGER_H