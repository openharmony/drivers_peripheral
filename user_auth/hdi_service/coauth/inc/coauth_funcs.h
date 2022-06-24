/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef COAUTH_FUNCS_H
#define COAUTH_FUNCS_H

#include "buffer.h"

#include "coauth.h"
#include "pool.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t RegisterExecutor(const ExecutorInfoHal *executorInfo, uint64_t *executorIndex);
int32_t UnRegisterExecutor(uint64_t executorIndex);

#ifdef __cplusplus
}
#endif

#endif // COAUTH_FUNCS_H
