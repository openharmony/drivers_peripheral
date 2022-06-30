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

#ifndef USERIAM_IDENTIFY_FUNCS_H
#define USERIAM_IDENTIFY_FUNCS_H

#include "buffer.h"
#include "coauth.h"
#include "context_manager.h"
#include "user_sign_centre.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t DoIdentify(const IdentifyParam param, LinkedList **schedule);
int32_t DoUpdateIdentify(uint64_t contextId, const Buffer *scheduleResult, int32_t *userId, UserAuthTokenHal *token,
    int32_t *result);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_IDENTIFY_FUNCS_H