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

#ifndef USER_AUTH_FUNCS_H
#define USER_AUTH_FUNCS_H

#include "buffer.h"

#include "user_sign_centre.h"
#include "context_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AuthResult {
    int32_t freezingTime;
    int32_t remainTimes;
    int32_t result;
    Buffer *rootSecret;
} AuthResult;

int32_t GenerateSolutionFunc(AuthSolutionHal param, LinkedList **schedules);
int32_t RequestAuthResultFunc(uint64_t contextId, const Buffer *scheduleResult, UserAuthTokenHal *authToken,
    AuthResult *result);

#ifdef __cplusplus
}
#endif

#endif // USER_AUTH_FUNCS_H
