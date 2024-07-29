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

#ifndef USERIAM_AUTH_TOKEN_SIGNER_H
#define USERIAM_AUTH_TOKEN_SIGNER_H

#include "context_manager.h"
#include "user_sign_centre.h"

#ifdef __cplusplus
extern "C" {
#endif

ResultCode GetAuthTokenDataAndSign(
    const UserAuthContext *context, uint64_t credentialId, uint32_t authMode, UserAuthTokenHal *authToken);

#ifdef __cplusplus
}
#endif

#endif // USERIAM_AUTH_TOKEN_SIGNER_H