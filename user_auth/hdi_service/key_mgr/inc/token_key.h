/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef USER_IAM_TOKEN_KEY
#define USER_IAM_TOKEN_KEY

#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HKS_DEFAULT_USER_AT_KEY_LEN 32
typedef struct HksAuthTokenKey {
    uint8_t macKey[HKS_DEFAULT_USER_AT_KEY_LEN];
    uint8_t cipherKey[HKS_DEFAULT_USER_AT_KEY_LEN];
} HksAuthTokenKey;

ResultCode GetTokenKey(HksAuthTokenKey *key);

#ifdef __cplusplus
}
#endif

#endif