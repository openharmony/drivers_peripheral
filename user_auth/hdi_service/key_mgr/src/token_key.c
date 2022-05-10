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

#include "token_key.h"

#include <stddef.h>

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "buffer.h"
#include "defines.h"

#define SHA256_KEY_LEN 32

// This is for example only. Should be implemented in trusted environment.
static Buffer *g_tokenKey = NULL;

Buffer *GetTokenKey(void)
{
    return CopyBuffer(g_tokenKey);
}

ResultCode InitTokenKey(void)
{
    if (g_tokenKey != NULL) {
        return RESULT_SUCCESS;
    }
    g_tokenKey = CreateBufferBySize(SHA256_KEY_LEN);
    if (g_tokenKey == NULL) {
        LOG_ERROR("g_tokenKey: create buffer failed");
        return RESULT_NO_MEMORY;
    }
    if (SecureRandom(g_tokenKey->buf, g_tokenKey->maxSize) != RESULT_SUCCESS) {
        LOG_ERROR("get random failed");
        return RESULT_GENERAL_ERROR;
    }
    g_tokenKey->contentSize = g_tokenKey->maxSize;
    return RESULT_SUCCESS;
}