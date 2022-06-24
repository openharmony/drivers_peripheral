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

#include "ed25519_key.h"

#include <stddef.h>

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "buffer.h"
#include "defines.h"

static KeyPair *g_keyPair = NULL;

ResultCode GenerateKeyPair(void)
{
    DestoryKeyPair(g_keyPair);
    g_keyPair = GenerateEd25519KeyPair();
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        LOG_ERROR("GenerateEd25519Keypair fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

const Buffer *GetPriKey(void)
{
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        LOG_ERROR("g_keyPair is invalid");
        return NULL;
    }
    return g_keyPair->priKey;
}

const Buffer *GetPubKey(void)
{
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        LOG_ERROR("g_keyPair is invalid");
        return NULL;
    }
    return g_keyPair->pubKey;
}

void DestoryEd25519KeyPair(void)
{
    DestoryKeyPair(g_keyPair);
    g_keyPair = NULL;
}

Buffer *ExecutorMsgSign(const Buffer *data)
{
    if (!IsEd25519KeyPairValid(g_keyPair)) {
        return NULL;
    }
    Buffer *signatrue = NULL;
    int32_t ret = Ed25519Sign(g_keyPair, data, &signatrue);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("sign failed");
        return NULL;
    }
    return signatrue;
}