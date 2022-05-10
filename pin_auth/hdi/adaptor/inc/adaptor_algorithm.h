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

#ifndef ADAPTOR_ALGORITHM_H
#define ADAPTOR_ALGORITHM_H

#include <stdbool.h>
#include <stdint.h>
#include "buffer.h"

#define ED25519_FIX_SIGN_BUFFER_SIZE 64

typedef struct {
    Buffer *pubKey;
    Buffer *priKey;
} KeyPair;

bool IsEd25519KeyPairValid(const KeyPair *keyPair);
void DestoryKeyPair(KeyPair *keyPair);
KeyPair *GenerateEd25519KeyPair(void);
int32_t Ed25519Sign(const KeyPair *keyPair, const Buffer *data, Buffer **sign);
int32_t Ed25519Verify(const Buffer *pubKey, const Buffer *data, const Buffer *sign);

int32_t HmacSha256(const Buffer *hmacKey, const Buffer *data, Buffer **hmac);
int32_t HmacSha512(const Buffer *hmacKey, const Buffer *data, Buffer **hmac);

int32_t SecureRandom(uint8_t *buffer, uint32_t size);

#endif

