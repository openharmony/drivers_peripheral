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

#ifndef ADAPTOR_ALGORITHM_H
#define ADAPTOR_ALGORITHM_H

#include <stdbool.h>
#include <stdint.h>
#include "securec.h"
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ED25519_FIX_SIGN_BUFFER_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define AES_GCM_TAG_SIZE 16
#define AES_GCM_IV_SIZE 12

#define USER_AUTH_DISTRIBUTE_DEVICE_KEY "USER_AUTH_DISTRIBUTED_DEVICE_KEY"
#define USER_AUTH_DISTRIBUTE_DEVICE_KEY_SIZE 32

typedef struct {
    Buffer *pubKey;
    Buffer *priKey;
} KeyPair;

typedef struct {
    Buffer *key;
    Buffer *iv;
    Buffer *aad;
} AesGcmParam;

bool IsEd25519KeyPairValid(const KeyPair *keyPair);
void DestoryKeyPair(KeyPair *keyPair);
KeyPair *GenerateEd25519KeyPair(void);
int32_t Ed25519Sign(const KeyPair *keyPair, const Buffer *data, Buffer **sign);
int32_t Ed25519Verify(const Buffer *pubKey, const Buffer *data, const Buffer *sign);

int32_t HmacSha256(const Buffer *hmacKey, const Buffer *data, Buffer **hmac);
int32_t SecureRandom(uint8_t *buffer, uint32_t size);

int32_t AesGcmEncrypt(const Buffer *plaintext, const AesGcmParam *aesGcmParam, Buffer **ciphertext, Buffer **tag);
int32_t AesGcmDecrypt(const Buffer *ciphertext, const AesGcmParam *aesGcmParam, const Buffer *tag, Buffer **plaintext);
int32_t GetDistributeKey(const Buffer *peerUdid, const Buffer *salt, Buffer **key);

#ifdef __cplusplus
}
#endif

#endif

