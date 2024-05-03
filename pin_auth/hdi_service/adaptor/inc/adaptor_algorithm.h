/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define ED25519_FIX_SIGN_BUFFER_SIZE 64
#define ED25519_FIX_PUBKEY_BUFFER_SIZE 32
#define SECRET_SIZE 32
#define HKDF_SALT_SIZE 32
#define HKDF_KEY_SIZE 32
#define AES_GCM_256_KEY_SIZE 32
#define AES_GCM_256_IV_SIZE 12
#define AES_GCM_256_TAG_SIZE 16
#define AES_GCM_256_AAD_MAX_SIZE 32
#define CIPHER_INFO_MAX_SIZE 1024
#define SHA256_DIGEST_SIZE 32

typedef struct KeyPair {
    Buffer *pubKey;
    Buffer *priKey;
} KeyPair;

typedef struct AesGcmParam {
    Buffer *aad;
    Buffer *iv;
    Buffer *key;
} AesGcmParam;

bool IsEd25519KeyPairValid(const KeyPair *keyPair);
void DestroyKeyPair(KeyPair *keyPair);
KeyPair *GenerateEd25519KeyPair(void);
int32_t Ed25519Sign(const KeyPair *keyPair, const Buffer *data, Buffer **sign);
int32_t Ed25519Verify(const Buffer *pubKey, const Buffer *data, const Buffer *sign);

int32_t AesGcm256Encrypt(const Buffer *plaintext, const AesGcmParam *param, Buffer **ciphertext, Buffer **tag);
int32_t AesGcm256Decrypt(const Buffer *ciphertext, const AesGcmParam *param, const Buffer *tag, Buffer **plaintext);

Buffer *DeriveDeviceKey(const Buffer *pinData, const Buffer *secret);
Buffer *Hkdf(const Buffer *salt, const Buffer *rootKey);
Buffer *Sha256Adaptor(const Buffer *data);

int32_t HmacSha256(const Buffer *hmacKey, const Buffer *data, Buffer **hmac);
int32_t HmacSha512(const Buffer *hmacKey, const Buffer *data, Buffer **hmac);

int32_t SecureRandom(uint8_t *buffer, uint32_t size);

/* This is for example only, distribute key should be distributed in trusted environment between devices. */
int32_t GetDistributeKey(const Buffer *peerUdid, const Buffer *salt, Buffer **key);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // ADAPTOR_ALGORITHM_H

