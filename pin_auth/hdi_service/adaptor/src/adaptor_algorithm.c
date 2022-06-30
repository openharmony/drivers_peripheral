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

#include "adaptor_algorithm.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "buffer.h"
#include "defines.h"

#define OPENSSL_SUCCESS 1

#define ED25519_FIX_PRIKEY_BUFFER_SIZE 32
#define ED25519_FIX_PUBKEY_BUFFER_SIZE 32
#define ED25519_FIX_SIGN_BUFFER_SIZE 64

#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64

static KeyPair *CreateEd25519KeyPair(void)
{
    KeyPair *keyPair = Malloc(sizeof(KeyPair));
    if (keyPair == NULL) {
        LOG_ERROR("no memory for key pair");
        return NULL;
    }
    keyPair->pubKey = CreateBufferBySize(ED25519_FIX_PUBKEY_BUFFER_SIZE);
    if (keyPair->pubKey == NULL) {
        LOG_ERROR("no memory for pub key");
        Free(keyPair);
        return NULL;
    }
    keyPair->priKey = CreateBufferBySize(ED25519_FIX_PRIKEY_BUFFER_SIZE);
    if (keyPair->priKey == NULL) {
        LOG_ERROR("no memory for pri key");
        DestoryBuffer(keyPair->pubKey);
        Free(keyPair);
        return NULL;
    }
    return keyPair;
}

void DestoryKeyPair(KeyPair *keyPair)
{
    if (keyPair == NULL) {
        return;
    }
    if (keyPair->pubKey != NULL) {
        DestoryBuffer(keyPair->pubKey);
    }
    if (keyPair->priKey != NULL) {
        DestoryBuffer(keyPair->priKey);
    }
    Free(keyPair);
}

bool IsEd25519KeyPairValid(const KeyPair *keyPair)
{
    if (keyPair == NULL) {
        LOG_ERROR("invalid key pair");
        return false;
    }
    if (!CheckBufferWithSize(keyPair->pubKey, ED25519_FIX_PUBKEY_BUFFER_SIZE)) {
        LOG_ERROR("invalid pub key");
        return false;
    }
    if (!CheckBufferWithSize(keyPair->priKey, ED25519_FIX_PRIKEY_BUFFER_SIZE)) {
        LOG_ERROR("invalid pri key");
        return false;
    }
    return true;
}

KeyPair *GenerateEd25519KeyPair()
{
    KeyPair *keyPair = CreateEd25519KeyPair();
    if (keyPair == NULL) {
        LOG_ERROR("create key pair fail");
        return NULL;
    }
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) {
        LOG_ERROR("new ctx fail");
        goto ERROR;
    }
    if (EVP_PKEY_keygen_init(ctx) != OPENSSL_SUCCESS) {
        LOG_ERROR("init ctx fail");
        goto ERROR;
    }
    if (EVP_PKEY_keygen(ctx, &key) != OPENSSL_SUCCESS) {
        LOG_ERROR("generate key fail");
        goto ERROR;
    }
    size_t pubKeySize = keyPair->pubKey->maxSize;
    if (EVP_PKEY_get_raw_public_key(key, keyPair->pubKey->buf, &pubKeySize) != OPENSSL_SUCCESS) {
        LOG_ERROR("get pub key fail");
        goto ERROR;
    }
    keyPair->pubKey->contentSize = pubKeySize;
    size_t priKeySize = keyPair->priKey->maxSize;
    if (EVP_PKEY_get_raw_private_key(key, keyPair->priKey->buf, &priKeySize) != OPENSSL_SUCCESS) {
        LOG_ERROR("get pri key fail");
        goto ERROR;
    }
    keyPair->priKey->contentSize = priKeySize;
    goto EXIT;

ERROR:
    DestoryKeyPair(keyPair);
    keyPair = NULL;
EXIT:
    if (key != NULL) {
        EVP_PKEY_free(key);
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return keyPair;
}

int32_t Ed25519Sign(const KeyPair *keyPair, const Buffer *data, Buffer **sign)
{
    if (!IsEd25519KeyPairValid(keyPair) || !IsBufferValid(data) || sign == NULL) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    int32_t ret = RESULT_GENERAL_ERROR;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
        keyPair->priKey->buf, keyPair->priKey->contentSize);
    if (key == NULL) {
        LOG_ERROR("get pri key fail");
        return ret;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("get ctx fail");
        EVP_PKEY_free(key);
        return ret;
    }
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != OPENSSL_SUCCESS) {
        LOG_ERROR("init sign fail");
        goto EXIT;
    }
    *sign = CreateBufferBySize(ED25519_FIX_SIGN_BUFFER_SIZE);
    if (!IsBufferValid(*sign)) {
        LOG_ERROR("create buffer fail");
        goto EXIT;
    }
    size_t signSize = (*sign)->maxSize;
    if (EVP_DigestSign(ctx, (*sign)->buf, &signSize, data->buf, data->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("sign fail");
        DestoryBuffer(*sign);
        *sign = NULL;
        goto EXIT;
    }
    (*sign)->contentSize = signSize;
    ret = RESULT_SUCCESS;

EXIT:
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(ctx);
    return ret;
}

int32_t Ed25519Verify(const Buffer *pubKey, const Buffer *data, const Buffer *sign)
{
    if (!CheckBufferWithSize(pubKey, ED25519_FIX_PUBKEY_BUFFER_SIZE) || !IsBufferValid(data) ||
        !CheckBufferWithSize(sign, ED25519_FIX_SIGN_BUFFER_SIZE)) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    int32_t ret = RESULT_GENERAL_ERROR;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubKey->buf, pubKey->contentSize);
    if (key == NULL) {
        LOG_ERROR("get pub key fail");
        return ret;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("get ctx fail");
        EVP_PKEY_free(key);
        return ret;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != OPENSSL_SUCCESS) {
        LOG_ERROR("init verify fail");
        goto EXIT;
    }
    if (EVP_DigestVerify(ctx, sign->buf, sign->contentSize, data->buf, data->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("verify fail");
        goto EXIT;
    }
    ret = RESULT_SUCCESS;

EXIT:
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int32_t IamHmac(const EVP_MD *alg,
    const Buffer *hmacKey, const Buffer *data, Buffer *hmac)
{
    if (!IsBufferValid(hmacKey) || hmacKey->contentSize > INT_MAX ||
        !IsBufferValid(data) || !IsBufferValid(hmac) || hmac->maxSize > UINT_MAX) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    unsigned int hmacSize = hmac->maxSize;
    uint8_t *hmacData = HMAC(alg, hmacKey->buf, (int)hmacKey->contentSize, data->buf, data->contentSize,
        hmac->buf, &hmacSize);
    if (hmacData == NULL) {
        LOG_ERROR("hmac fail");
        return RESULT_GENERAL_ERROR;
    }
    hmac->contentSize = hmacSize;
    return RESULT_SUCCESS;
}

int32_t HmacSha256(const Buffer *hmacKey, const Buffer *data, Buffer **hmac)
{
    const EVP_MD *alg = EVP_sha256();
    if (alg == NULL) {
        LOG_ERROR("no algo");
        return RESULT_GENERAL_ERROR;
    }
    *hmac = CreateBufferBySize(SHA256_DIGEST_SIZE);
    if (*hmac == NULL) {
        LOG_ERROR("create buffer fail");
        return RESULT_NO_MEMORY;
    }
    if (IamHmac(alg, hmacKey, data, *hmac) != RESULT_SUCCESS) {
        DestoryBuffer(*hmac);
        *hmac = NULL;
        LOG_ERROR("hmac fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

int32_t HmacSha512(const Buffer *hmacKey, const Buffer *data, Buffer **hmac)
{
    const EVP_MD *alg = EVP_sha512();
    if (alg == NULL) {
        LOG_ERROR("no algo");
        return RESULT_GENERAL_ERROR;
    }
    *hmac = CreateBufferBySize(SHA512_DIGEST_SIZE);
    if (*hmac == NULL) {
        LOG_ERROR("create buffer fail");
        return RESULT_NO_MEMORY;
    }
    if (IamHmac(alg, hmacKey, data, *hmac) != RESULT_SUCCESS) {
        DestoryBuffer(*hmac);
        *hmac = NULL;
        LOG_ERROR("hmac fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

int32_t SecureRandom(uint8_t *buffer, uint32_t size)
{
    if (buffer == NULL || size > INT_MAX) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    if (RAND_bytes(buffer, (int)size) != OPENSSL_SUCCESS) {
        LOG_ERROR("rand fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}