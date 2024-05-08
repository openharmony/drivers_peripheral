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

#include "adaptor_algorithm.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include "securec.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "buffer.h"
#include "defines.h"

#define OPENSSL_SUCCESS 1

#define ED25519_FIX_PRIKEY_BUFFER_SIZE 32

#define SHA512_DIGEST_SIZE 64
#define NO_PADDING 0

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
        DestroyBuffer(keyPair->pubKey);
        Free(keyPair);
        return NULL;
    }
    return keyPair;
}

void DestroyKeyPair(KeyPair *keyPair)
{
    if (keyPair == NULL) {
        return;
    }
    if (keyPair->pubKey != NULL) {
        DestroyBuffer(keyPair->pubKey);
    }
    if (keyPair->priKey != NULL) {
        DestroyBuffer(keyPair->priKey);
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

KeyPair *GenerateEd25519KeyPair(void)
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
    DestroyKeyPair(keyPair);
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
        DestroyBuffer(*sign);
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
        DestroyBuffer(*hmac);
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
        DestroyBuffer(*hmac);
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

// Here is the piling code. The real implementation needs to call the security interface.
Buffer *DeriveDeviceKey(const Buffer *pinData, const Buffer *secret)
{
    if (!IsBufferValid(secret) || secret->contentSize != SECRET_SIZE || !IsBufferValid(pinData)) {
        LOG_ERROR("bad param");
        return NULL;
    }
    return CopyBuffer(secret);
}

Buffer *Hkdf(const Buffer *salt, const Buffer *rootKey)
{
    if (!IsBufferValid(salt) || salt->contentSize != HKDF_SALT_SIZE ||
        !IsBufferValid(rootKey) || rootKey->contentSize != HKDF_KEY_SIZE) {
        LOG_ERROR("bad param");
        return NULL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (ctx == NULL) {
        LOG_ERROR("pctx is null");
        return NULL;
    }
    Buffer *key = CreateBufferBySize(SHA256_DIGEST_SIZE);
    if (!IsBufferValid(key)) {
        LOG_ERROR("failed to create buffer");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    size_t outLen = SHA256_DIGEST_SIZE;
    if (EVP_PKEY_derive_init(ctx) != OPENSSL_SUCCESS ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != OPENSSL_SUCCESS ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt->buf, salt->contentSize) != OPENSSL_SUCCESS ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, rootKey->buf, rootKey->contentSize) != OPENSSL_SUCCESS ||
        EVP_PKEY_derive(ctx, key->buf, &outLen) != OPENSSL_SUCCESS ||
        outLen > key->maxSize) {
        LOG_ERROR("failed to call algorithm interface");
        DestroyBuffer(key);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    key->contentSize = outLen;
    EVP_PKEY_CTX_free(ctx);
    return key;
}

Buffer *Sha256Adaptor(const Buffer *data)
{
    if (!IsBufferValid(data)) {
        LOG_ERROR("bad param");
        return NULL;
    }
    Buffer *result = CreateBufferBySize(SHA256_DIGEST_SIZE);
    if (!IsBufferValid(result)) {
        LOG_ERROR("failed to create buffer");
        return NULL;
    }
    if (SHA256(data->buf, data->contentSize, result->buf) != result->buf) {
        LOG_ERROR("failed to do sha256");
        DestroyBuffer(result);
        return NULL;
    }
    result->contentSize = SHA256_DIGEST_SIZE;
    return result;
}

#define REMOTE_PIN_DISTRIBUTE_DEVICE_KEY "REMOTE_PIN_DISTRIBUTE_DEVICE_KEY"
#define REMOTE_PIN_DISTRIBUTE_DEVICE_KEY_SIZE 32

/* This is for example only, distribute key should be distributed in trusted environment between devices. */
int32_t GetDistributeKey(const Buffer *peerUdid, const Buffer *salt, Buffer **key)
{
    if (!IsBufferValid(peerUdid) || !IsBufferValid(salt) || (key == NULL)) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    Buffer *keyData = CreateBufferBySize(salt->contentSize + REMOTE_PIN_DISTRIBUTE_DEVICE_KEY_SIZE);
    if (keyData == NULL) {
        LOG_ERROR("CreateBufferBySize keyData fail");
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(keyData->buf, keyData->maxSize,
        REMOTE_PIN_DISTRIBUTE_DEVICE_KEY, REMOTE_PIN_DISTRIBUTE_DEVICE_KEY_SIZE) != EOK) {
        LOG_ERROR("copy fix tag fail");
        DestroyBuffer(keyData);
        return RESULT_NO_MEMORY;
    }
    keyData->contentSize += REMOTE_PIN_DISTRIBUTE_DEVICE_KEY_SIZE;
    if (memcpy_s(keyData->buf + keyData->contentSize,
        keyData->maxSize - keyData->contentSize, salt->buf, salt->contentSize) != EOK) {
        LOG_ERROR("copy salt fail");
        DestroyBuffer(keyData);
        return RESULT_NO_MEMORY;
    }
    keyData->contentSize += salt->contentSize;
    *key = Sha256Adaptor(keyData);
    DestroyBuffer(keyData);
    if (*key == NULL) {
        LOG_ERROR("calculate key fail");
        return RESULT_NO_MEMORY;
    }
    return RESULT_SUCCESS;
}

static bool CheckAes256GcmParams(const AesGcmParam *param)
{
    if (param == NULL) {
        LOG_ERROR("get null AesGcmParam");
        return false;
    }
    if (!CheckBufferWithSize(param->key, AES_GCM_256_KEY_SIZE)) {
        LOG_ERROR("invalid key");
        return false;
    }
    if (!CheckBufferWithSize(param->iv, AES_GCM_256_IV_SIZE)) {
        LOG_ERROR("invalid iv");
        return false;
    }
    if (param->aad == NULL) {
        LOG_INFO("get null aad");
        return true;
    }
    if (!IsBufferValid(param->aad)) {
        LOG_ERROR("invalid aad");
        return false;
    }
    if ((param->aad->contentSize == 0) || (param->aad->contentSize > AES_GCM_256_AAD_MAX_SIZE)) {
        LOG_ERROR("invalid aad size");
        return false;
    }
    return true;
}

static bool SetAesEncryptParam(EVP_CIPHER_CTX *ctx, const AesGcmParam *param)
{
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, param->key->buf, NULL) != OPENSSL_SUCCESS) {
        LOG_ERROR("EVP_EncryptInit_ex fail");
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, param->iv->contentSize, NULL) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set iv len");
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, param->iv->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to init iv");
        return false;
    }
    if (EVP_CIPHER_CTX_set_padding(ctx, NO_PADDING) != OPENSSL_SUCCESS) {
        LOG_ERROR("set padding fail");
        return false;
    }
    int outLen = 0;
    if ((param->aad != NULL) &&
        (EVP_EncryptUpdate(ctx, NULL, &outLen, param->aad->buf, param->aad->contentSize) != OPENSSL_SUCCESS)) {
        LOG_ERROR("set aad fail");
        return false;
    }
    return true;
}

static bool DoAesEncrypt(EVP_CIPHER_CTX *ctx, const Buffer *plaintext, Buffer **ciphertext, Buffer **tag)
{
    *ciphertext = CreateBufferBySize(plaintext->contentSize);
    *tag = CreateBufferBySize(AES_GCM_256_TAG_SIZE);
    if ((*ciphertext == NULL) || (*tag == NULL)) {
        LOG_ERROR("create cipher fail");
        goto ERROR;
    }

    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, (*ciphertext)->buf, &outLen,
        plaintext->buf, plaintext->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to update");
        goto ERROR;
    }
    if ((outLen < 0) || ((uint32_t)outLen > (*ciphertext)->maxSize)) {
        LOG_ERROR("outLen out of range");
        goto ERROR;
    }
    (*ciphertext)->contentSize = (uint32_t)outLen;
    if (EVP_EncryptFinal_ex(ctx, (*ciphertext)->buf + (*ciphertext)->contentSize, &outLen) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to finish");
        goto ERROR;
    }
    if ((outLen < 0) || ((uint32_t)outLen > ((*ciphertext)->maxSize) - (*ciphertext)->contentSize)) {
        LOG_ERROR("final outLen out of range");
        goto ERROR;
    }
    (*ciphertext)->contentSize += (uint32_t)outLen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AES_GCM_256_TAG_SIZE, (*tag)->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to get tag");
        goto ERROR;
    }
    (*tag)->contentSize = AES_GCM_256_TAG_SIZE;
    return true;

ERROR:
    DestroyBuffer(*ciphertext);
    *ciphertext = NULL;
    DestroyBuffer(*tag);
    *tag = NULL;
    return false;
}

int32_t AesGcm256Encrypt(const Buffer *plaintext, const AesGcmParam *param, Buffer **ciphertext, Buffer **tag)
{
    if (!IsBufferValid(plaintext) ||
        (plaintext->contentSize == 0) ||(plaintext->contentSize > CIPHER_INFO_MAX_SIZE) ||
        !CheckAes256GcmParams(param) || (ciphertext == NULL) || (tag == NULL)) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }

    int result = RESULT_GENERAL_ERROR;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("get ctx fail");
        return result;
    }
    if (!SetAesEncryptParam(ctx, param)) {
        LOG_ERROR("SetAesEncryptParam fail");
        goto EXIT;
    }
    if (!DoAesEncrypt(ctx, plaintext, ciphertext, tag)) {
        LOG_ERROR("DoAesEncrypt fail");
        goto EXIT;
    }
    result = RESULT_SUCCESS;

EXIT:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

static bool SetAesDecryptParam(EVP_CIPHER_CTX *ctx, const AesGcmParam *param)
{
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, param->key->buf, NULL) != OPENSSL_SUCCESS) {
        LOG_ERROR("EVP_DecryptInit_ex fail");
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, param->iv->contentSize, NULL) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set iv len");
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, param->iv->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to init iv");
        return false;
    }
    if (EVP_CIPHER_CTX_set_padding(ctx, NO_PADDING) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set padding");
        return false;
    }
    int outLen = 0;
    if ((param->aad != NULL) &&
        (EVP_DecryptUpdate(ctx, NULL, &outLen, param->aad->buf, param->aad->contentSize) != OPENSSL_SUCCESS)) {
        LOG_ERROR("set aad fail");
        return false;
    }
    return true;
}

static bool DoAesDecrypt(EVP_CIPHER_CTX *ctx, const Buffer *ciphertext, const Buffer *tag, Buffer **plaintext)
{
    *plaintext = CreateBufferBySize(ciphertext->contentSize);
    if (*plaintext == NULL) {
        LOG_ERROR("create plain fail");
        goto ERROR;
    }

    int outLen = 0;
    if (EVP_DecryptUpdate(ctx, (*plaintext)->buf, &outLen,
        ciphertext->buf, ciphertext->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to update");
        goto ERROR;
    }
    if ((outLen < 0) || ((uint32_t)outLen > (*plaintext)->maxSize)) {
        LOG_ERROR("outLen out of range");
        goto ERROR;
    }
    (*plaintext)->contentSize = (uint32_t)outLen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag->contentSize, tag->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set tag");
        goto ERROR;
    }
    if (EVP_DecryptFinal_ex(ctx, (*plaintext)->buf + (*plaintext)->contentSize, &outLen) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to finish");
        goto ERROR;
    }
    if ((outLen < 0) || ((uint32_t)outLen > ((*plaintext)->maxSize) - (*plaintext)->contentSize)) {
        LOG_ERROR("final outLen out of range");
        goto ERROR;
    }
    (*plaintext)->contentSize += (uint32_t)outLen;
    return true;

ERROR:
    DestroyBuffer(*plaintext);
    *plaintext = NULL;
    return false;
}

int32_t AesGcm256Decrypt(const Buffer *ciphertext, const AesGcmParam *param, const Buffer *tag, Buffer **plaintext)
{
    if (!IsBufferValid(ciphertext) ||
        (ciphertext->contentSize == 0) ||(ciphertext->contentSize > CIPHER_INFO_MAX_SIZE) ||
        !CheckAes256GcmParams(param) || !CheckBufferWithSize(tag, AES_GCM_256_TAG_SIZE) || (plaintext == NULL)) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }

    int result = RESULT_GENERAL_ERROR;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("get ctx fail");
        return result;
    }
    if (!SetAesDecryptParam(ctx, param)) {
        LOG_ERROR("SetAesEncryptParam fail");
        goto EXIT;
    }
    if (!DoAesDecrypt(ctx, ciphertext, tag, plaintext)) {
        LOG_ERROR("DoAesEncrypt fail");
        goto EXIT;
    }
    result = RESULT_SUCCESS;

EXIT:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}