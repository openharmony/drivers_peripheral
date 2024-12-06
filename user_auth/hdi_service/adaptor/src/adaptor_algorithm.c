/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <openssl/sha.h>
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "buffer.h"
#include "defines.h"

#define OPENSSL_SUCCESS 1

#define ED25519_FIX_PRIKEY_BUFFER_SIZE 32
#define ED25519_FIX_PUBKEY_BUFFER_SIZE 32

#define SHA512_DIGEST_SIZE 64

#define AES_GCM_TEXT_MAX_SIZE 1000
#define AES_GCM_AAD_MAX_SIZE 32
#define AES_GCM_256_KEY_SIZE 32
#define NO_PADDING 0

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

IAM_STATIC KeyPair *CreateEd25519KeyPair(void)
{
    KeyPair *keyPair = Malloc(sizeof(KeyPair));
    if (keyPair == NULL) {
        LOG_ERROR("no memory for key pair");
        return NULL;
    }
    keyPair->pubKey = CreateBufferBySize(ED25519_FIX_PUBKEY_BUFFER_SIZE);
    if (keyPair->pubKey == NULL) {
        LOG_ERROR("no memory for public key");
        Free(keyPair);
        return NULL;
    }
    keyPair->priKey = CreateBufferBySize(ED25519_FIX_PRIKEY_BUFFER_SIZE);
    if (keyPair->priKey == NULL) {
        LOG_ERROR("no memory for private key");
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
        LOG_ERROR("invalid public key");
        return false;
    }
    if (!CheckBufferWithSize(keyPair->priKey, ED25519_FIX_PRIKEY_BUFFER_SIZE)) {
        LOG_ERROR("invalid private key");
        return false;
    }
    return true;
}

KeyPair *GenerateEd25519KeyPair(void)
{
    KeyPair *keyPair = CreateEd25519KeyPair();
    if (keyPair == NULL) {
        LOG_ERROR("create key pair failed");
        return NULL;
    }
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) {
        LOG_ERROR("new ctx failed");
        goto ERROR;
    }
    if (EVP_PKEY_keygen_init(ctx) != OPENSSL_SUCCESS) {
        LOG_ERROR("init ctx failed");
        goto ERROR;
    }
    if (EVP_PKEY_keygen(ctx, &key) != OPENSSL_SUCCESS) {
        LOG_ERROR("generate key failed");
        goto ERROR;
    }
    size_t pubKeySize = keyPair->pubKey->maxSize;
    if (EVP_PKEY_get_raw_public_key(key, keyPair->pubKey->buf, &pubKeySize) != OPENSSL_SUCCESS) {
        LOG_ERROR("get public key failed");
        goto ERROR;
    }
    keyPair->pubKey->contentSize = pubKeySize;
    size_t priKeySize = keyPair->priKey->maxSize;
    if (EVP_PKEY_get_raw_private_key(key, keyPair->priKey->buf, &priKeySize) != OPENSSL_SUCCESS) {
        LOG_ERROR("get private key failed");
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
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    int32_t ret = RESULT_GENERAL_ERROR;
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
        keyPair->priKey->buf, keyPair->priKey->contentSize);
    if (key == NULL) {
        LOG_ERROR("get private key failed");
        return ret;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("get ctx failed");
        EVP_PKEY_free(key);
        return ret;
    }
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != OPENSSL_SUCCESS) {
        LOG_ERROR("init sign failed");
        goto EXIT;
    }
    *sign = CreateBufferBySize(ED25519_FIX_SIGN_BUFFER_SIZE);
    if (!IsBufferValid(*sign)) {
        LOG_ERROR("create buffer failed");
        goto EXIT;
    }
    size_t signSize = (*sign)->maxSize;
    if (EVP_DigestSign(ctx, (*sign)->buf, &signSize, data->buf, data->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("sign failed");
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
        LOG_ERROR("get public key failed");
        return ret;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("get ctx failed");
        EVP_PKEY_free(key);
        return ret;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != OPENSSL_SUCCESS) {
        LOG_ERROR("init verify failed");
        goto EXIT;
    }
    if (EVP_DigestVerify(ctx, sign->buf, sign->contentSize, data->buf, data->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("verify failed");
        goto EXIT;
    }
    ret = RESULT_SUCCESS;

EXIT:
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(ctx);
    return ret;
}

IAM_STATIC int32_t IamHmac(const EVP_MD *alg, const Buffer *hmacKey, const Buffer *data, Buffer *hmac)
{
    if (!IsBufferValid(hmacKey) || hmacKey->contentSize > INT_MAX ||
        !IsBufferValid(data) || !IsBufferValid(hmac) || hmac->maxSize > UINT_MAX) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    uint32_t hmacSize = hmac->maxSize;
    uint8_t *hmacData = HMAC(alg, hmacKey->buf, (int)hmacKey->contentSize, data->buf, data->contentSize,
        hmac->buf, &hmacSize);
    if (hmacData == NULL) {
        LOG_ERROR("hmac failed");
        return RESULT_GENERAL_ERROR;
    }
    hmac->contentSize = hmacSize;
    return RESULT_SUCCESS;
}

int32_t HmacSha256(const Buffer *hmacKey, const Buffer *data, Buffer **hmac)
{
    if (hmac == NULL) {
        LOG_ERROR("hmac is null");
        return RESULT_BAD_PARAM;
    }
    const EVP_MD *alg = EVP_sha256();
    if (alg == NULL) {
        LOG_ERROR("no algo");
        return RESULT_GENERAL_ERROR;
    }
    *hmac = CreateBufferBySize(SHA256_DIGEST_SIZE);
    if (*hmac == NULL) {
        LOG_ERROR("create buffer failed");
        return RESULT_NO_MEMORY;
    }
    if (IamHmac(alg, hmacKey, data, *hmac) != RESULT_SUCCESS) {
        DestoryBuffer(*hmac);
        *hmac = NULL;
        LOG_ERROR("hmac failed");
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
        LOG_ERROR("rand failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC bool CheckAesGcmParam(const AesGcmParam *aesGcmParam)
{
    if (aesGcmParam == NULL) {
        LOG_ERROR("get null AesGcmParam");
        return false;
    }
    if (!CheckBufferWithSize(aesGcmParam->key, AES_GCM_256_KEY_SIZE)) {
        LOG_ERROR("invalid key");
        return false;
    }
    if (!CheckBufferWithSize(aesGcmParam->iv, AES_GCM_IV_SIZE)) {
        LOG_ERROR("invalid iv");
        return false;
    }
    if (aesGcmParam->aad == NULL) {
        LOG_INFO("get null aad");
        return true;
    }
    if (!IsBufferValid(aesGcmParam->aad)) {
        return false;
    }
    if (aesGcmParam->aad->contentSize == 0 || aesGcmParam->aad->contentSize > AES_GCM_AAD_MAX_SIZE) {
        LOG_ERROR("invalid aad");
        return false;
    }
    return true;
}

static bool SetAesEncryptParam(EVP_CIPHER_CTX *ctx, const AesGcmParam *aesGcmParam)
{
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)aesGcmParam->key->buf, NULL) !=
        OPENSSL_SUCCESS) {
        LOG_ERROR("failed to init ctx");
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, aesGcmParam->iv->contentSize, NULL) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set iv len");
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, aesGcmParam->iv->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to init iv");
        return false;
    }
    if (aesGcmParam->aad != NULL) {
        int out;
        if (EVP_EncryptUpdate(ctx, NULL, &out,
            (unsigned char *)(aesGcmParam->aad->buf), aesGcmParam->aad->contentSize) != OPENSSL_SUCCESS) {
            LOG_ERROR("failed to update aad");
            return false;
        }
    }
    if (EVP_CIPHER_CTX_set_padding(ctx, NO_PADDING) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set padding");
        return false;
    }
    return true;
}

int32_t AesGcmEncrypt(const Buffer *plaintext, const AesGcmParam *aesGcmParam, Buffer **ciphertext, Buffer **tag)
{
    if (!IsBufferValid(plaintext) ||
        plaintext->contentSize == 0 || plaintext->contentSize > AES_GCM_TEXT_MAX_SIZE ||
        !CheckAesGcmParam(aesGcmParam) || ciphertext == NULL || tag == NULL) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    (*ciphertext) = CreateBufferBySize(plaintext->contentSize);
    (*tag) = CreateBufferBySize(AES_GCM_TAG_SIZE);
    if (ctx == NULL || (*ciphertext) == NULL || (*tag) == NULL) {
        LOG_ERROR("init fail");
        goto FAIL;
    }
    if (!SetAesEncryptParam(ctx, aesGcmParam)) {
        LOG_ERROR("SetAesEncryptParam fail");
        goto FAIL;
    }
    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, (unsigned char *)((*ciphertext)->buf), &outLen,
        (unsigned char *)plaintext->buf, plaintext->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to update");
        goto FAIL;
    }
    if (outLen < 0 || (uint32_t)outLen > (*ciphertext)->maxSize) {
        LOG_ERROR("outLen out of range");
        goto FAIL;
    }
    (*ciphertext)->contentSize = (uint32_t)outLen;
    if (EVP_EncryptFinal_ex(ctx, NULL, &outLen) != OPENSSL_SUCCESS || outLen != 0) { // no padding no out
        LOG_ERROR("failed to finish");
        goto FAIL;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, (*tag)->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to get tag");
        goto FAIL;
    }
    (*tag)->contentSize = AES_GCM_TAG_SIZE;
    EVP_CIPHER_CTX_free(ctx);
    return RESULT_SUCCESS;
FAIL:
    DestoryBuffer(*tag);
    *tag = NULL;
    DestoryBuffer(*ciphertext);
    *ciphertext = NULL;
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return RESULT_GENERAL_ERROR;
}

static bool SetAesDecryptParam(EVP_CIPHER_CTX *ctx, const AesGcmParam *aesGcmParam)
{
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)aesGcmParam->key->buf, NULL) !=
        OPENSSL_SUCCESS) {
        LOG_ERROR("failed to init ctx");
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, aesGcmParam->iv->contentSize, NULL) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set iv len");
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, aesGcmParam->iv->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to init iv");
        return false;
    }
    if (aesGcmParam->aad != NULL) {
        int out;
        if (EVP_DecryptUpdate(ctx, NULL, &out,
            (unsigned char *)(aesGcmParam->aad->buf), aesGcmParam->aad->contentSize) != OPENSSL_SUCCESS) {
            LOG_ERROR("failed to update aad");
            return false;
        }
    }
    if (EVP_CIPHER_CTX_set_padding(ctx, NO_PADDING) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set padding");
        return false;
    }
    return true;
}

int32_t AesGcmDecrypt(const Buffer *ciphertext, const AesGcmParam *aesGcmParam, const Buffer *tag, Buffer **plaintext)
{
    if (!IsBufferValid(ciphertext) ||
        ciphertext->contentSize == 0 || ciphertext->contentSize > AES_GCM_TEXT_MAX_SIZE ||
        !CheckAesGcmParam(aesGcmParam) || !CheckBufferWithSize(tag, AES_GCM_TAG_SIZE) || plaintext == NULL) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    (*plaintext) = CreateBufferBySize(ciphertext->contentSize);
    if (ctx == NULL || (*plaintext) == NULL) {
        LOG_ERROR("init fail");
        goto FAIL;
    }
    if (!SetAesDecryptParam(ctx, aesGcmParam)) {
        LOG_ERROR("SetAesEncryptParam fail");
        goto FAIL;
    }
    int outLen = 0;
    if (EVP_DecryptUpdate(ctx, (unsigned char *)((*plaintext)->buf), &outLen,
        (unsigned char *)ciphertext->buf, ciphertext->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to update");
        goto FAIL;
    }
    if (outLen < 0 || (uint32_t)outLen > (*plaintext)->maxSize) {
        LOG_ERROR("outLen out of range");
        goto FAIL;
    }
    (*plaintext)->contentSize = (uint32_t)outLen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to get tag");
        goto FAIL;
    }
    if (EVP_DecryptFinal_ex(ctx, NULL, &outLen) != OPENSSL_SUCCESS || outLen != 0) { // no padding no out
        LOG_ERROR("failed to finish");
        goto FAIL;
    }
    EVP_CIPHER_CTX_free(ctx);
    return RESULT_SUCCESS;
FAIL:
    DestoryBuffer(*plaintext);
    *plaintext = NULL;
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return RESULT_GENERAL_ERROR;
}

static Buffer *Sha256Adaptor(const Buffer *data)
{
    if (!IsBufferValid(data)) {
        LOG_ERROR("bad param");
        return NULL;
    }
    Buffer *result = CreateBufferBySize(SHA256_DIGEST_SIZE);
    if (!IsBufferValid(result)) {
        LOG_ERROR("create buffer failed");
        return NULL;
    }
    if (SHA256(data->buf, data->contentSize, result->buf) != result->buf) {
        LOG_ERROR("SHA256 failed");
        DestoryBuffer(result);
        return NULL;
    }
    result->contentSize = SHA256_DIGEST_SIZE;
    return result;
}

int32_t GetDistributeKey(const Buffer *peerUdid, const Buffer *salt, Buffer **key)
{
    if (!IsBufferValid(peerUdid) || !IsBufferValid(salt) || (key == NULL)) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    Buffer *keyData = CreateBufferBySize(salt->contentSize + USER_AUTH_DISTRIBUTE_DEVICE_KEY_SIZE);
    if (keyData == NULL) {
        LOG_ERROR("CreateBufferBySize keyData fail");
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(keyData->buf, keyData->maxSize, USER_AUTH_DISTRIBUTE_DEVICE_KEY, USER_AUTH_DISTRIBUTE_DEVICE_KEY_SIZE)
        != EOK) {
        LOG_ERROR("copy fix tag fail");
        DestoryBuffer(keyData);
        return RESULT_NO_MEMORY;
    }
    keyData->contentSize += USER_AUTH_DISTRIBUTE_DEVICE_KEY_SIZE;
    if (memcpy_s(keyData->buf + keyData->contentSize, keyData->maxSize - keyData->contentSize, salt->buf,
        salt->contentSize) != EOK) {
        LOG_ERROR("copy salt fail");
        DestoryBuffer(keyData);
        return RESULT_NO_MEMORY;
    }
    keyData->contentSize += salt->contentSize;
    *key = Sha256Adaptor(keyData);
    DestoryBuffer(keyData);
    if (*key == NULL) {
        LOG_ERROR("calculate key fail");
        return RESULT_NO_MEMORY;
    }
    return RESULT_SUCCESS;
}