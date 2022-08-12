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
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include "securec.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "buffer.h"
#include "defines.h"

#define OPENSSL_SUCCESS 1

#define ED25519_FIX_PRIKEY_BUFFER_SIZE 32
#define ED25519_FIX_PUBKEY_BUFFER_SIZE 32

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

static int32_t SetAesEncryptVi(EVP_CIPHER_CTX *ctx, const Buffer *vi)
{
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, vi->contentSize, NULL) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set vi len");
        return RESULT_GENERAL_ERROR;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, vi->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to init vi");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static Buffer *CreateCiphertext(EVP_CIPHER_CTX *ctx, const Buffer *plaintext)
{
    Buffer *ciphertext = CreateBufferBySize(plaintext->contentSize);
    if (!IsBufferValid(ciphertext)) {
        LOG_ERROR("ciphertext is invalid");
        return NULL;
    }
    if (EVP_CIPHER_CTX_set_padding(ctx, NO_PADDING) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set padding");
        DestoryBuffer(ciphertext);
        return NULL;
    }
    int32_t outLen = 0;
    if (EVP_EncryptUpdate(ctx, (unsigned char *)(ciphertext->buf), &outLen,
        (unsigned char *)plaintext->buf, plaintext->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to update");
        DestoryBuffer(ciphertext);
        return NULL;
    }
    if (outLen < 0) {
        LOG_ERROR("outLen out of range");
        DestoryBuffer(ciphertext);
        return NULL;
    }
    ciphertext->contentSize = (uint32_t)outLen;
    if (ciphertext->maxSize < ciphertext->contentSize) {
        LOG_ERROR("memory overflow occurred, please check");
        DestoryBuffer(ciphertext);
        return NULL;
    }
    if (EVP_EncryptFinal_ex(ctx, NULL, &outLen) != OPENSSL_SUCCESS || outLen != 0) { // no padding no out
        LOG_ERROR("failed to finish");
        DestoryBuffer(ciphertext);
        return NULL;
    }
    return ciphertext;
}

static int32_t SpliceOutput(const Buffer *vi, const Buffer *tag, const Buffer *ciphertext, Buffer *cipherInfo)
{
    if (cipherInfo->contentSize != 0) {
        LOG_ERROR("cipherInfo is not 0 bytes");
        return RESULT_BAD_PARAM;
    }
    if (cipherInfo->maxSize < ciphertext->contentSize ||
        cipherInfo->maxSize - ciphertext->contentSize < vi->contentSize + tag->contentSize) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    if (memcpy_s(cipherInfo->buf, cipherInfo->maxSize, vi->buf, vi->contentSize) != EOK) {
        LOG_ERROR("failed to copy vi");
        return RESULT_BAD_COPY;
    }
    cipherInfo->contentSize += vi->contentSize;
    if (memcpy_s(cipherInfo->buf + cipherInfo->contentSize, cipherInfo->maxSize - cipherInfo->contentSize,
        tag->buf, tag->contentSize) != EOK) {
        LOG_ERROR("failed to copy tag");
        return RESULT_BAD_COPY;
    }
    cipherInfo->contentSize += tag->contentSize;
    if (memcpy_s(cipherInfo->buf + cipherInfo->contentSize, cipherInfo->maxSize - cipherInfo->contentSize,
        ciphertext->buf, ciphertext->contentSize) != EOK) {
        LOG_ERROR("failed to copy ciphertext");
        return RESULT_BAD_COPY;
    }
    cipherInfo->contentSize += ciphertext->contentSize;
    return RESULT_SUCCESS;
}

static int32_t DoAes256GcmEncryptNoPadding(const Buffer *plaintext, const Buffer *key, Buffer *cipherInfo)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    Buffer *vi = CreateBufferBySize(AES_GCM_VI_SIZE);
    Buffer *tag = CreateBufferBySize(AES_GCM_TAG_SIZE);
    Buffer *ciphertext = NULL;
    if (ctx == NULL || !IsBufferValid(vi) || !IsBufferValid(tag)) {
        LOG_ERROR("failed to init");
        goto FAIL;
    }
    vi->contentSize = AES_GCM_VI_SIZE;
    if (SecureRandom(vi->buf, vi->contentSize) != RESULT_SUCCESS ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)key->buf, NULL) != OPENSSL_SUCCESS ||
        SetAesEncryptVi(ctx, vi) != RESULT_SUCCESS) {
        LOG_ERROR("failed to call algorithm interface");
        goto FAIL;
    }
    ciphertext = CreateCiphertext(ctx, plaintext);
    if (!IsBufferValid(ciphertext)) {
        LOG_ERROR("failed to create ciphertext");
        goto FAIL;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AES_GCM_TAG_SIZE, tag->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to get tag");
        goto FAIL;
    }
    tag->contentSize = AES_GCM_TAG_SIZE;
    if (SpliceOutput(vi, tag, ciphertext, cipherInfo) != RESULT_SUCCESS) {
        LOG_ERROR("failed to splice");
        goto FAIL;
    }
    DestoryBuffer(vi);
    DestoryBuffer(ciphertext);
    DestoryBuffer(tag);
    EVP_CIPHER_CTX_free(ctx);
    return RESULT_SUCCESS;
FAIL:
    DestoryBuffer(vi);
    DestoryBuffer(ciphertext);
    DestoryBuffer(tag);
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return RESULT_GENERAL_ERROR;
}

// Return is 12 byte VI, 16 byte tag, and the AES ciphertext corresponding to plaintext, is used to parse plaintext.
Buffer *Aes256GcmEncryptNoPadding(const Buffer *plaintext, const Buffer *key)
{
    if (!IsBufferValid(plaintext) || plaintext->contentSize == 0 || plaintext->contentSize > CIPHER_INFO_MAX_SIZE ||
        plaintext->contentSize % AES256_BLOCK_SIZE != 0 || !IsBufferValid(key) || key->contentSize != AES256_KEY_SIZE) {
        LOG_ERROR("bad param");
        return NULL;
    }
    Buffer *cipherInfo = CreateBufferBySize(CIPHER_INFO_MAX_SIZE);
    if (!IsBufferValid(cipherInfo)) {
        LOG_ERROR("failed to create cipherInfo");
        return NULL;
    }
    if (DoAes256GcmEncryptNoPadding(plaintext, key, cipherInfo) != RESULT_SUCCESS) {
        LOG_ERROR("failed to encrypt");
        DestoryBuffer(cipherInfo);
        return NULL;
    }
    return cipherInfo;
}

static int32_t SplitInput(const Buffer *cipherInfo, Buffer *vi, Buffer *tag, Buffer *ciphertext)
{
    if (cipherInfo->contentSize <= AES_GCM_VI_SIZE + AES_GCM_TAG_SIZE ||
        cipherInfo->contentSize - (AES_GCM_VI_SIZE + AES_GCM_TAG_SIZE) > ciphertext->maxSize) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    uint32_t offset = 0;
    if (memcpy_s(vi->buf, vi->maxSize, cipherInfo->buf, AES_GCM_VI_SIZE) != EOK) {
        LOG_ERROR("failed to copy vi");
        return RESULT_BAD_COPY;
    }
    vi->contentSize = AES_GCM_VI_SIZE;
    offset += AES_GCM_VI_SIZE;
    if (memcpy_s(tag->buf, tag->maxSize, cipherInfo->buf + offset, AES_GCM_TAG_SIZE) != EOK) {
        LOG_ERROR("failed to copy tag");
        return RESULT_BAD_COPY;
    }
    tag->contentSize = AES_GCM_TAG_SIZE;
    offset += AES_GCM_TAG_SIZE;
    if (memcpy_s(ciphertext->buf, ciphertext->maxSize,
        cipherInfo->buf + offset, cipherInfo->contentSize - offset) != EOK) {
        LOG_ERROR("failed to copy ciphertext");
        return RESULT_BAD_COPY;
    }
    ciphertext->contentSize = cipherInfo->contentSize - offset;
    return RESULT_SUCCESS;
}

static int32_t SetAesDecryptVi(EVP_CIPHER_CTX *ctx, const Buffer *vi)
{
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, vi->contentSize, NULL) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set vi len");
        return RESULT_GENERAL_ERROR;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, vi->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to init vi");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static int32_t SetPlaintext(EVP_CIPHER_CTX *ctx, const Buffer *ciphertext, const Buffer *tag, Buffer *plaintext)
{
    if (EVP_CIPHER_CTX_set_padding(ctx, NO_PADDING) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set padding");
        return RESULT_GENERAL_ERROR;
    }
    int32_t outLen = 0;
    if (EVP_DecryptUpdate(ctx, (unsigned char *)(plaintext->buf), &outLen,
        (unsigned char *)ciphertext->buf, ciphertext->contentSize) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to update");
        return RESULT_GENERAL_ERROR;
    }
    if (outLen < 0) {
        LOG_ERROR("outLen out of range");
        return RESULT_GENERAL_ERROR;
    }
    plaintext->contentSize = (uint32_t)outLen;
    if (plaintext->maxSize < plaintext->contentSize) {
        LOG_ERROR("memory overflow occurred, please check");
        return RESULT_GENERAL_ERROR;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag->contentSize, tag->buf) != OPENSSL_SUCCESS) {
        LOG_ERROR("failed to set tag");
        return RESULT_GENERAL_ERROR;
    }
    if (EVP_DecryptFinal_ex(ctx, NULL, &outLen) != OPENSSL_SUCCESS || outLen != 0) { // no padding no out
        LOG_ERROR("failed to finish");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static int32_t DoAes256GcmDecryptNoPadding(const Buffer *cipherInfo, const Buffer *key, Buffer *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    Buffer *vi = CreateBufferBySize(AES_GCM_VI_SIZE);
    Buffer *tag = CreateBufferBySize(AES_GCM_TAG_SIZE);
    Buffer *ciphertext = CreateBufferBySize(cipherInfo->contentSize);
    if (ctx == NULL || !IsBufferValid(vi) || !IsBufferValid(tag) || !IsBufferValid(ciphertext)) {
        LOG_ERROR("failed to init");
        goto FAIL;
    }
    if (SplitInput(cipherInfo, vi, tag, ciphertext) != RESULT_SUCCESS ||
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char *)key->buf, NULL) != OPENSSL_SUCCESS ||
        SetAesDecryptVi(ctx, vi) != RESULT_SUCCESS ||
        SetPlaintext(ctx, ciphertext, tag, plaintext) != RESULT_SUCCESS) {
        LOG_ERROR("failed to call algorithm interface");
        goto FAIL;
    }
    DestoryBuffer(vi);
    DestoryBuffer(ciphertext);
    DestoryBuffer(tag);
    EVP_CIPHER_CTX_free(ctx);
    return RESULT_SUCCESS;
FAIL:
    DestoryBuffer(vi);
    DestoryBuffer(ciphertext);
    DestoryBuffer(tag);
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    return RESULT_GENERAL_ERROR;
}

Buffer *Aes256GcmDecryptNoPadding(const Buffer *cipherInfo, const Buffer *key)
{
    if (!IsBufferValid(cipherInfo) || cipherInfo->contentSize <= AES_GCM_VI_SIZE + AES_GCM_TAG_SIZE ||
        cipherInfo->contentSize > CIPHER_INFO_MAX_SIZE || !IsBufferValid(key) || key->contentSize != AES256_KEY_SIZE) {
        LOG_ERROR("bad param");
        return NULL;
    }
    Buffer *plaintext = CreateBufferBySize(cipherInfo->contentSize);
    if (!IsBufferValid(plaintext)) {
        LOG_ERROR("failed to create cipherInfo");
        return NULL;
    }
    if (DoAes256GcmDecryptNoPadding(cipherInfo, key, plaintext) != RESULT_SUCCESS) {
        LOG_ERROR("failed to do decrypt");
        DestoryBuffer(plaintext);
        return NULL;
    }
    return plaintext;
}

// Here is the piling code. The real implementation needs to call the security interface.
Buffer *DeriveDeviceKey(const Buffer *secret)
{
    if (!IsBufferValid(secret) || secret->contentSize != SECRET_SIZE) {
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
        DestoryBuffer(key);
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
        DestoryBuffer(result);
        return NULL;
    }
    result->contentSize = SHA256_DIGEST_SIZE;
    return result;
}