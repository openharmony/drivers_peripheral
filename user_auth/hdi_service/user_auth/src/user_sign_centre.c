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

#include "user_sign_centre.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_time.h"
#include "token_key.h"
#include "idm_database.h"

#define TOKEN_VALIDITY_PERIOD (10 * 60 * 1000)

#define AES_GCM_TOKEN_AAD "OH_authToken"
#define AES_GCM_TOKEN_AAD_SIZE 12

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

IAM_STATIC bool IsTimeValid(const UserAuthTokenHal *userAuthToken)
{
    uint64_t currentTime = GetSystemTime();
    if (currentTime < userAuthToken->tokenDataPlain.time) {
        return false;
    }
    if (currentTime - userAuthToken->tokenDataPlain.time > TOKEN_VALIDITY_PERIOD) {
        return false;
    }
    return true;
}

IAM_STATIC ResultCode UserAuthTokenSign(UserAuthTokenHal *userAuthToken, HksAuthTokenKey *tokenKey)
{
    Buffer *key = GetTokenHmacKey();
    Buffer *sign = NULL;
    ResultCode ret = RESULT_GENERAL_ERROR;
    if (!IsBufferValid(key)) {
        LOG_ERROR("lack of member");
        goto EXIT;
    }
    const Buffer data = GetTmpBuffer((uint8_t *)userAuthToken, AUTH_TOKEN_DATA_LEN, AUTH_TOKEN_DATA_LEN);
    ret = HmacSha256(key, &data, &sign);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("HmacSha256 failed");
        goto EXIT;
    }
    if (!CheckBufferWithSize(sign, SHA256_DIGEST_SIZE)) {
        LOG_ERROR("CheckBufferWithSize failed");
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }
    if (memcpy_s(userAuthToken->sign, SHA256_DIGEST_SIZE, sign->buf, sign->contentSize) != EOK) {
        LOG_ERROR("sign copy failed");
        ret = RESULT_BAD_COPY;
        goto EXIT;
    }

EXIT:
    DestoryBuffer(key);
    DestoryBuffer(sign);
    return ret;
}

IAM_STATIC void DeinitAesGcmParam(AesGcmParam *aesGcmParam)
{
    DestoryBuffer(aesGcmParam->aad);
    DestoryBuffer(aesGcmParam->iv);
    DestoryBuffer(aesGcmParam->key);
    (void)memset_s(aesGcmParam, sizeof(AesGcmParam), 0, sizeof(AesGcmParam));
}

IAM_STATIC ResultCode DecryptTokenCipher(const UserAuthTokenHal *userAuthToken, UserAuthTokenPlain *tokenPlain,
    HksAuthTokenKey *tokenKey)
{
    AesGcmParam aesGcmParam = {
        .key = GetTokenAesKey(),
        .iv = CreateBufferByData(userAuthToken->iv, sizeof(userAuthToken->iv)),
        .aad = CreateBufferByData((uint8_t *)AES_GCM_TOKEN_AAD, AES_GCM_TOKEN_AAD_SIZE),
    };
    Buffer *plaintext = NULL;
    int ret = RESULT_GENERAL_ERROR;
    if (!IsBufferValid(aesGcmParam.key) || !IsBufferValid(aesGcmParam.iv) || !IsBufferValid(aesGcmParam.aad)) {
        LOG_ERROR("get buffer failed");
        goto EXIT;
    }
    const Buffer tag = GetTmpBuffer((uint8_t *)userAuthToken->tag, sizeof(userAuthToken->tag),
        sizeof(userAuthToken->tag));
    const Buffer ciphertext = GetTmpBuffer((uint8_t *)userAuthToken->tokenDataCipher,
        sizeof(userAuthToken->tokenDataCipher), sizeof(userAuthToken->tokenDataCipher));
    ret = AesGcmDecrypt(&ciphertext, &aesGcmParam, &tag, &plaintext);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("AesGcmDecrypt failed");
        goto EXIT;
    }
    if (!CheckBufferWithSize(plaintext, sizeof(tokenPlain->tokenDataToEncrypt))) {
        LOG_ERROR("CheckBufferWithSize failed");
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }
    if (memcpy_s(&(tokenPlain->tokenDataToEncrypt), sizeof(tokenPlain->tokenDataToEncrypt),
        plaintext->buf, plaintext->contentSize) != EOK) {
        LOG_ERROR("copy TokenDataToEncrypt failed");
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }

EXIT:
    DestoryBuffer(plaintext);
    DeinitAesGcmParam(&aesGcmParam);
    return ret;
}

IAM_STATIC ResultCode CheckUserAuthTokenHmac(const UserAuthTokenHal *userAuthToken, HksAuthTokenKey *tokenKey)
{
    Buffer *key = GetTokenHmacKey();
    Buffer *rightSign = NULL;
    ResultCode ret = RESULT_SUCCESS;
    if (key == NULL) {
        LOG_ERROR("lack of member");
        ret = RESULT_NO_MEMORY;
        goto EXIT;
    }
    const Buffer data = GetTmpBuffer((uint8_t *)userAuthToken, AUTH_TOKEN_DATA_LEN, AUTH_TOKEN_DATA_LEN);
    ret = HmacSha256(key, &data, &rightSign);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("HmacSha256 failed");
        goto EXIT;
    }
    const Buffer sign = GetTmpBuffer((uint8_t *)userAuthToken->sign, SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE);
    if (!CompareBuffer(rightSign, &sign)) {
        LOG_ERROR("sign compare failed");
        ret = RESULT_BAD_SIGN;
    }

EXIT:
    DestoryBuffer(key);
    DestoryBuffer(rightSign);
    return ret;
}

ResultCode UserAuthTokenVerify(UserAuthTokenHal *userAuthToken, UserAuthTokenPlain *tokenPlain)
{
    if (userAuthToken == NULL || tokenPlain == NULL) {
        LOG_ERROR("userAuthToken is null");
        return RESULT_BAD_PARAM;
    }
    if (!IsTimeValid(userAuthToken)) {
        LOG_ERROR("token timeout");
        return RESULT_TOKEN_TIMEOUT;
    }
    HksAuthTokenKey tokenKey = {};
    ResultCode ret = CheckUserAuthTokenHmac(userAuthToken, &tokenKey);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("UserAuthTokenVerify fail");
        (void)memset_s(&tokenKey, sizeof(HksAuthTokenKey), 0, sizeof(HksAuthTokenKey));
        return ret;
    }
    tokenPlain->tokenDataPlain = userAuthToken->tokenDataPlain;
    ret = DecryptTokenCipher(userAuthToken, tokenPlain, &tokenKey);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("DecryptTokenCipher fail");
        return ret;
    }
    return ret;
}

IAM_STATIC ResultCode GetTokenDataPlain(UserAuthContext *context, uint32_t authMode, UserAuthTokenHal *authToken)
{
    authToken->version = TOKEN_VERSION;
    if (memcpy_s(authToken->tokenDataPlain.challenge, CHALLENGE_LEN, context->challenge, CHALLENGE_LEN) != EOK) {
        LOG_ERROR("failed to copy challenge");
        return RESULT_BAD_COPY;
    }
    authToken->tokenDataPlain.time = GetSystemTime();
    authToken->tokenDataPlain.authTrustLevel = context->authTrustLevel;
    authToken->tokenDataPlain.authType = context->authType;
    authToken->tokenDataPlain.authMode = authMode;
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode InitAesGcmParam(AesGcmParam *aesGcmParam, const HksAuthTokenKey *tokenKey)
{
    int32_t ret = RESULT_GENERAL_ERROR;
    aesGcmParam->key = GetTokenAesKey();
    aesGcmParam->iv = CreateBufferBySize(AES_GCM_IV_SIZE);
    aesGcmParam->aad = CreateBufferByData((uint8_t *)AES_GCM_TOKEN_AAD, AES_GCM_TOKEN_AAD_SIZE);
    if (!IsBufferValid(aesGcmParam->key) || !IsBufferValid(aesGcmParam->iv) || !IsBufferValid(aesGcmParam->aad)) {
        LOG_ERROR("get secure uid failed");
        goto EXIT;
    }
    ret = SecureRandom(aesGcmParam->iv->buf, aesGcmParam->iv->maxSize);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SecureRandom failed");
        goto EXIT;
    }
    aesGcmParam->iv->contentSize = aesGcmParam->iv->maxSize;
    return ret;
EXIT:
    DeinitAesGcmParam(aesGcmParam);
    return ret;
}

IAM_STATIC ResultCode CopyTokenCipherParam(const Buffer *ciphertext, const Buffer *tag, const Buffer *iv,
    UserAuthTokenHal *authToken)
{
    if (!CheckBufferWithSize(ciphertext, sizeof(authToken->tokenDataCipher))) {
        LOG_ERROR("bad ciphertext size");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(authToken->tokenDataCipher, sizeof(authToken->tokenDataCipher),
        ciphertext->buf, ciphertext->contentSize) != EOK) {
        LOG_ERROR("copy ciphertext failed");
        return RESULT_GENERAL_ERROR;
    }
    if (!CheckBufferWithSize(tag, sizeof(authToken->tag))) {
        LOG_ERROR("bad tag size");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(authToken->tag, sizeof(authToken->tag), tag->buf, tag->contentSize) != EOK) {
        LOG_ERROR("copy tag failed");
        return RESULT_GENERAL_ERROR;
    }
    if (!CheckBufferWithSize(iv, sizeof(authToken->iv))) {
        LOG_ERROR("bad iv size");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(authToken->iv, sizeof(authToken->iv), iv->buf, iv->contentSize) != EOK) {
        LOG_ERROR("copy iv failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetTokenDataToEncrypt(const UserAuthContext *context, uint64_t credentialId,
    TokenDataToEncrypt *data)
{
    EnrolledInfoHal enrolledInfo = {};
    int32_t ret = GetEnrolledInfoAuthType(context->userId, context->authType, &enrolledInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get enrolled info failed");
        return ret;
    }
    uint64_t secureUid;
    ret = GetSecureUid(context->userId, &secureUid);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get secure uid failed");
        return ret;
    }
    data->userId = context->userId;
    data->secureUid = secureUid;
    data->enrolledId = enrolledInfo.enrolledId;
    data->credentialId = credentialId;
    return ret;
}

IAM_STATIC ResultCode GetTokenDataCipherResult(const TokenDataToEncrypt *data, UserAuthTokenHal *authToken,
    const HksAuthTokenKey *tokenKey)
{
    AesGcmParam aesGcmParam = {0};
    Buffer *ciphertext = NULL;
    Buffer *tag = NULL;
    ResultCode ret = InitAesGcmParam(&aesGcmParam, tokenKey);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("InitAesGcmParam failed");
        goto EXIT;
    }
    const Buffer plaintext = GetTmpBuffer((uint8_t *)data, sizeof(TokenDataToEncrypt), sizeof(TokenDataToEncrypt));
    ret = AesGcmEncrypt(&plaintext, &aesGcmParam, &ciphertext, &tag);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("AesGcmEncrypt failed");
        goto EXIT;
    }
    ret = CopyTokenCipherParam(ciphertext, tag, aesGcmParam.iv, authToken);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("CopyTokenCipherParam failed");
        goto EXIT;
    }

EXIT:
    DestoryBuffer(tag);
    DestoryBuffer(ciphertext);
    DeinitAesGcmParam(&aesGcmParam);
    return ret;
}

IAM_STATIC ResultCode GetTokenDataCipher(const UserAuthContext *context, uint64_t credentialId,
    UserAuthTokenHal *authToken, const HksAuthTokenKey *tokenKey)
{
    TokenDataToEncrypt data = {0};
    int32_t ret = GetTokenDataToEncrypt(context, credentialId, &data);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetTokenDataToEncrypt failed");
        return ret;
    }
    ret = GetTokenDataCipherResult(&data, authToken, tokenKey);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetTokenDataCipherResult failed");
    }
    (void)memset_s(&data, sizeof(TokenDataToEncrypt), 0, sizeof(TokenDataToEncrypt));
    return ret;
}

ResultCode GetTokenDataAndSign(UserAuthContext *context,
    uint64_t credentialId, uint32_t authMode, UserAuthTokenHal *authToken)
{
    if (context == NULL || authToken == NULL) {
        LOG_ERROR("context or authToken is null");
        return RESULT_BAD_PARAM;
    }
    (void)memset_s(authToken, sizeof(UserAuthTokenHal), 0, sizeof(UserAuthTokenHal));
    HksAuthTokenKey tokenKey = {};
    ResultCode ret = GetTokenDataPlain(context, authMode, authToken);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetTokenDataPlain fail");
        goto FAIL;
    }
    ret = GetTokenDataCipher(context, credentialId, authToken, &tokenKey);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetTokenDataCipher fail");
        goto FAIL;
    }
    ret = UserAuthTokenSign(authToken, &tokenKey);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("UserAuthTokenSign fail");
        goto FAIL;
    }
    (void)memset_s(&tokenKey, sizeof(HksAuthTokenKey), 0, sizeof(HksAuthTokenKey));
    return RESULT_SUCCESS;

FAIL:
    (void)memset_s(&tokenKey, sizeof(HksAuthTokenKey), 0, sizeof(HksAuthTokenKey));
    (void)memset_s(authToken, sizeof(UserAuthTokenHal), 0, sizeof(UserAuthTokenHal));
    return ret;
}
