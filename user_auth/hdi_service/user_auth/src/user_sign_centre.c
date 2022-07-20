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

#include "user_sign_centre.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_time.h"
#include "token_key.h"
#include "idm_database.h"

#define TOKEN_VALIDITY_PERIOD (10 * 60 * 1000)

static bool IsTimeValid(const UserAuthTokenHal *userAuthToken)
{
    uint64_t currentTime = GetSystemTime();
    if (currentTime < userAuthToken->time) {
        return false;
    }
    if (currentTime - userAuthToken->time > TOKEN_VALIDITY_PERIOD) {
        return false;
    }
    return true;
}

ResultCode UserAuthTokenSign(UserAuthTokenHal *userAuthToken)
{
    if (userAuthToken == NULL) {
        LOG_ERROR("userAuthToken is null");
        return RESULT_BAD_PARAM;
    }
    userAuthToken->version = TOKEN_VERSION;
    ResultCode ret = RESULT_SUCCESS;
    Buffer *data = CreateBufferByData((uint8_t *)userAuthToken, AUTH_TOKEN_DATA_LEN);
    Buffer *key = GetTokenKey();
    Buffer *sign = NULL;
    if (data == NULL || key == NULL) {
        LOG_ERROR("lack of member");
        ret = RESULT_NO_MEMORY;
        goto EXIT;
    }

    if (HmacSha256(key, data, &sign) != RESULT_SUCCESS || !IsBufferValid(sign)) {
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }

    if (memcpy_s(userAuthToken->sign, SHA256_SIGN_LEN, sign->buf, sign->contentSize) != EOK) {
        LOG_ERROR("sign copy failed");
        ret = RESULT_BAD_COPY;
        goto EXIT;
    }

EXIT:
    DestoryBuffer(data);
    DestoryBuffer(key);
    DestoryBuffer(sign);
    return ret;
}

ResultCode UserAuthTokenVerify(const UserAuthTokenHal *userAuthToken)
{
    if (userAuthToken == NULL) {
        LOG_ERROR("userAuthToken is null");
        return RESULT_BAD_PARAM;
    }

    if (!IsTimeValid(userAuthToken)) {
        LOG_ERROR("token timeout");
        return RESULT_TOKEN_TIMEOUT;
    }
    ResultCode ret = RESULT_SUCCESS;
    Buffer *data = CreateBufferByData((uint8_t *)userAuthToken, AUTH_TOKEN_DATA_LEN);
    Buffer *key = GetTokenKey();
    Buffer *sign = CreateBufferByData((uint8_t *)userAuthToken->sign, SHA256_SIGN_LEN);
    Buffer *rightSign = NULL;
    if (data == NULL || key == NULL || sign == NULL) {
        LOG_ERROR("lack of member");
        ret = RESULT_NO_MEMORY;
        goto EXIT;
    }

    if (HmacSha256(key, data, &rightSign) != RESULT_SUCCESS || !IsBufferValid(rightSign)) {
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }

    if (!CompareBuffer(rightSign, sign)) {
        LOG_ERROR("sign compare failed");
        ret = RESULT_BAD_SIGN;
    }

EXIT:
    DestoryBuffer(data);
    DestoryBuffer(key);
    DestoryBuffer(sign);
    DestoryBuffer(rightSign);
    return ret;
}

ResultCode GetTokenDataAndSign(const UserAuthContext *context,
    uint64_t credentialId, uint32_t authMode, UserAuthTokenHal *authToken)
{
    if (context == NULL || authToken == NULL) {
        LOG_ERROR("context or authToken is null");
        return RESULT_BAD_PARAM;
    }
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
    if (memcpy_s(authToken->challenge, CHALLENGE_LEN, context->challenge, CHALLENGE_LEN) != EOK) {
        LOG_ERROR("failed to copy challenge");
        return RESULT_BAD_COPY;
    }
    authToken->authTrustLevel = context->authTrustLevel;
    authToken->authType = context->authType;
    authToken->authMode = authMode;
    authToken->secureUid = secureUid;
    authToken->credentialId = credentialId;
    authToken->enrolledId = enrolledInfo.enrolledId;
    authToken->time = GetSystemTime();
    authToken->version = TOKEN_VERSION;
    return UserAuthTokenSign(authToken);
}
