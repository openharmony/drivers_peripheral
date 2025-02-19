/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "auth_token_signer.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_time.h"
#include "idm_database.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

IAM_STATIC ResultCode GetAuthTokenDataPlain(
    const UserAuthContext *context, uint32_t authMode, TokenDataPlain *dataPlain)
{
    if (memcpy_s(dataPlain->challenge, CHALLENGE_LEN, context->challenge, CHALLENGE_LEN) != EOK) {
        LOG_ERROR("failed to copy challenge");
        return RESULT_BAD_COPY;
    }
    dataPlain->time = GetSystemTime();
    dataPlain->authTrustLevel = context->authTrustLevel;
    dataPlain->authType = context->authType;
    dataPlain->authMode = authMode;
    if (memcmp(context->localUdid, context->collectorUdid, sizeof(context->localUdid)) == 0) {
        dataPlain->tokenType = TOKEN_TYPE_LOCAL_AUTH;
    } else {
        dataPlain->tokenType = TOKEN_TYPE_COAUTH;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetAuthTokenDataToEncrypt(const UserAuthContext *context, uint64_t credentialId,
    TokenDataToEncrypt *data)
{
    EnrolledInfoHal enrolledInfo = {};
    ResultCode ret = GetEnrolledInfoAuthType(context->userId, context->authType, &enrolledInfo);
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
    if (memcpy_s(data->collectorUdid, sizeof(data->collectorUdid),
        context->collectorUdid, sizeof(context->collectorUdid)) != EOK) {
        LOG_ERROR("copy collectorUdid failed");
        return RESULT_GENERAL_ERROR;
    }

    if (memcpy_s(data->verifierUdid, sizeof(data->verifierUdid),
        context->localUdid, sizeof(context->localUdid)) != EOK) {
        LOG_ERROR("copy verifierUdid failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

ResultCode GetAuthTokenDataAndSign(
    const UserAuthContext *context, uint64_t credentialId, uint32_t authMode, UserAuthTokenHal *authToken)
{
    if ((context == NULL) || (authToken == NULL)) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    (void)memset_s(authToken, sizeof(UserAuthTokenHal), 0, sizeof(UserAuthTokenHal));

    UserAuthTokenPlainHal tokenPlain = {};
    ResultCode ret = GetAuthTokenDataPlain(context, authMode, &(tokenPlain.tokenDataPlain));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetAuthTokenDataPlain fail");
        return ret;
    }
    ret = GetAuthTokenDataToEncrypt(context, credentialId, &(tokenPlain.tokenDataToEncrypt));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetAuthTokenDataToEncrypt fail");
        return ret;
    }
    ret = UserAuthTokenSign(&tokenPlain, authToken);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("UserAuthTokenSign fail");
        return ret;
    }
    return RESULT_SUCCESS;
}
