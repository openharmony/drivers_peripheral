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

#include "enroll_specification_check.h"

#include "adaptor_log.h"
#include "idm_database.h"
#include "idm_session.h"

typedef struct {
    AuthType authType;
    uint32_t maxErollNumber;
} SpecificationMap;

static SpecificationMap g_specificationMap[] = {
    {PIN_AUTH, MAX_NUMBER_OF_PIN_PER_USER},
    {FACE_AUTH, MAX_NUMBER_OF_FACE_PER_USER},
    {FINGER_AUTH, MAX_NUMBER_OF_FINGERS_PER_USER},
};

static uint32_t GetMaxNumber(uint32_t authType)
{
    for (uint32_t i = 0; i < sizeof(g_specificationMap) / sizeof(SpecificationMap); ++i) {
        if (g_specificationMap[i].authType == authType) {
            return g_specificationMap[i].maxErollNumber;
        }
    }
    return INVALID_AUTH_TYPE_EROLL_NUMBER;
}

ResultCode CheckIdmOperationToken(int32_t userId, UserAuthTokenHal *authToken)
{
    if (authToken == NULL) {
        LOG_ERROR("auth token is null");
        return RESULT_BAD_PARAM;
    }
    if (authToken->authType != PIN_AUTH) {
        LOG_ERROR("need pin token");
        return RESULT_VERIFY_TOKEN_FAIL;
    }
    ResultCode ret = CheckChallenge(authToken->challenge, CHALLENGE_LEN);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("check challenge failed, token is invalid");
        return RESULT_BAD_MATCH;
    }
    int32_t userIdGet;
    ret = GetUserId(&userIdGet);
    if (ret != RESULT_SUCCESS || userIdGet != userId) {
        LOG_ERROR("check userId failed");
        return RESULT_BAD_MATCH;
    }
    uint64_t secureUid;
    ret = GetSecureUid(userId, &secureUid);
    if (ret != RESULT_SUCCESS || secureUid != authToken->secureUid) {
        LOG_ERROR("check secureUid failed, token is invalid");
        return RESULT_BAD_MATCH;
    }
    if (!IsValidTokenTime(authToken->time)) {
        LOG_ERROR("check token time failed, token is invalid");
        return RESULT_VERIFY_TOKEN_FAIL;
    }
    return UserAuthTokenVerify(authToken);
}

ResultCode CheckSpecification(int32_t userId, uint32_t authType)
{
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, authType);
    SetCredentialConditionUserId(&condition, userId);
    LinkedList *credList = QueryCredentialLimit(&condition);
    if (credList == NULL) {
        LOG_ERROR("query credential failed");
        return RESULT_UNKNOWN;
    }
    uint32_t maxNumber = GetMaxNumber(authType);
    if (credList->getSize(credList) >= maxNumber) {
        LOG_ERROR("the erolled quantity has reached the upper limit, authType is %{public}u", authType);
        DestroyLinkedList(credList);
        return RESULT_EXCEED_LIMIT;
    }
    DestroyLinkedList(credList);
    return RESULT_SUCCESS;
}