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

#include "idm_session.h"

#include "securec.h"
#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "coauth.h"
#include "linked_list.h"

#define SESSION_VALIDITY_PERIOD (10 * 60 * 1000)
#define MAX_CHALLENGE_GENERATION_TIMES 5

// User IDM session information.
struct SessionInfo {
    int32_t userId;
    uint32_t authType;
    uint64_t time;
    uint64_t validAuthTokenTime;
    uint8_t challenge[CHALLENGE_LEN];
    uint64_t scheduleId;
    bool isUpdate;
    bool isScheduleValid;
} *g_session;

static bool IsSessionExist()
{
    if (g_session == NULL) {
        LOG_INFO("the session does not exist");
        return false;
    }
    return true;
}

static ResultCode GenerateChallenge(uint8_t *challenge, uint32_t challengeLen)
{
    for (uint32_t i = 0; i < MAX_CHALLENGE_GENERATION_TIMES; ++i) {
        if (SecureRandom(challenge, challengeLen) != RESULT_SUCCESS) {
            LOG_ERROR("get challenge failed");
            return RESULT_GENERAL_ERROR;
        }
        for (uint32_t j = 0; j < challengeLen; j++) {
            if (challenge[j] != 0) {
                return RESULT_SUCCESS;
            }
        }
        LOG_INFO("challenge is invalid, get again.");
    }
    LOG_ERROR("a rare failture");
    return RESULT_GENERAL_ERROR;
}

ResultCode OpenEditSession(int32_t userId, uint8_t *challenge, uint32_t challengeLen)
{
    if (challenge == NULL || challengeLen != CHALLENGE_LEN) {
        LOG_ERROR("challenge is null");
        return RESULT_BAD_PARAM;
    }
    (void)memset_s(challenge, CHALLENGE_LEN, 0, CHALLENGE_LEN);
    if (IsSessionExist()) {
        (void)CloseEditSession();
    }
    g_session = Malloc(sizeof(struct SessionInfo));
    if (g_session == NULL) {
        LOG_ERROR("g_session malloc failed");
        return RESULT_NO_MEMORY;
    }
    if (memset_s(g_session, sizeof(struct SessionInfo), 0, sizeof(struct SessionInfo)) != EOK) {
        LOG_ERROR("g_session set failed");
        Free(g_session);
        g_session = NULL;
        return RESULT_GENERAL_ERROR;
    }
    g_session->userId = userId;
    ResultCode ret = GenerateChallenge(g_session->challenge, CHALLENGE_LEN);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to generate challenge");
        Free(g_session);
        g_session = NULL;
        return ret;
    }
    g_session->time = GetSystemTime();
    g_session->validAuthTokenTime = g_session->time;

    if (memcpy_s(challenge, CHALLENGE_LEN, g_session->challenge, CHALLENGE_LEN) != EOK) {
        LOG_ERROR("failed to copy challenge");
        Free(g_session);
        g_session = NULL;
        return ret;
    }
    g_session->isScheduleValid = false;
    return RESULT_SUCCESS;
}

void RefreshValidTokenTime(void)
{
    if (!IsSessionExist()) {
        LOG_ERROR("session is invalid");
        return;
    }
    g_session->validAuthTokenTime = GetSystemTime();
}

bool IsValidTokenTime(uint64_t tokenTime)
{
    if (!IsSessionExist()) {
        LOG_ERROR("session is invalid");
        return false;
    }
    return tokenTime >= g_session->validAuthTokenTime;
}

ResultCode CloseEditSession()
{
    if (!IsSessionExist()) {
        return RESULT_GENERAL_ERROR;
    }
    Free(g_session);
    g_session = NULL;
    return RESULT_SUCCESS;
}

ResultCode GetUserId(int32_t *userId)
{
    if (userId == NULL || !IsSessionExist()) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    *userId = g_session->userId;
    return RESULT_SUCCESS;
}

ResultCode CheckChallenge(uint8_t *challenge, uint32_t challengeLen)
{
    if (challenge == NULL || challengeLen != CHALLENGE_LEN) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    if (!IsSessionExist()) {
        LOG_ERROR("param is invalid");
        return RESULT_NEED_INIT;
    }
    if (memcmp(challenge, g_session->challenge, CHALLENGE_LEN) != EOK) {
        LOG_ERROR("failed to compare challenge");
        return RESULT_BAD_MATCH;
    }
    return RESULT_SUCCESS;
}

ResultCode AssociateCoauthSchedule(uint64_t scheduleId, uint32_t authType, bool isUpdate)
{
    if (!IsSessionExist()) {
        return RESULT_NEED_INIT;
    }
    g_session->scheduleId = scheduleId;
    g_session->authType = authType;
    g_session->isUpdate = isUpdate;
    g_session->isScheduleValid = true;
    return RESULT_SUCCESS;
}

void BreakOffCoauthSchedule(void)
{
    if (!IsSessionExist()) {
        return;
    }
    if (g_session->isScheduleValid) {
        RemoveCoAuthSchedule(g_session->scheduleId);
    }
    g_session->isScheduleValid = false;
}

ResultCode GetEnrollScheduleInfo(uint64_t *scheduleId, uint32_t *authType)
{
    if (scheduleId == NULL || authType == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    if (!IsSessionExist() || g_session->isScheduleValid == false) {
        return RESULT_NEED_INIT;
    }
    *scheduleId = g_session->scheduleId;
    *authType = g_session->authType;
    return RESULT_SUCCESS;
}

bool IsSessionTimeout(void)
{
    if (!IsSessionExist()) {
        return true;
    }
    uint64_t currentTime = GetSystemTime();
    if (currentTime < g_session->time || currentTime - g_session->time > SESSION_VALIDITY_PERIOD) {
        LOG_ERROR("timeout, %{public}llu, %{public}llu",
                  (unsigned long long)currentTime, (unsigned long long)g_session->time);
        return true;
    }
    return false;
}

ResultCode GetIsUpdate(bool *isUpdate)
{
    if (isUpdate == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    if (!IsSessionExist() || g_session->isScheduleValid == false) {
        LOG_ERROR("session need init");
        return RESULT_NEED_INIT;
    }
    *isUpdate = g_session->isUpdate;
    return RESULT_SUCCESS;
}

bool IsSessionValid(int32_t userId)
{
    if (!IsSessionExist() || IsSessionTimeout()) {
        return false;
    }
    if (g_session->userId == userId) {
        return true;
    }
    return false;
}