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

#include <inttypes.h>
#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "coauth.h"
#include "buffer.h"
#include "linked_list.h"
#include "idm_database.h"

#define SESSION_VALIDITY_PERIOD (10 * 60 * 1000)
#define MAX_CHALLENGE_GENERATION_TIMES 5

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

// User IDM session information.
struct SessionInfo {
    int32_t userId;
    uint32_t authType;
    uint64_t time;
    uint64_t validAuthTokenTime;
    uint8_t challenge[CHALLENGE_LEN];
    uint64_t scheduleId;
    ScheduleType scheduleType;
    bool isScheduleValid;
    PinChangeScence pinChangeScence;
    Buffer *oldRootSecret;
    Buffer *curRootSecret;
    Buffer *newRootSecret;
} *g_session;

IAM_STATIC bool IsSessionExist(void)
{
    if (g_session == NULL) {
        LOG_INFO("the session does not exist");
        return false;
    }
    return true;
}

IAM_STATIC ResultCode GenerateChallenge(uint8_t *challenge, uint32_t challengeLen)
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
        return RESULT_BAD_COPY;
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

ResultCode CloseEditSession(void)
{
    if (!IsSessionExist()) {
        return RESULT_GENERAL_ERROR;
    }
    ClearCachePin(g_session->userId);
    DestoryBuffer(g_session->oldRootSecret);
    DestoryBuffer(g_session->curRootSecret);
    DestoryBuffer(g_session->newRootSecret);
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

ResultCode CheckChallenge(const uint8_t *challenge, uint32_t challengeLen)
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

ResultCode AssociateCoauthSchedule(uint64_t scheduleId, uint32_t authType, ScheduleType scheduleType)
{
    LOG_INFO("start");
    if (!IsSessionExist()) {
        LOG_ERROR("session is not exist");
        return RESULT_NEED_INIT;
    }
    g_session->scheduleId = scheduleId;
    g_session->authType = authType;
    g_session->scheduleType = scheduleType;
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

ResultCode CheckSessionTimeout(void)
{
    if (!IsSessionExist()) {
        return RESULT_NEED_INIT;
    }
    uint64_t currentTime = GetSystemTime();
    if (currentTime < g_session->time) {
        LOG_ERROR("bad time, currentTime: %{public}" PRIu64 ", sessionTime: %{public}" PRIu64,
            currentTime, g_session->time);
        return RESULT_GENERAL_ERROR;
    }
    if (currentTime - g_session->time > SESSION_VALIDITY_PERIOD) {
        LOG_ERROR("timeout, currentTime: %{public}" PRIu64 ", sessionTime: %{public}" PRIu64,
            currentTime, g_session->time);
        DestoryBuffer(g_session->oldRootSecret);
        ClearCachePin(g_session->userId);
        return RESULT_TIMEOUT;
    }
    return RESULT_SUCCESS;
}

ResultCode GetScheduleType(ScheduleType *scheduleType)
{
    if (scheduleType == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    if (!IsSessionExist() || g_session->isScheduleValid == false) {
        LOG_ERROR("session need init");
        return RESULT_NEED_INIT;
    }
    *scheduleType = g_session->scheduleType;
    return RESULT_SUCCESS;
}

ResultCode CheckSessionValid(int32_t userId)
{
    ResultCode ret = CheckSessionTimeout();
    if (ret != RESULT_SUCCESS) {
        return ret;
    }
    if (g_session->userId != userId) {
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

ResultCode GetChallenge(uint8_t *challenge, uint32_t challengeLen)
{
    if ((challenge == NULL) || (challengeLen != CHALLENGE_LEN)) {
        LOG_ERROR("challenge is invalid");
        return RESULT_BAD_PARAM;
    }

    ResultCode ret = CheckSessionTimeout();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("session does not exist");
        return ret;
    }
    if (memcpy_s(challenge, challengeLen, g_session->challenge, CHALLENGE_LEN) != EOK) {
        LOG_ERROR("copy challenge failed");
        return RESULT_GENERAL_ERROR;
    }

    return RESULT_SUCCESS;
}

ResultCode IsValidUserType(int32_t userType)
{
    if (userType != MAIN_USER && userType != SUB_USER && userType != PRIVATE_USER) {
        LOG_ERROR("userType is invalid");
        return RESULT_BAD_PARAM;
    }
    LOG_INFO("userType is valid");
    return RESULT_SUCCESS;
}

void SetPinChangeScence(int32_t userId, uint32_t authIntent)
{
    if (CheckSessionValid(userId) != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid, userId: %{public}d", userId);
        return;
    }
    if (authIntent == ABANDONED_PIN_AUTH) {
        g_session->pinChangeScence = PIN_RESET_SCENCE;
    } else {
        g_session->pinChangeScence = PIN_UPDATE_SCENCE;
    }
    LOG_INFO("pinChangeScence: %{public}d", g_session->pinChangeScence);
    return;
}

PinChangeScence GetPinChangeScence(int32_t userId)
{
    if (CheckSessionValid(userId) != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid, userId: %{public}d", userId);
        return 0;
    }
    LOG_INFO("pinChangeScence: %{public}d", g_session->pinChangeScence);
    return g_session->pinChangeScence;
}

void SetOldRootSecret(int32_t userId, Buffer *rootSecret)
{
    if (CheckSessionValid(userId) != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid, userId: %{public}d", userId);
        return;
    }

    if (!CheckBufferWithSize(rootSecret, ROOT_SECRET_LEN)) {
        LOG_ERROR("rootSecret is invalid, userId: %{public}d", userId);
        return;
    }

    DestoryBuffer(g_session->oldRootSecret);
    g_session->oldRootSecret = CreateBufferByData(rootSecret->buf, rootSecret->contentSize);
    if (g_session->oldRootSecret == NULL) {
        LOG_ERROR("CreateBufferByData fail, userId: %{public}d", userId);
        return;
    }

    return;
}

Buffer *GetOldRootSecret(int32_t userId)
{
    if (CheckSessionValid(userId) != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid, userId: %{public}d", userId);
        return NULL;
    }
    return g_session->oldRootSecret;
}

void SetCurRootSecret(int32_t userId, Buffer *rootSecret)
{
    if (CheckSessionValid(userId) != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid, userId: %{public}d", userId);
        return;
    }

    if (!CheckBufferWithSize(rootSecret, ROOT_SECRET_LEN)) {
        LOG_ERROR("rootSecret is invalid, userId: %{public}d", userId);
        return;
    }

    DestoryBuffer(g_session->curRootSecret);
    g_session->curRootSecret = CreateBufferByData(rootSecret->buf, rootSecret->contentSize);
    if (g_session->curRootSecret == NULL) {
        LOG_ERROR("CreateBufferByData fail, userId: %{public}d", userId);
        return;
    }

    return;
}

Buffer *GetCurRootSecret(int32_t userId)
{
    if (CheckSessionValid(userId) != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid, userId: %{public}d", userId);
        return NULL;
    }
    return g_session->curRootSecret;
}

ResultCode SetNewRootSecret(int32_t userId, Buffer *rootSecret)
{
    if (CheckSessionValid(userId) != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid, userId: %{public}d", userId);
        return RESULT_GENERAL_ERROR;
    }

    if (!CheckBufferWithSize(rootSecret, ROOT_SECRET_LEN)) {
        LOG_ERROR("rootSecret is invalid, userId: %{public}d", userId);
        return RESULT_GENERAL_ERROR;
    }

    DestoryBuffer(g_session->newRootSecret);
    g_session->newRootSecret = CreateBufferByData(rootSecret->buf, rootSecret->contentSize);
    if (g_session->newRootSecret == NULL) {
        LOG_ERROR("CreateBufferByData fail, userId: %{public}d", userId);
        return RESULT_NO_MEMORY;
    }

    return RESULT_SUCCESS;
}

Buffer *GetNewRootSecret(int32_t userId)
{
    if (CheckSessionValid(userId) != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid, userId: %{public}d", userId);
        return NULL;
    }
    return g_session->newRootSecret;
}