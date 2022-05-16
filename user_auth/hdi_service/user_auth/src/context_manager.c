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

#include "context_manager.h"

#include "adaptor_log.h"
#include "auth_level.h"
#include "coauth.h"
#include "idm_database.h"

static bool IsContextDuplicate(uint64_t contextId);
static ResultCode CreateSchedules(UserAuthContext *context);
static CoAuthSchedule *CreateCoauthSchedule(uint32_t userId, uint64_t contextId, uint32_t authType);
static void DestroyContextNode(void *data);

// Stores information about the current user authentication schedule.
static LinkedList *g_contextList = NULL;

ResultCode InitUserAuthContextList()
{
    if (g_contextList != NULL) {
        return RESULT_SUCCESS;
    }
    g_contextList = CreateLinkedList(DestroyContextNode);
    if (g_contextList == NULL) {
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

void DestoryUserAuthContextList(void)
{
    DestroyLinkedList(g_contextList);
    g_contextList = NULL;
}

static void CopyParamToContext(UserAuthContext *context, AuthSolutionHal params)
{
    context->contextId = params.contextId;
    context->userId = params.userId;
    context->challenge = params.challenge;
    context->authType = params.authType;
    context->authTrustLevel = params.authTrustLevel;
}

UserAuthContext *GenerateContext(AuthSolutionHal params)
{
    LOG_INFO("start");
    if (g_contextList == NULL) {
        LOG_ERROR("need init");
        return NULL;
    }
    if (IsContextDuplicate(params.contextId)) {
        LOG_ERROR("contextId is duplicate");
        return NULL;
    }
    uint32_t authTypeAtl;
    ResultCode ret = SingleAuthTrustLevel(params.userId, params.authType, &authTypeAtl);
    if (ret != RESULT_SUCCESS || authTypeAtl < params.authTrustLevel) {
        LOG_ERROR("authTrustLevel is satisfied");
        return NULL;
    }

    UserAuthContext *context = Malloc(sizeof(UserAuthContext));
    if (context == NULL) {
        LOG_ERROR("context malloc failed");
        return NULL;
    }
    CopyParamToContext(context, params);
    ret = CreateSchedules(context);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("create schedule failed");
        DestroyContextNode(context);
        return NULL;
    }
    ret = g_contextList->insert(g_contextList, context);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("create schedule failed");
        DestroyContextNode(context);
        return NULL;
    }
    return context;
}

UserAuthContext *GetContext(uint64_t contextId)
{
    if (g_contextList == NULL) {
        LOG_ERROR("context list is null");
        return NULL;
    }
    uint32_t num = g_contextList->getSize(g_contextList);
    LinkedListNode *tempNode = g_contextList->head;
    UserAuthContext *contextRet = NULL;
    for (uint32_t index = 0; index < num; index++) {
        if (tempNode == NULL) {
            LOG_ERROR("node is null");
            return NULL;
        }
        contextRet = (UserAuthContext *)tempNode->data;
        if (contextRet != NULL && contextRet->contextId == contextId) {
            return contextRet;
        }
        tempNode = tempNode->next;
    }
    return NULL;
}

static ResultCode InsertScheduleToContext(CoAuthSchedule *schedule, UserAuthContext *context)
{
    LinkedList *scheduleList = context->scheduleList;
    return scheduleList->insert(scheduleList, schedule);
}

static void DestroyScheduleNode(void *data)
{
    if (data == NULL) {
        LOG_ERROR("schedule is null");
        return;
    }
    Free(data);
}

static ResultCode CreateSchedules(UserAuthContext *context)
{
    LOG_INFO("start");
    context->scheduleList = CreateLinkedList(DestroyScheduleNode);
    if (context->scheduleList == NULL) {
        LOG_ERROR("schedule list create failed");
        return RESULT_NO_MEMORY;
    }
    CoAuthSchedule *schedule = CreateCoauthSchedule(context->userId, context->contextId, context->authType);
    if (schedule == NULL) {
        LOG_INFO("the authType is invalid");
        DestroyLinkedList(context->scheduleList);
        context->scheduleList = NULL;
        return RESULT_BAD_PARAM;
    }
    if (InsertScheduleToContext(schedule, context) != RESULT_SUCCESS) {
        DestroyScheduleNode(schedule);
        DestroyLinkedList(context->scheduleList);
        context->scheduleList = NULL;
        LOG_ERROR("insert failed");
        return RESULT_UNKNOWN;
    }
    return RESULT_SUCCESS;
}

static CoAuthSchedule *CreateCoauthSchedule(uint32_t userId, uint64_t contextId, uint32_t authType)
{
    CredentialInfoHal credential;
    ResultCode ret = QueryCredentialInfo(userId, authType, &credential);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query credential info failed");
        return NULL;
    }

    CoAuthSchedule *schedule = GenerateAuthSchedule(contextId, authType, DEFAULT_TYPE, credential.templateId);
    if (schedule == NULL) {
        LOG_ERROR("schedule is null");
        return NULL;
    }
    ret = AddCoAuthSchedule(schedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("AddCoAuthSchedule failed");
        DestroyCoAuthSchedule(schedule);
        return NULL;
    }
    return schedule;
}

static bool IsContextDuplicate(uint64_t contextId)
{
    if (g_contextList == NULL) {
        LOG_ERROR("context list is null");
        return false;
    }
    LinkedListNode *tempNode = g_contextList->head;
    while (tempNode != NULL) {
        UserAuthContext *context = tempNode->data;
        if (context == NULL) {
            LOG_ERROR("context is null, please check");
            continue;
        }
        if (context->contextId == contextId) {
            return true;
        }
        tempNode = tempNode->next;
    }
    return false;
}

ResultCode GetSchedules(UserAuthContext *context, CoAuthSchedule **schedules, uint32_t *scheduleNum)
{
    if (context == NULL || context->scheduleList == NULL || schedules == NULL || scheduleNum == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    LinkedList *scheduleList = context->scheduleList;
    *scheduleNum = scheduleList->getSize(scheduleList);
    if (*scheduleNum > AUTH_MAX_SCHEDULING_NUM) {
        LOG_ERROR("scheduleNum is invalid, scheduleNum is %{public}u", *scheduleNum);
        return RESULT_UNKNOWN;
    }
    if (*scheduleNum == 0) {
        LOG_INFO("scheduleNum is zero");
        return RESULT_SUCCESS;
    }

    *schedules = Malloc(*scheduleNum * sizeof(CoAuthSchedule));
    if (*schedules == NULL) {
        LOG_ERROR("schedules malloc failed");
        return RESULT_NO_MEMORY;
    }

    LinkedListNode *temp = scheduleList->head;
    for (uint32_t index = 0; index < *scheduleNum; index++) {
        if (temp == NULL) {
            LOG_ERROR("something is wrong, please check");
            goto ERROR;
        }
        CoAuthSchedule *schedule = temp->data;
        if (schedule == NULL) {
            LOG_ERROR("data is null");
            goto ERROR;
        }
        (*schedules)[index] = *schedule;
        temp = temp->next;
    }
    return RESULT_SUCCESS;

ERROR:
    Free(*schedules);
    *schedules = NULL;
    return RESULT_GENERAL_ERROR;
}

static bool MatchSchedule(void *data, void *condition)
{
    if (data == NULL || condition == NULL) {
        LOG_ERROR("param is null");
        return false;
    }
    CoAuthSchedule *schedule = (CoAuthSchedule *)data;
    if (schedule->scheduleId == *(uint64_t *)condition) {
        return true;
    }
    return false;
}

ResultCode ScheduleOnceFinish(UserAuthContext *context, uint64_t scheduleId)
{
    if (context == NULL || context->scheduleList == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    RemoveCoAuthSchedule(scheduleId);
    return context->scheduleList->remove(context->scheduleList, &scheduleId, MatchSchedule, true);
}

static bool MatchContextSelf(void *data, void *condition)
{
    return data == condition;
}

void DestoryContext(UserAuthContext *context)
{
    if (context == NULL) {
        LOG_ERROR("context is null");
        return;
    }
    if (g_contextList == NULL) {
        LOG_ERROR("context list is null");
        return;
    }
    g_contextList->remove(g_contextList, context, MatchContextSelf, true);
}

static void DestroyContextNode(void *data)
{
    if (data == NULL) {
        return;
    }
    LinkedList *schedules = ((UserAuthContext *)data)->scheduleList;
    if (schedules == NULL) {
        LOG_ERROR("schedules is null");
        return;
    }
    LinkedListNode *tempNode = schedules->head;
    while (tempNode != NULL) {
        CoAuthSchedule *schedule = tempNode->data;
        if (schedule == NULL) {
            LOG_ERROR("schedule is null, please check");
            tempNode = tempNode->next;
            continue;
        }
        RemoveCoAuthSchedule(schedule->scheduleId);
        tempNode = tempNode->next;
    }
    DestroyLinkedList(schedules);
    Free(data);
}
