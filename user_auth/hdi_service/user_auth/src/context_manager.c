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

#include "securec.h"

#include "adaptor_log.h"
#include "auth_level.h"
#include "coauth.h"
#include "idm_database.h"

static bool IsContextDuplicate(uint64_t contextId);
static ResultCode CreateAndInsertSchedules(UserAuthContext *context, uint32_t authMode);
static ResultCode CreateAuthSchedule(UserAuthContext *context, CoAuthSchedule **schedule);
static ResultCode CreateIdentifySchedule(const UserAuthContext *context, CoAuthSchedule **schedule);
static void DestroyContextNode(void *data);
static ResultCode InsertScheduleToContext(CoAuthSchedule *schedule, UserAuthContext *context);

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

static UserAuthContext *InitAuthContext(AuthSolutionHal params)
{
    UserAuthContext *context = (UserAuthContext *)Malloc(sizeof(UserAuthContext));
    if (context == NULL) {
        LOG_ERROR("context malloc failed");
        return NULL;
    }
    (void)memset_s(context, sizeof(UserAuthContext), 0, sizeof(UserAuthContext));
    if (memcpy_s(context->challenge, CHALLENGE_LEN, params.challenge, CHALLENGE_LEN) != EOK) {
        LOG_ERROR("failed to copy challenge");
        Free(context);
        return NULL;
    }
    context->contextId = params.contextId;
    context->userId = params.userId;
    context->authType = params.authType;
    context->authTrustLevel = params.authTrustLevel;
    context->collectorSensorHint = params.executorSensorHint;
    context->scheduleList = CreateLinkedList(DestroyScheduleNode);
    if (context->scheduleList == NULL) {
        LOG_ERROR("schedule list create failed");
        Free(context);
        return NULL;
    }
    return context;
}

ResultCode GenerateAuthContext(AuthSolutionHal params, UserAuthContext **context)
{
    LOG_INFO("start");
    if (context == NULL) {
        LOG_ERROR("context is null");
        return RESULT_BAD_PARAM;
    }
    if (g_contextList == NULL) {
        LOG_ERROR("need init");
        return RESULT_NEED_INIT;
    }
    if (IsContextDuplicate(params.contextId)) {
        LOG_ERROR("contextId is duplicate");
        return RESULT_DUPLICATE_CHECK_FAILED;
    }
    *context = InitAuthContext(params);
    if (*context == NULL) {
        LOG_ERROR("init context failed");
        return RESULT_GENERAL_ERROR;
    }
    ResultCode ret = CreateAndInsertSchedules(*context, SCHEDULE_MODE_AUTH);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("create schedule failed %{public}d", ret);
        DestroyContextNode(*context);
        *context = NULL;
        return ret;
    }
    ret = g_contextList->insert(g_contextList, *context);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("create schedule failed");
        DestroyContextNode(*context);
        *context = NULL;
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static ResultCode CreateIdentifySchedule(const UserAuthContext *context, CoAuthSchedule **schedule)
{
    ScheduleParam scheduleParam = {};
    scheduleParam.associateId.contextId = context->contextId;
    scheduleParam.authType = context->authType;
    scheduleParam.collectorSensorHint = context->collectorSensorHint;
    scheduleParam.verifierSensorHint = context->collectorSensorHint;
    scheduleParam.scheduleMode = SCHEDULE_MODE_IDENTIFY;
    *schedule = GenerateSchedule(&scheduleParam);
    if (*schedule == NULL) {
        LOG_ERROR("GenerateSchedule failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static UserAuthContext *InitIdentifyContext(const IdentifyParam *params)
{
    UserAuthContext *context = (UserAuthContext *)Malloc(sizeof(UserAuthContext));
    if (context == NULL) {
        LOG_ERROR("context malloc failed");
        return NULL;
    }
    (void)memset_s(context, sizeof(UserAuthContext), 0, sizeof(UserAuthContext));
    if (memcpy_s(context->challenge, CHALLENGE_LEN, params->challenge, CHALLENGE_LEN) != EOK) {
        LOG_ERROR("failed to copy challenge");
        Free(context);
        return NULL;
    }
    context->contextId = params->contextId;
    context->authType = params->authType;
    context->collectorSensorHint = params->executorSensorHint;
    context->scheduleList = CreateLinkedList(DestroyScheduleNode);
    if (context->scheduleList == NULL) {
        LOG_ERROR("schedule list create failed");
        Free(context);
        return NULL;
    }
    return context;
}

UserAuthContext *GenerateIdentifyContext(IdentifyParam params)
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

    UserAuthContext *context = InitIdentifyContext(&params);
    if (context == NULL) {
        LOG_ERROR("init context failed");
        return NULL;
    }
    ResultCode ret = CreateAndInsertSchedules(context, SCHEDULE_MODE_IDENTIFY);
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

static ResultCode CreateAndInsertSchedules(UserAuthContext *context, uint32_t authMode)
{
    LOG_INFO("start");
    CoAuthSchedule *schedule = NULL;
    ResultCode result = RESULT_BAD_PARAM;
    if (authMode == SCHEDULE_MODE_AUTH) {
        result = CreateAuthSchedule(context, &schedule);
    } else if (authMode == SCHEDULE_MODE_IDENTIFY) {
        result = CreateIdentifySchedule(context, &schedule);
    } else {
        LOG_ERROR("authMode is invalid");
        return result;
    }
    if (result != RESULT_SUCCESS) {
        LOG_INFO("create schedule fail %{public}d", result);
        return result;
    }
    if (AddCoAuthSchedule(schedule) != RESULT_SUCCESS) {
        LOG_ERROR("AddCoAuthSchedule failed");
        DestroyCoAuthSchedule(schedule);
        return RESULT_UNKNOWN;
    }
    if (InsertScheduleToContext(schedule, context) != RESULT_SUCCESS) {
        RemoveCoAuthSchedule(schedule->scheduleId);
        DestroyCoAuthSchedule(schedule);
        LOG_ERROR("insert failed");
        return RESULT_UNKNOWN;
    }
    return RESULT_SUCCESS;
}

static LinkedList *GetAuthCredentialList(const UserAuthContext *context)
{
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, context->authType);
    SetCredentialConditionUserId(&condition, context->userId);
    if (context->collectorSensorHint != INVALID_SENSOR_HINT) {
        uint32_t executorMatcher;
        ResultCode ret = QueryCollecterMatcher(context->authType, context->collectorSensorHint, &executorMatcher);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("query collect matcher failed");
            return NULL;
        }
        SetCredentialConditionExecutorMatcher(&condition, executorMatcher);
    }
    return QueryCredentialLimit(&condition);
}

static ResultCode CheckCredentialSize(LinkedList *credList)
{
    uint32_t credNum = credList->getSize(credList);
    if (credNum == 0) {
        LOG_ERROR("credNum is 0");
        return RESULT_NOT_ENROLLED;
    }
    if (credNum > MAX_CREDENTIAL) {
        LOG_ERROR("credNum exceed limit");
        return RESULT_EXCEED_LIMIT;
    }
    return RESULT_SUCCESS;
}

static ResultCode QueryAuthTempletaInfo(UserAuthContext *context, TemplateIdArrays *templateIds,
    uint32_t *sensorHint, uint32_t *matcher, uint32_t *acl)
{
    LinkedList *credList = GetAuthCredentialList(context);
    if (credList == NULL) {
        LOG_ERROR("query credential failed");
        return RESULT_UNKNOWN;
    }
    ResultCode checkResult = CheckCredentialSize(credList);
    if (checkResult != RESULT_SUCCESS) {
        LOG_ERROR("CheckCredentialSize failed %{public}d", checkResult);
        DestroyLinkedList(credList);
        return checkResult;
    }
    templateIds->value = (uint64_t *)Malloc(sizeof(uint64_t) * credList->getSize(credList));
    if (templateIds->value == NULL) {
        LOG_ERROR("value malloc failed");
        DestroyLinkedList(credList);
        return RESULT_NO_MEMORY;
    }
    templateIds->num = 0;
    LinkedListNode *temp = credList->head;
    if (temp == NULL || temp->data == NULL) {
        LOG_ERROR("link node is invalid");
        goto FAIL;
    }
    CredentialInfoHal *credentialHal = (CredentialInfoHal *)temp->data;
    *sensorHint = credentialHal->executorSensorHint;
    *matcher = credentialHal->executorMatcher;
    *acl = credentialHal->capabilityLevel;
    while (temp != NULL) {
        if (temp->data == NULL) {
            LOG_ERROR("link node is invalid");
            goto FAIL;
        }
        credentialHal = (CredentialInfoHal *)temp->data;
        if (credentialHal->executorSensorHint == *sensorHint) {
            templateIds->value[templateIds->num] = credentialHal->templateId;
            ++(templateIds->num);
        }
        temp = temp->next;
    }
    DestroyLinkedList(credList);
    return RESULT_SUCCESS;

FAIL:
    Free(templateIds->value);
    templateIds->value = NULL;
    DestroyLinkedList(credList);
    return RESULT_UNKNOWN;
}

static ResultCode CreateAuthSchedule(UserAuthContext *context, CoAuthSchedule **schedule)
{
    TemplateIdArrays templateIds;
    uint32_t verifierSensorHint;
    uint32_t executorMatcher;
    uint32_t acl;
    ResultCode ret = QueryAuthTempletaInfo(context, &templateIds, &verifierSensorHint, &executorMatcher, &acl);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("QueryAuthTempletaInfo failed %{public}d", ret);
        return ret;
    }
    ScheduleParam scheduleParam = {};
    scheduleParam.associateId.contextId = context->contextId;
    scheduleParam.authType = context->authType;
    scheduleParam.collectorSensorHint = context->collectorSensorHint;
    scheduleParam.verifierSensorHint = verifierSensorHint;
    scheduleParam.templateIds = &templateIds;
    scheduleParam.executorMatcher = executorMatcher;
    scheduleParam.scheduleMode = SCHEDULE_MODE_AUTH;
    *schedule = GenerateSchedule(&scheduleParam);
    if (*schedule == NULL) {
        LOG_ERROR("schedule is null");
        Free(templateIds.value);
        return RESULT_GENERAL_ERROR;
    }
    uint32_t scheduleAtl;
    ret = QueryScheduleAtl(*schedule, acl, &scheduleAtl);
    if (ret != RESULT_SUCCESS || context->authTrustLevel > scheduleAtl) {
        Free(templateIds.value);
        DestroyCoAuthSchedule(*schedule);
        *schedule = NULL;
        return ret;
    }
    Free(templateIds.value);
    return RESULT_SUCCESS;
}

static bool IsContextDuplicate(uint64_t contextId)
{
    if (g_contextList == NULL) {
        LOG_ERROR("context list is null");
        return false;
    }
    LinkedListNode *tempNode = g_contextList->head;
    while (tempNode != NULL) {
        UserAuthContext *context = (UserAuthContext *)tempNode->data;
        if (context == NULL) {
            LOG_ERROR("context is null, please check");
            tempNode = tempNode->next;
            continue;
        }
        if (context->contextId == contextId) {
            return true;
        }
        tempNode = tempNode->next;
    }
    return false;
}

ResultCode CopySchedules(UserAuthContext *context, LinkedList **schedules)
{
    if (context == NULL || context->scheduleList == NULL || schedules == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    LinkedList *scheduleList = context->scheduleList;
    uint32_t scheduleNum = scheduleList->getSize(scheduleList);
    if (scheduleNum > AUTH_MAX_SCHEDULING_NUM) {
        LOG_ERROR("scheduleNum is invalid, scheduleNum is %{public}u", scheduleNum);
        return RESULT_UNKNOWN;
    }
    *schedules = CreateLinkedList(DestroyScheduleNode);
    if (*schedules == NULL) {
        LOG_ERROR("schedules malloc failed");
        return RESULT_NO_MEMORY;
    }
    if (scheduleNum == 0) {
        LOG_INFO("scheduleNum is zero");
        return RESULT_SUCCESS;
    }

    LinkedListNode *temp = scheduleList->head;
    while (temp != NULL) {
        if (temp->data == NULL) {
            LOG_ERROR("node data is wrong, please check");
            goto ERROR;
        }
        CoAuthSchedule *schedule = CopyCoAuthSchedule((CoAuthSchedule *)temp->data);
        if (schedule == NULL) {
            LOG_ERROR("data is null");
            goto ERROR;
        }
        if ((*schedules)->insert(*schedules, schedule) != RESULT_SUCCESS) {
            LOG_ERROR("insert schedule failed");
            DestroyCoAuthSchedule(schedule);
            goto ERROR;
        }
        temp = temp->next;
    }
    return RESULT_SUCCESS;

ERROR:
    DestroyLinkedList(*schedules);
    *schedules = NULL;
    return RESULT_GENERAL_ERROR;
}

static bool MatchSchedule(const void *data, const void *condition)
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

static bool MatchContextSelf(const void *data, const void *condition)
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

int32_t DestoryContextbyId(uint64_t contextId)
{
    UserAuthContext *authContext = GetContext(contextId);
    if (authContext == NULL) {
        LOG_ERROR("get context failed");
        return RESULT_NOT_FOUND;
    }
    DestoryContext(authContext);
    return RESULT_SUCCESS;
}

int32_t FillInContext(UserAuthContext *context, uint64_t *credentialId, ExecutorResultInfo *info)
{
    if (context == NULL || credentialId == NULL  || info == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    const CoAuthSchedule *schedule = GetCoAuthSchedule(info->scheduleId);
    if (schedule == NULL) {
        LOG_ERROR("GetCoAuthSchedule failed");
        return RESULT_GENERAL_ERROR;
    }
    int32_t ret = QueryScheduleAtl(schedule, info->capabilityLevel, &context->authTrustLevel);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("QueryScheduleAtl failed");
        return ret;
    }
    uint32_t veriferSensorHint = GetScheduleVeriferSensorHint(schedule);
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, context->authType);
    SetCredentialConditionTemplateId(&condition, info->templateId);
    SetCredentialConditionExecutorSensorHint(&condition, veriferSensorHint);
    LinkedList *credList = QueryCredentialLimit(&condition);
    if (credList == NULL || credList->getSize(credList) != 1) {
        LOG_ERROR("query credential failed");
        DestroyLinkedList(credList);
        return RESULT_UNKNOWN;
    }
    if (credList->head == NULL || credList->head->data == NULL) {
        LOG_ERROR("list node is invalid");
        DestroyLinkedList(credList);
        return RESULT_UNKNOWN;
    }
    CredentialInfoHal *credentialNode = (CredentialInfoHal *)credList->head->data;
    ret = QueryCredentialUserId(credentialNode->credentialId, &context->userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query userId failed");
        DestroyLinkedList(credList);
        return ret;
    }

    *credentialId = credentialNode->credentialId;
    DestroyLinkedList(credList);
    return ret;
}
