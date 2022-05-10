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

#include "coauth.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "pool.h"

// Used to cache the ongoing coAuth scheduling.
static LinkedList *g_scheduleList = NULL;

static bool IsCoAuthInit()
{
    return g_scheduleList != NULL;
}

static void DestroySchedule(void *data)
{
    if (data == NULL) {
        LOG_ERROR("get null data");
        return;
    }
    Free(data);
}

void DestroyCoAuthSchedule(CoAuthSchedule *coAuthSchedule)
{
    if (coAuthSchedule == NULL) {
        return;
    }
    DestroySchedule(coAuthSchedule);
}

ResultCode InitCoAuth(void)
{
    if (!IsCoAuthInit()) {
        g_scheduleList = CreateLinkedList(DestroySchedule);
    }
    if (g_scheduleList == NULL) {
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

void DestoryCoAuth(void)
{
    DestroyLinkedList(g_scheduleList);
    g_scheduleList = NULL;
}

ResultCode AddCoAuthSchedule(CoAuthSchedule *coAuthSchedule)
{
    if (!IsCoAuthInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    if (coAuthSchedule == NULL) {
        LOG_ERROR("get null schedule");
        return RESULT_BAD_PARAM;
    }
    CoAuthSchedule *schedule = (CoAuthSchedule *)Malloc(sizeof(CoAuthSchedule));
    if (schedule == NULL) {
        LOG_ERROR("no memory");
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(schedule, sizeof(CoAuthSchedule), coAuthSchedule, sizeof(CoAuthSchedule)) != EOK) {
        LOG_ERROR("copy failed");
        Free(schedule);
        return RESULT_BAD_COPY;
    }
    ResultCode result = g_scheduleList->insert(g_scheduleList, schedule);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("insert failed");
        Free(schedule);
        return result;
    }
    return result;
}

static bool IsScheduleMatch(void *data, void *condition)
{
    if ((condition == NULL) || (data == NULL)) {
        LOG_ERROR("get null data");
        return false;
    }
    uint64_t scheduleId = *(uint64_t *)condition;
    CoAuthSchedule *coAuthSchedule = (CoAuthSchedule *)data;
    return (coAuthSchedule->scheduleId == scheduleId);
}

ResultCode RemoveCoAuthSchedule(uint64_t scheduleId)
{
    if (!IsCoAuthInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    return g_scheduleList->remove(g_scheduleList, (void *)&scheduleId, IsScheduleMatch, true);
}

ResultCode GetCoAuthSchedule(CoAuthSchedule *coAuthSchedule)
{
    if (!IsCoAuthInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    if (coAuthSchedule == NULL) {
        LOG_ERROR("get null schedule");
        return RESULT_BAD_PARAM;
    }
    LinkedListIterator *iterator = g_scheduleList->createIterator(g_scheduleList);
    if (iterator == NULL) {
        LOG_ERROR("create iterator failed");
        return RESULT_NO_MEMORY;
    }
    int32_t result = RESULT_BAD_MATCH;
    while (iterator->hasNext(iterator)) {
        CoAuthSchedule *schedule = (CoAuthSchedule *)iterator->next(iterator);
        if (schedule->scheduleId != coAuthSchedule->scheduleId) {
            continue;
        }
        if (memcpy_s(coAuthSchedule, sizeof(CoAuthSchedule), schedule, sizeof(CoAuthSchedule)) != EOK) {
            LOG_ERROR("memcpy failed");
            result = RESULT_BAD_COPY;
            break;
        }
        g_scheduleList->destroyIterator(iterator);
        return RESULT_SUCCESS;
    }

    g_scheduleList->destroyIterator(iterator);
    return result;
}

static bool IsScheduleIdDuplicate(uint64_t scheduleId)
{
    LinkedListNode *temp = g_scheduleList->head;
    CoAuthSchedule *schedule = NULL;
    while (temp != NULL) {
        schedule = (CoAuthSchedule *)temp->data;
        if (schedule != NULL && schedule->scheduleId == scheduleId) {
            return true;
        }
        temp = temp->next;
    }

    return false;
}

static ResultCode GenerateValidScheduleId(uint64_t *scheduleId)
{
    if (g_scheduleList == NULL) {
        LOG_ERROR("g_poolList is null");
        return RESULT_BAD_PARAM;
    }

    for (uint32_t i = 0; i < MAX_DUPLICATE_CHECK; i++) {
        uint64_t tempRandom;
        if (SecureRandom((uint8_t *)&tempRandom, sizeof(uint64_t)) != RESULT_SUCCESS) {
            LOG_ERROR("get random failed");
            return RESULT_GENERAL_ERROR;
        }
        if (!IsScheduleIdDuplicate(tempRandom)) {
            *scheduleId = tempRandom;
            return RESULT_SUCCESS;
        }
    }

    LOG_ERROR("a rare failure");
    return RESULT_GENERAL_ERROR;
}

static ResultCode MountExecutor(uint32_t authType, CoAuthSchedule *coAuthSchedule)
{
    LinkedList *executors = NULL;
    ResultCode ret = QueryExecutor(authType, &executors);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query executor failed");
        return ret;
    }

    coAuthSchedule->executorSize = executors->getSize(executors);
    if (coAuthSchedule->executorSize <= 0 || coAuthSchedule->executorSize > MAX_EXECUTOR_SIZE) {
        LOG_ERROR("executorSize is invalid");
        ret = RESULT_UNKNOWN;
        goto EXIT;
    }
    LinkedListNode *tempNode = executors->head;
    for (uint32_t i = 0; i < coAuthSchedule->executorSize; i++) {
        if (tempNode == NULL || tempNode->data == NULL) {
            LOG_ERROR("tempNode or data is null");
            ret = RESULT_UNKNOWN;
            goto EXIT;
        }
        if (memcpy_s(coAuthSchedule->executors + i, sizeof(ExecutorInfoHal),
            tempNode->data, sizeof(ExecutorInfoHal)) != EOK) {
            LOG_ERROR("copy executorinfo failed");
            ret = RESULT_UNKNOWN;
            goto EXIT;
        }
        tempNode = tempNode->next;
    }

EXIT:
    DestroyLinkedList(executors);
    return ret;
}

CoAuthSchedule *GenerateAuthSchedule(uint64_t contextId, uint32_t authType, uint64_t authSubType,
    uint64_t templateId)
{
    CoAuthSchedule *coAuthSchedule = Malloc(sizeof(CoAuthSchedule));
    if (coAuthSchedule == NULL) {
        LOG_ERROR("coAuthSchedule is null");
        return NULL;
    }
    if (memset_s(coAuthSchedule, sizeof(CoAuthSchedule), 0, sizeof(CoAuthSchedule)) != EOK) {
        LOG_ERROR("reset coAuthSchedule failed");
        goto EXIT;
    }
    ResultCode ret = GenerateValidScheduleId(&coAuthSchedule->scheduleId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get scheduleId failed");
        goto EXIT;
    }

    coAuthSchedule->associateId.contextId = contextId;
    coAuthSchedule->templateId = templateId;
    coAuthSchedule->authSubType = authSubType;
    coAuthSchedule->scheduleMode = SCHEDULE_MODE_AUTH;

    ret = MountExecutor(authType, coAuthSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("mount failed");
        goto EXIT;
    }

    return coAuthSchedule;

EXIT:
    Free(coAuthSchedule);
    return NULL;
}

CoAuthSchedule *GenerateIdmSchedule(uint64_t challenge, uint32_t authType, uint64_t authSubType)
{
    CoAuthSchedule *coAuthSchedule = Malloc(sizeof(CoAuthSchedule));
    if (coAuthSchedule == NULL) {
        LOG_ERROR("coAuthSchedule is null");
        return NULL;
    }
    if (memset_s(coAuthSchedule, sizeof(CoAuthSchedule), 0, sizeof(CoAuthSchedule)) != EOK) {
        LOG_ERROR("reset coAuthSchedule failed");
        goto EXIT;
    }
    ResultCode ret = GenerateValidScheduleId(&coAuthSchedule->scheduleId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get scheduleId failed");
        goto EXIT;
    }

    coAuthSchedule->associateId.challenge = challenge;
    coAuthSchedule->authSubType = authSubType;
    coAuthSchedule->scheduleMode = SCHEDULE_MODE_ENROLL;

    ret = MountExecutor(authType, coAuthSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("mount failed");
        goto EXIT;
    }

    return coAuthSchedule;
EXIT:
    Free(coAuthSchedule);
    return NULL;
}