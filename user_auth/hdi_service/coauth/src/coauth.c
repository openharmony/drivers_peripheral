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

#include "coauth.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "pool.h"
#include "udid_manager.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

// Used to cache the ongoing coAuth scheduling.
IAM_STATIC LinkedList *g_scheduleList = NULL;

IAM_STATIC bool IsCoAuthInit(void)
{
    return g_scheduleList != NULL;
}

void DestroyScheduleNode(void *data)
{
    if (data == NULL) {
        LOG_ERROR("get null data");
        return;
    }
    CoAuthSchedule *schedule = (CoAuthSchedule *)data;
    if (schedule->templateIds.data != NULL) {
        Free(schedule->templateIds.data);
        schedule->templateIds.data = NULL;
    }
    Free(schedule);
}

CoAuthSchedule *CopyCoAuthSchedule(const CoAuthSchedule *coAuthSchedule)
{
    if (coAuthSchedule == NULL || !IsTemplateArraysValid(&(coAuthSchedule->templateIds))) {
        LOG_ERROR("coAuthSchedule is invalid");
        return NULL;
    }
    CoAuthSchedule *schedule = (CoAuthSchedule *)Malloc(sizeof(CoAuthSchedule));
    if (schedule == NULL) {
        LOG_ERROR("schedule is null");
        return NULL;
    }
    if (memcpy_s(schedule, sizeof(CoAuthSchedule), coAuthSchedule, sizeof(CoAuthSchedule)) != EOK) {
        LOG_ERROR("copy schedule failed");
        Free(schedule);
        return NULL;
    }
    schedule->templateIds.data = NULL;
    schedule->templateIds.len = 0;
    ResultCode ret = CopyTemplateArrays(&(coAuthSchedule->templateIds), &(schedule->templateIds));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("copy templateIds failed");
        Free(schedule);
        return NULL;
    }
    return schedule;
}

void DestroyCoAuthSchedule(CoAuthSchedule *coAuthSchedule)
{
    if (coAuthSchedule == NULL) {
        return;
    }
    DestroyScheduleNode(coAuthSchedule);
}

ResultCode InitCoAuth(void)
{
    if (!IsCoAuthInit()) {
        g_scheduleList = CreateLinkedList(DestroyScheduleNode);
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

ResultCode AddCoAuthSchedule(const CoAuthSchedule *coAuthSchedule)
{
    if (!IsCoAuthInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    if (coAuthSchedule == NULL) {
        LOG_ERROR("get null schedule");
        return RESULT_BAD_PARAM;
    }
    CoAuthSchedule *schedule = CopyCoAuthSchedule(coAuthSchedule);
    if (schedule == NULL) {
        LOG_ERROR("no memory");
        return RESULT_NO_MEMORY;
    }
    if (g_scheduleList->getSize(g_scheduleList) >= MAX_SCHEDULE_NUM) {
        LOG_ERROR("too many schedules already");
        DestroyCoAuthSchedule(schedule);
        return RESULT_GENERAL_ERROR;
    }
    ResultCode result = g_scheduleList->insert(g_scheduleList, schedule);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("insert failed");
        DestroyCoAuthSchedule(schedule);
    }
    LOG_INFO("success");
    return result;
}

IAM_STATIC bool IsScheduleMatch(const void *data, const void *condition)
{
    if ((condition == NULL) || (data == NULL)) {
        LOG_ERROR("get null data");
        return false;
    }
    uint64_t scheduleId = *(const uint64_t *)condition;
    const CoAuthSchedule *coAuthSchedule = (const CoAuthSchedule *)data;
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

const CoAuthSchedule *GetCoAuthSchedule(uint64_t scheduleId)
{
    if (!IsCoAuthInit()) {
        LOG_ERROR("pool not init");
        return NULL;
    }
    LinkedListIterator *iterator = g_scheduleList->createIterator(g_scheduleList);
    if (iterator == NULL) {
        LOG_ERROR("create iterator failed");
        return NULL;
    }
    CoAuthSchedule *schedule = NULL;
    while (iterator->hasNext(iterator)) {
        schedule = (CoAuthSchedule *)iterator->next(iterator);
        if (schedule == NULL) {
            LOG_ERROR("list node is null, please check");
            continue;
        }
        if (schedule->scheduleId != scheduleId) {
            continue;
        }
        g_scheduleList->destroyIterator(iterator);
        return schedule;
    }
    g_scheduleList->destroyIterator(iterator);
    LOG_ERROR("can't find this schedule");
    return NULL;
}

IAM_STATIC bool IsScheduleIdDuplicate(uint64_t scheduleId)
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

IAM_STATIC ResultCode GenerateValidScheduleId(uint64_t *scheduleId)
{
    if (g_scheduleList == NULL) {
        LOG_ERROR("g_scheduleList is null");
        return RESULT_BAD_PARAM;
    }

    for (uint32_t i = 0; i < MAX_DUPLICATE_CHECK; ++i) {
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

IAM_STATIC ResultCode MountExecutorOnce(const LinkedList *executors, CoAuthSchedule *coAuthSchedule,
    uint32_t sensorHint, uint32_t executorRole, Uint8Array deviceUdid)
{
    LinkedListNode *tempNode = executors->head;
    while (tempNode != NULL) {
        if (tempNode->data == NULL) {
            LOG_ERROR("data is null");
            return RESULT_UNKNOWN;
        }
        ExecutorInfoHal *executor = (ExecutorInfoHal *)tempNode->data;
        if (executor->executorRole != executorRole) {
            tempNode = tempNode->next;
            continue;
        }
        if (sensorHint != INVALID_SENSOR_HINT && sensorHint != executor->executorSensorHint) {
            tempNode = tempNode->next;
            continue;
        }

        if (memcmp(deviceUdid.data, executor->deviceUdid, UDID_LEN) != 0) {
            tempNode = tempNode->next;
            continue;
        }
        coAuthSchedule->executors[coAuthSchedule->executorSize] = *executor;
        ++(coAuthSchedule->executorSize);
        return RESULT_SUCCESS;
    }
    LOG_ERROR("mount executor failed");
    return RESULT_NOT_FOUND;
}

IAM_STATIC ResultCode MountExecutor(const ScheduleParam *param, CoAuthSchedule *coAuthSchedule)
{
    ExecutorCondition condition = {};
    SetExecutorConditionAuthType(&condition, param->authType);
    if (param->collectorSensorHint != INVALID_SENSOR_HINT || param->verifierSensorHint != INVALID_SENSOR_HINT) {
        SetExecutorConditionExecutorMatcher(&condition, param->executorMatcher);
    }
    LinkedList *executors = QueryExecutor(&condition);
    if (executors == NULL) {
        LOG_ERROR("query executor failed");
        return RESULT_UNKNOWN;
    }

    Uint8Array localUdidArray = { .data = (uint8_t *)(param->localUdid), .len = UDID_LEN };
    Uint8Array collectorUdidArray = { .data = (uint8_t *)(param->collectorUdid), .len = UDID_LEN };
    ResultCode ret;
    LOG_INFO("collectorSensorHint: %{public}u, verifierSensorHint: %{public}u", param->collectorSensorHint,
        param->verifierSensorHint);
    if ((param->collectorSensorHint == INVALID_SENSOR_HINT || param->verifierSensorHint == INVALID_SENSOR_HINT ||
        param->collectorSensorHint == param->verifierSensorHint) &&
        IsAllZero(param->collectorUdid, UDID_LEN)) {
        uint32_t allInOneSensorHint = param->verifierSensorHint | param->collectorSensorHint;
        LOG_INFO("mount all-in-one executor");
        ret = MountExecutorOnce(executors, coAuthSchedule, allInOneSensorHint, ALL_IN_ONE, localUdidArray);
        if (ret != RESULT_SUCCESS) {
            LOG_INFO("all-in-one executor is not found");
        }
        goto EXIT;
    }

    LOG_INFO("mount verifier and collector");
    if (param->scheduleMode == SCHEDULE_MODE_IDENTIFY) {
        LOG_ERROR("identification only supports all in one");
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }
    ret = MountExecutorOnce(executors, coAuthSchedule, param->verifierSensorHint, VERIFIER, localUdidArray);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("verifier is not found");
        goto EXIT;
    }

    ret = MountExecutorOnce(executors, coAuthSchedule, param->collectorSensorHint, COLLECTOR, collectorUdidArray);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("collector is not found");
    }

EXIT:
    DestroyLinkedList(executors);
    return ret;
}

uint32_t GetScheduleVerifierSensorHint(const CoAuthSchedule *coAuthSchedule)
{
    if (coAuthSchedule == NULL) {
        LOG_ERROR("coAuthSchedule is null");
        return INVALID_SENSOR_HINT;
    }
    for (uint32_t i = 0; i < coAuthSchedule->executorSize; ++i) {
        const ExecutorInfoHal *executor = coAuthSchedule->executors + i;
        if (executor->executorRole == VERIFIER || executor->executorRole == ALL_IN_ONE) {
            return executor->executorSensorHint;
        }
    }
    LOG_ERROR("not found");
    return INVALID_SENSOR_HINT;
}

CoAuthSchedule *GenerateSchedule(const ScheduleParam *param)
{
    if (param == NULL) {
        LOG_ERROR("param is invalid");
        return NULL;
    }
    CoAuthSchedule *coAuthSchedule = Malloc(sizeof(CoAuthSchedule));
    if (coAuthSchedule == NULL) {
        LOG_ERROR("coAuthSchedule is null");
        return NULL;
    }
    if (memset_s(coAuthSchedule, sizeof(CoAuthSchedule), 0, sizeof(CoAuthSchedule)) != EOK) {
        LOG_ERROR("reset coAuthSchedule failed");
        Free(coAuthSchedule);
        return NULL;
    }
    ResultCode ret = GenerateValidScheduleId(&coAuthSchedule->scheduleId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get scheduleId failed");
        goto FAIL;
    }
    coAuthSchedule->associateId = param->associateId;
    coAuthSchedule->scheduleMode = param->scheduleMode;
    coAuthSchedule->authType = param->authType;
    coAuthSchedule->userType = param->userType;
    if (param->templateIds != NULL) {
        ret = CopyTemplateArrays(param->templateIds, &(coAuthSchedule->templateIds));
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("copy template failed");
            goto FAIL;
        }
    }

    ret = MountExecutor(param, coAuthSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("mount failed");
        goto FAIL;
    }
    return coAuthSchedule;
FAIL:
    DestroyCoAuthSchedule(coAuthSchedule);
    return NULL;
}

bool IsTemplateArraysValid(const Uint64Array *templateIds)
{
    if (templateIds == NULL) {
        LOG_ERROR("templateIds is null");
        return false;
    }
    if (templateIds->len > MAX_TEMPLATE_OF_SCHEDULE || (templateIds->len != 0 && templateIds->data == NULL)) {
        LOG_ERROR("templateIds's content is invalid");
        return false;
    }
    return true;
}

ResultCode CopyTemplateArrays(const Uint64Array *in, Uint64Array *out)
{
    if (!IsTemplateArraysValid(in) || out == NULL || out->data != NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    if (in->len == 0) {
        out->len = 0;
        return RESULT_SUCCESS;
    }
    out->len = in->len;
    out->data = (uint64_t *)Malloc(sizeof(uint64_t) * out->len);
    if (out->data == NULL) {
        LOG_ERROR("out data is null");
        out->len = 0;
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(out->data, (sizeof(uint64_t) * out->len), in->data, (sizeof(uint64_t) * in->len)) != EOK) {
        LOG_ERROR("copy failed");
        Free(out->data);
        out->data = NULL;
        out->len = 0;
        return RESULT_BAD_COPY;
    }
    return RESULT_SUCCESS;
}