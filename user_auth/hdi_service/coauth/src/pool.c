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

#include "pool.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"

#define MAX_DUPLICATE_CHECK 100
#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

// Resource pool list, which caches registered executor information.
IAM_STATIC LinkedList *g_poolList = NULL;

IAM_STATIC void DestroyExecutorInfo(void *data)
{
    if (data == NULL) {
        LOG_ERROR("data is null");
        return;
    }
    Free(data);
}

IAM_STATIC bool IsExecutorIdMatchById(const void *data, const void *condition)
{
    if ((condition == NULL) || (data == NULL)) {
        LOG_ERROR("input para is null");
        return false;
    }
    uint64_t executorIndex = *(const uint64_t *)condition;
    const ExecutorInfoHal *executorInfo = (const ExecutorInfoHal *)data;
    return (executorInfo->executorIndex == executorIndex);
}

IAM_STATIC bool IsExecutorNodeMatch(const void *data, const void *condition)
{
    if ((condition == NULL) || (data == NULL)) {
        LOG_ERROR("get null data");
        return false;
    }
    const ExecutorInfoHal *executorIndex = (const ExecutorInfoHal *)condition;
    const ExecutorInfoHal *executorInfo = (const ExecutorInfoHal *)data;
    return (executorInfo->executorRole == executorIndex->executorRole &&
        executorInfo->authType == executorIndex->authType &&
        executorInfo->executorSensorHint == executorIndex->executorSensorHint) &&
        memcmp(executorInfo->deviceUdid, executorIndex->deviceUdid, UDID_LEN) == 0;
}

IAM_STATIC bool IsInit(void)
{
    return g_poolList != NULL;
}

ResultCode InitResourcePool(void)
{
    if (!IsInit()) {
        g_poolList = CreateLinkedList(DestroyExecutorInfo);
    }
    if (g_poolList == NULL) {
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

void DestroyResourcePool(void)
{
    DestroyLinkedList(g_poolList);
    g_poolList = NULL;
}

IAM_STATIC bool IsExecutorValid(const ExecutorInfoHal *executorInfo)
{
    if (executorInfo == NULL) {
        LOG_ERROR("get null data");
        return false;
    }
    return true;
}

IAM_STATIC bool IsExecutorIdDuplicate(uint64_t executorIndex)
{
    LinkedListNode *temp = g_poolList->head;
    ExecutorInfoHal *executorInfo = NULL;
    while (temp != NULL) {
        executorInfo = (ExecutorInfoHal *)temp->data;
        if (executorInfo != NULL && executorInfo->executorIndex == executorIndex) {
            return true;
        }
        temp = temp->next;
    }

    return false;
}

IAM_STATIC ResultCode GenerateValidExecutorId(uint64_t *executorIndex)
{
    if (g_poolList == NULL) {
        LOG_ERROR("g_poolList is null");
        return RESULT_BAD_PARAM;
    }

    for (uint32_t i = 0; i < MAX_DUPLICATE_CHECK; ++i) {
        uint64_t tempRandom;
        if (SecureRandom((uint8_t *)&tempRandom, sizeof(uint64_t)) != RESULT_SUCCESS) {
            LOG_ERROR("get random failed");
            return RESULT_GENERAL_ERROR;
        }
        if (!IsExecutorIdDuplicate(tempRandom)) {
            *executorIndex = tempRandom;
            return RESULT_SUCCESS;
        }
    }

    LOG_ERROR("a rare failure");
    return RESULT_GENERAL_ERROR;
}

IAM_STATIC LinkedList *QueryRepeatExecutor(ExecutorInfoHal *executorInfo)
{
    ExecutorCondition condition = {};
    SetExecutorConditionAuthType(&condition, executorInfo->authType);
    SetExecutorConditionSensorHint(&condition, executorInfo->executorSensorHint);
    SetExecutorConditionExecutorRole(&condition, executorInfo->executorRole);
    const Uint8Array udid = { executorInfo->deviceUdid, UDID_LEN };
    SetExecutorConditionDeviceUdid(&condition, udid);
    return QueryExecutor(&condition);
}

ResultCode RegisterExecutorToPool(ExecutorInfoHal *executorInfo)
{
    if (!IsInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    if (!IsExecutorValid(executorInfo)) {
        LOG_ERROR("get invalid executorInfo");
        return RESULT_BAD_PARAM;
    }
    LinkedList *executors = QueryRepeatExecutor(executorInfo);
    if (executors == NULL) {
        LOG_ERROR("query executor failed");
        return RESULT_NO_MEMORY;
    }
    ResultCode result = RESULT_UNKNOWN;
    if (executors->getSize(executors) != 0) {
        if (executors->head == NULL || executors->head->data == NULL) {
            LOG_ERROR("list node is invalid");
            goto EXIT;
        }
        executorInfo->executorIndex = ((ExecutorInfoHal *)(executors->head->data))->executorIndex;
        if (g_poolList->remove(g_poolList, (void *)executorInfo, IsExecutorNodeMatch, true) != RESULT_SUCCESS) {
            LOG_INFO("remove executor failed");
            goto EXIT;
        }
    } else {
        result = GenerateValidExecutorId(&executorInfo->executorIndex);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("get executorId failed");
            goto EXIT;
        }
    }
    ExecutorInfoHal *executorCopy = CopyExecutorInfo(executorInfo);
    if (executorCopy == NULL) {
        LOG_ERROR("copy executor failed");
        result = RESULT_BAD_COPY;
        goto EXIT;
    }
    result = g_poolList->insert(g_poolList, (void *)executorCopy);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("insert failed");
        DestroyExecutorInfo(executorCopy);
    }

EXIT:
    DestroyLinkedList(executors);
    return result;
}

ResultCode UnregisterExecutorToPool(uint64_t executorIndex)
{
    if (!IsInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    return g_poolList->remove(g_poolList, (void *)&executorIndex, IsExecutorIdMatchById, true);
}

ExecutorInfoHal *CopyExecutorInfo(ExecutorInfoHal *src)
{
    if (src == NULL) {
        LOG_ERROR("get null data");
        return NULL;
    }
    ExecutorInfoHal *dest = (ExecutorInfoHal *)Malloc(sizeof(ExecutorInfoHal));
    if (dest == NULL) {
        LOG_ERROR("no memory");
        return NULL;
    }
    if (memcpy_s(dest, sizeof(ExecutorInfoHal), src, sizeof(ExecutorInfoHal)) != EOK) {
        LOG_ERROR("copy executor info failed");
        Free(dest);
        return NULL;
    }
    return dest;
}

IAM_STATIC bool IsExecutorMatch(const ExecutorCondition *condition, const ExecutorInfoHal *credentialInfo)
{
    if ((condition->conditonFactor & EXECUTOR_CONDITION_INDEX) != 0 &&
        condition->executorIndex != credentialInfo->executorIndex) {
        return false;
    }
    if ((condition->conditonFactor & EXECUTOR_CONDITION_AUTH_TYPE) != 0 &&
        condition->authType != credentialInfo->authType) {
        return false;
    }
    if ((condition->conditonFactor & EXECUTOR_CONDITION_SENSOR_HINT) != 0 &&
        condition->executorSensorHint != INVALID_SENSOR_HINT &&
        condition->executorSensorHint != credentialInfo->executorSensorHint) {
        return false;
    }
    if ((condition->conditonFactor & EXECUTOR_CONDITION_ROLE) != 0 &&
        condition->executorRole != credentialInfo->executorRole) {
        return false;
    }
    if ((condition->conditonFactor & EXECUTOR_CONDITION_MATCHER) != 0 &&
        condition->executorMatcher != credentialInfo->executorMatcher) {
        return false;
    }
    if ((condition->conditonFactor & EXECUTOR_CONDITION_UDID) != 0 &&
        memcmp(condition->deviceUdid, credentialInfo->deviceUdid, UDID_LEN) != 0) {
        return false;
    }
    return true;
}

LinkedList *QueryExecutor(const ExecutorCondition *condition)
{
    if (!IsInit()) {
        LOG_ERROR("pool not init");
        return NULL;
    }
    LinkedList *result = CreateLinkedList(DestroyExecutorInfo);
    if (result == NULL) {
        LOG_ERROR("create result list failed");
        return NULL;
    }
    LinkedListIterator *iterator = g_poolList->createIterator(g_poolList);
    if (iterator == NULL) {
        LOG_ERROR("create iterator failed");
        DestroyLinkedList(result);
        return NULL;
    }

    while (iterator->hasNext(iterator)) {
        ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)iterator->next(iterator);
        if (!IsExecutorValid(executorInfo)) {
            LOG_ERROR("get invalid executor info");
            continue;
        }
        if (!IsExecutorMatch(condition, executorInfo)) {
            continue;
        }
        ExecutorInfoHal *copy = CopyExecutorInfo(executorInfo);
        if (copy == NULL) {
            LOG_ERROR("copy executor info failed");
            continue;
        }
        if (result->insert(result, copy) != RESULT_SUCCESS) {
            LOG_ERROR("insert executor info failed");
            DestroyExecutorInfo(copy);
            continue;
        }
    }
    g_poolList->destroyIterator(iterator);
    return result;
}

ResultCode QueryCollecterMatcher(uint32_t authType, uint32_t executorSensorHint, uint32_t *matcher)
{
    if (!IsInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    if (matcher == NULL) {
        LOG_ERROR("matcher is null");
        return RESULT_BAD_PARAM;
    }
    LinkedListIterator *iterator = g_poolList->createIterator(g_poolList);
    if (iterator == NULL) {
        LOG_ERROR("create iterator failed");
        return RESULT_NO_MEMORY;
    }

    while (iterator->hasNext(iterator)) {
        ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)(iterator->next(iterator));
        if (!IsExecutorValid(executorInfo)) {
            LOG_ERROR("get invalid executor info");
            continue;
        }
        if (executorInfo->authType == authType && executorInfo->executorSensorHint == executorSensorHint &&
            (executorInfo->executorRole == COLLECTOR || executorInfo->executorRole == ALL_IN_ONE)) {
            *matcher = executorInfo->executorMatcher;
            g_poolList->destroyIterator(iterator);
            return RESULT_SUCCESS;
        }
    }
    LOG_ERROR("can't found executor, sensor hint is %{public}u", executorSensorHint);
    g_poolList->destroyIterator(iterator);
    return RESULT_NOT_FOUND;
}


uint64_t QueryCredentialExecutorIndex(uint32_t authType, uint32_t executorSensorHint)
{
    if (!IsInit()) {
        LOG_ERROR("pool not init");
        return INVALID_EXECUTOR_INDEX;
    }
    LinkedListIterator *iterator = g_poolList->createIterator(g_poolList);
    if (iterator == NULL) {
        LOG_ERROR("create iterator failed");
        return INVALID_EXECUTOR_INDEX;
    }

    while (iterator->hasNext(iterator)) {
        ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)(iterator->next(iterator));
        if (!IsExecutorValid(executorInfo)) {
            LOG_ERROR("get invalid executor info");
            continue;
        }
        if (executorInfo->authType == authType && executorInfo->executorSensorHint == executorSensorHint &&
            executorInfo->executorRole == ALL_IN_ONE) {
            g_poolList->destroyIterator(iterator);
            return executorInfo->executorIndex;
        }
    }
    LOG_ERROR("can't found executor, sensor hint is %{public}u", executorSensorHint);
    g_poolList->destroyIterator(iterator);
    return INVALID_EXECUTOR_INDEX;
}


void SetExecutorConditionExecutorIndex(ExecutorCondition *condition, uint64_t executorIndex)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->executorIndex = executorIndex;
    condition->conditonFactor |= EXECUTOR_CONDITION_INDEX;
}

void SetExecutorConditionAuthType(ExecutorCondition *condition, uint32_t authType)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->authType = authType;
    condition->conditonFactor |= EXECUTOR_CONDITION_AUTH_TYPE;
}

void SetExecutorConditionSensorHint(ExecutorCondition *condition, uint32_t executorSensorHint)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->executorSensorHint = executorSensorHint;
    condition->conditonFactor |= EXECUTOR_CONDITION_SENSOR_HINT;
}

void SetExecutorConditionExecutorRole(ExecutorCondition *condition, uint32_t executorRole)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->executorRole = executorRole;
    condition->conditonFactor |= EXECUTOR_CONDITION_ROLE;
}

void SetExecutorConditionExecutorMatcher(ExecutorCondition *condition, uint32_t executorMatcher)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->executorMatcher = executorMatcher;
    condition->conditonFactor |= EXECUTOR_CONDITION_MATCHER;
}

void SetExecutorConditionDeviceUdid(ExecutorCondition *condition, Uint8Array deviceUdid)
{
    if (condition == NULL || IS_ARRAY_NULL(deviceUdid)) {
        LOG_ERROR("condition is null");
        return;
    }
    if (memcpy_s(condition->deviceUdid, UDID_LEN, deviceUdid.data, deviceUdid.len) != EOK) {
        LOG_ERROR("copy udid failed");
        return;
    }
    condition->conditonFactor |= EXECUTOR_CONDITION_UDID;
}