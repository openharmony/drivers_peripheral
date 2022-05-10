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

// Resource pool list, which caches registered executor information.
static LinkedList *g_poolList = NULL;

static void DestroyExecutorInfo(void *data)
{
    if (data  == NULL) {
        LOG_ERROR("data is null");
        return;
    }
    Free(data);
}

static bool IsExecutorIdMatchById(void *data, void *condition)
{
    if ((condition == NULL) || (data == NULL)) {
        LOG_ERROR("input para is null");
        return false;
    }
    uint64_t executorId = *(uint64_t *)condition;
    ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)data;
    return (executorInfo->executorId == executorId);
}

static bool IsExecutorIdMatchByType(void *data, void *condition)
{
    if ((condition == NULL) || (data == NULL)) {
        LOG_ERROR("get null data");
        return false;
    }
    ExecutorInfoHal *executorIndex = (ExecutorInfoHal *)condition;
    ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)data;
    return (executorInfo->executorType == executorIndex->executorType &&
        executorInfo->authType == executorIndex->authType);
}

static bool IsInit()
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

static bool IsExecutorValid(ExecutorInfoHal *executorInfo)
{
    if (executorInfo == NULL) {
        LOG_ERROR("get null data");
        return false;
    }
    return true;
}

static bool IsExecutorIdDuplicate(uint64_t executorId)
{
    LinkedListNode *temp = g_poolList->head;
    ExecutorInfoHal *executorInfo = NULL;
    while (temp != NULL) {
        executorInfo = (ExecutorInfoHal *)temp->data;
        if (executorInfo != NULL && executorInfo->executorId == executorId) {
            return true;
        }
        temp = temp->next;
    }

    return false;
}

static ResultCode GenerateValidExecutorId(uint64_t *executorId)
{
    if (g_poolList == NULL) {
        LOG_ERROR("g_poolList is null");
        return RESULT_BAD_PARAM;
    }

    for (uint32_t i = 0; i < MAX_DUPLICATE_CHECK; i++) {
        uint64_t tempRandom;
        if (SecureRandom((uint8_t *)&tempRandom, sizeof(uint64_t)) != RESULT_SUCCESS) {
            LOG_ERROR("get random failed");
            return RESULT_GENERAL_ERROR;
        }
        if (!IsExecutorIdDuplicate(tempRandom)) {
            *executorId = tempRandom;
            return RESULT_SUCCESS;
        }
    }

    LOG_ERROR("a rare failure");
    return RESULT_GENERAL_ERROR;
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
    if (g_poolList->remove(g_poolList, (void *)executorInfo, IsExecutorIdMatchByType, true) != RESULT_SUCCESS) {
        LOG_INFO("current executor isn't registered");
    }
    ResultCode result = GenerateValidExecutorId(&executorInfo->executorId);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("get executorId failed");
        return result;
    }
    ExecutorInfoHal *executorCopy = CopyExecutorInfo(executorInfo);
    if (executorCopy == NULL) {
        LOG_ERROR("copy executor failed");
        return RESULT_NO_MEMORY;
    }
    result = g_poolList->insert(g_poolList, (void *)executorCopy);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("insert failed");
        DestroyExecutorInfo(executorCopy);
        return result;
    }
    return result;
}

ResultCode UnregisterExecutorToPool(uint64_t executorId)
{
    if (!IsInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    return g_poolList->remove(g_poolList, (void *)&executorId, IsExecutorIdMatchById, true);
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

ResultCode QueryExecutor(uint32_t authType, LinkedList **result)
{
    if (!IsInit()) {
        LOG_ERROR("pool not init");
        return RESULT_NEED_INIT;
    }
    if (result == NULL) {
        LOG_ERROR("get null data");
        return RESULT_BAD_PARAM;
    }
    *result = CreateLinkedList(DestroyExecutorInfo);
    if (*result == NULL) {
        LOG_ERROR("create result list failed");
        return RESULT_NO_MEMORY;
    }
    LinkedListIterator *iterator = g_poolList->createIterator(g_poolList);
    if (iterator == NULL) {
        LOG_ERROR("create iterator failed");
        DestroyLinkedList(*result);
        return RESULT_NO_MEMORY;
    }

    while (iterator->hasNext(iterator)) {
        ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)iterator->next(iterator);
        if (!IsExecutorValid(executorInfo)) {
            LOG_ERROR("get invalid executor info");
            continue;
        }
        if (executorInfo->authType != authType) {
            continue;
        }
        ExecutorInfoHal *copy = CopyExecutorInfo(executorInfo);
        if (copy == NULL) {
            LOG_ERROR("copy executor info failed");
            continue;
        }
        if ((*result)->insert(*result, copy) != RESULT_SUCCESS) {
            LOG_ERROR("insert executor info failed");
            DestroyExecutorInfo(copy);
            continue;
        }
    }
    g_poolList->destroyIterator(iterator);
    return RESULT_SUCCESS;
}