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

#include "linked_list.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"

static ResultCode InsertNode(LinkedList *list, void *data)
{
    if (list == NULL) {
        LOG_ERROR("list is null");
        return RESULT_BAD_PARAM;
    }
    if (list->size == UINT32_MAX) {
        LOG_ERROR("reach limit");
        return RESULT_REACH_LIMIT;
    }
    LinkedListNode *node = Malloc(sizeof(LinkedListNode));
    if (node == NULL) {
        LOG_ERROR("no memory");
        return RESULT_NO_MEMORY;
    }
    node->data = data;
    node->next = list->head;
    list->head = node;
    list->size++;
    return RESULT_SUCCESS;
}

static ResultCode RemoveNode(LinkedList *list, void *condition, MatchFunc matchFunc, bool destroyNode)
{
    if (list == NULL) {
        LOG_ERROR("list is null");
        return RESULT_BAD_PARAM;
    }
    if (matchFunc == NULL) {
        LOG_ERROR("matchFunc is null");
        return RESULT_BAD_PARAM;
    }
    LinkedListNode *pre = NULL;
    LinkedListNode *node = list->head;
    while (node != NULL) {
        if (matchFunc(node->data, condition)) {
            break;
        }
        pre = node;
        node = node->next;
    }
    if (node == NULL) {
        return RESULT_NOT_FOUND;
    }
    if (pre == NULL) {
        list->head = node->next;
    } else {
        pre->next = node->next;
    }
    list->size--;
    node->next = NULL;
    if (destroyNode) {
        if (list->destroyDataFunc != NULL) {
            list->destroyDataFunc(node->data);
        }
        Free(node);
    }
    return RESULT_SUCCESS;
}

static uint32_t GetSize(LinkedList *list)
{
    if (list == NULL) {
        LOG_ERROR("list is null");
        return 0;
    }
    return list->size;
}

static bool IteratorHasNext(LinkedListIterator *iterator)
{
    if (iterator == NULL) {
        LOG_ERROR("iterator is null");
        return false;
    }
    return iterator->current != NULL;
}

static void *IteratorNext(LinkedListIterator *iterator)
{
    if (!IteratorHasNext(iterator)) {
        LOG_ERROR("reach end");
        return NULL;
    }
    LinkedListNode *current = iterator->current;
    iterator->current = current->next;
    return current->data;
}

static LinkedListIterator *CreateIterator(struct LinkedList *list)
{
    if (list == NULL) {
        LOG_ERROR("list is null");
        return NULL;
    }
    LinkedListIterator *iterator = (LinkedListIterator *)Malloc(sizeof(LinkedListIterator));
    if (iterator == NULL) {
        LOG_ERROR("malloc failed");
        return NULL;
    }
    iterator->current = list->head;
    iterator->hasNext = IteratorHasNext;
    iterator->next = IteratorNext;
    return iterator;
}

static void DestroyIterator(LinkedListIterator *iterator)
{
    if (iterator == NULL) {
        LOG_ERROR("iterator is null");
        return;
    }
    Free(iterator);
}

LinkedList *CreateLinkedList(DestroyDataFunc destroyDataFunc)
{
    if (destroyDataFunc == NULL) {
        LOG_ERROR("destroyDataFunc is null");
        return NULL;
    }
    LinkedList *list = Malloc(sizeof(LinkedList));
    if (list == NULL) {
        LOG_ERROR("no memory");
        return NULL;
    }
    list->size = 0;
    list->head = NULL;
    list->destroyDataFunc = destroyDataFunc;
    list->getSize = GetSize;
    list->insert = InsertNode;
    list->remove = RemoveNode;
    list->createIterator = CreateIterator;
    list->destroyIterator = DestroyIterator;
    return list;
}

static void DestroyLinkedListNode(const LinkedList *list, LinkedListNode *node)
{
    if (node == NULL) {
        LOG_ERROR("node is null");
        return;
    }
    if ((list != NULL) && (list->destroyDataFunc != NULL)) {
        list->destroyDataFunc(node->data);
    }
    Free(node);
}

void DestroyLinkedList(LinkedList *list)
{
    if (list == NULL) {
        LOG_ERROR("list is null");
        return;
    }
    while (list->head != NULL) {
        LinkedListNode *node = list->head;
        list->head = node->next;
        DestroyLinkedListNode(list, node);
    }
    Free(list);
}
