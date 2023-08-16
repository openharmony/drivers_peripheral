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

#ifndef COMMON_LINKED_LIST_H
#define COMMON_LINKED_LIST_H

#include <stdbool.h>
#include <stdint.h>
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*DestroyDataFunc)(void *data);
typedef bool (*MatchFunc)(const void *data, const void *condition);

typedef struct LinkedListNode {
    void *data;
    struct LinkedListNode *next;
} LinkedListNode;

typedef struct LinkedListIterator {
    LinkedListNode *current;
    bool (*hasNext)(struct LinkedListIterator *iterator);
    void *(*next)(struct LinkedListIterator *iterator);
} LinkedListIterator;

typedef struct LinkedList {
    uint32_t size;
    LinkedListNode *head;
    DestroyDataFunc destroyDataFunc;
    uint32_t (*getSize)(struct LinkedList *list);
    ResultCode (*insert)(struct LinkedList *list, void *data);
    ResultCode (*remove)(struct LinkedList *list, void *condition, MatchFunc matchFunc, bool destroyNode);
    LinkedListIterator *(*createIterator)(struct LinkedList *list);
    void (*destroyIterator)(LinkedListIterator *iterator);
} LinkedList;

LinkedList *CreateLinkedList(DestroyDataFunc destroyDataFunc);
void DestroyLinkedList(LinkedList *list);

#ifdef __cplusplus
}
#endif

#endif
