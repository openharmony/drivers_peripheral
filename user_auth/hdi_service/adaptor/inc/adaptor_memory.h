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

#ifndef ADAPTOR_MEMORY_H
#define ADAPTOR_MEMORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *Malloc(const size_t size);

void Free(void *ptr);

#define IAM_FREE_AND_SET_NULL(ptr)    \
    do {                              \
        Free(ptr);                    \
        (ptr) = NULL;                 \
    } while (0)

static inline bool IsAllZero(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (data[i] != 0) {
            return false;
        }
    }
    return true;
}

#ifdef __cplusplus
}
#endif

#endif
