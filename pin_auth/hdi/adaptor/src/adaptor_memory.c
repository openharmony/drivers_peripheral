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

#include "adaptor_memory.h"

#include <stdlib.h>
#define MAX_SIZE 1073741824

void *Malloc(const size_t size)
{
    if (size == 0 || size > MAX_SIZE) {
        return NULL;
    }
    return malloc(size);
}

void Free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr);
}