/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef IAM_C_ARRAY_H
#define IAM_C_ARRAY_H

#include <stdint.h>
#include <string.h>

#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IS_ARRAY_NULL(array) ((array).data == NULL || (array).len == 0)
#define IS_ARRAY_VALID(array) ((array).data != NULL || ((array).data == NULL && (array).len == 0))

typedef struct Uint8Array {
    uint8_t *data;
    uint32_t len;
} Uint8Array;

typedef struct Uint64Array {
    uint64_t *data;
    uint32_t len;
} Uint64Array;

inline bool Uint8ArrayIsSame(const Uint8Array array1, const Uint8Array array2)
{
    if (array1.len != array2.len) {
        return false;
    }
    if (array1.data == NULL || array2.data == NULL) {
        return false;
    }
    return memcmp(array1.data, array2.data, array1.len) == 0;
}

void DestroyUint8Array(Uint8Array **array);
void DestroyUint64Array(Uint64Array **array);
Uint8Array *CreateUint8ArrayBySize(uint32_t size);
Uint8Array *CreateUint8ArrayByData(const uint8_t *data, uint32_t len);
Uint64Array *CreateUint64ArrayByData(const uint64_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif // IAM_C_ARRAY_H