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

#include "c_array.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"

void DestroyUint8Array(Uint8Array **array)
{
    IF_TRUE_LOGE_AND_RETURN(array == NULL);
    if (*array == NULL) {
        return;
    }
    if ((*array)->len != 0 && ((*array)->len < UINT32_MAX / sizeof(uint8_t))) {
        uint32_t arraySize = sizeof(uint8_t) * (*array)->len;
        (void)memset_s((*array)->data, arraySize, 0, arraySize);
    }
    IAM_FREE_AND_SET_NULL((*array)->data);
    IAM_FREE_AND_SET_NULL(*array);
}

void DestroyUint64Array(Uint64Array **array)
{
    IF_TRUE_LOGE_AND_RETURN(array == NULL);
    if (*array == NULL) {
        return;
    }
    if ((*array)->len != 0 && ((*array)->len < UINT32_MAX / sizeof(uint64_t))) {
        uint32_t arraySize = sizeof(uint64_t) * (*array)->len;
        (void)memset_s((*array)->data, arraySize, 0, arraySize);
    }
    IAM_FREE_AND_SET_NULL((*array)->data);
    IAM_FREE_AND_SET_NULL(*array);
}

Uint8Array *CreateUint8ArrayBySize(uint32_t size)
{
    Uint8Array *array = Malloc(sizeof(Uint8Array));
    IF_TRUE_LOGE_AND_RETURN_VAL(array == NULL, NULL);
    if (size == 0) {
        LOG_INFO("create an empty uint8_t array");
        return array;
    }
    array->data = Malloc(size);
    if (array->data == NULL) {
        LOG_ERROR("malloc fail");
        Free(array);
        return NULL;
    }
    array->len = size;

    return array;
}

Uint8Array *CreateUint8ArrayByData(const uint8_t *data, uint32_t len)
{
    if (data == NULL && len != 0) {
        LOG_ERROR("invalid para");
        return NULL;
    }

    Uint8Array *array = CreateUint8ArrayBySize(len);
    IF_TRUE_LOGE_AND_RETURN_VAL(array == NULL, NULL);
    if (len == 0) {
        return array;
    }

    if (memcpy_s(array->data, len, data, len) != EOK) {
        LOG_ERROR("memcpy fail");
        DestroyUint8Array(&array);
        return NULL;
    }
    array->len = len;

    return array;
}

Uint64Array *CreateUint64ArrayByData(const uint64_t *data, uint32_t len)
{
    if ((data == NULL && len != 0) || (len > UINT32_MAX / sizeof(uint64_t))) {
        LOG_ERROR("invalid para");
        return NULL;
    }

    Uint64Array *array = Malloc(sizeof(Uint64Array));
    IF_TRUE_LOGE_AND_RETURN_VAL(array == NULL, NULL);

    if (len == 0) {
        return array;
    }

    array->data = Malloc(len * sizeof(uint64_t));
    if (array->data == NULL) {
        LOG_ERROR("malloc fail");
        Free(array);
        return NULL;
    }

    if (memcpy_s(array->data, len * sizeof(uint64_t), data, len * sizeof(uint64_t)) != EOK) {
        LOG_ERROR("memcpy fail");
        DestroyUint64Array(&array);
        return NULL;
    }
    array->len = len;

    return array;
}