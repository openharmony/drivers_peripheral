/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "file_manager_utils.h"

#define MAX_BUFFER_LEN 512000
#define DEFAULT_EXPANSION_RATIO 2

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

IAM_STATIC uint32_t GetRemainSpace(const Buffer *object)
{
    return object->maxSize - object->contentSize;
}

IAM_STATIC uint8_t *GetStreamAddress(const Buffer *object)
{
    return object->buf + object->contentSize;
}

IAM_STATIC ResultCode CapacityExpansion(Buffer *object, uint32_t targetCapacity)
{
    if (!IsBufferValid(object) || object->maxSize > MAX_BUFFER_LEN / DEFAULT_EXPANSION_RATIO) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    uint32_t targetSize = object->maxSize;
    while (targetSize < targetCapacity && targetSize <= MAX_BUFFER_LEN / DEFAULT_EXPANSION_RATIO) {
        targetSize = targetSize * DEFAULT_EXPANSION_RATIO;
    }
    if (targetSize < targetCapacity) {
        LOG_ERROR("target capacity can not reach");
        return RESULT_BAD_PARAM;
    }
    uint8_t *buf = Malloc(targetSize);
    if (buf == NULL) {
        LOG_ERROR("malloc failed");
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(buf, targetSize, object->buf, object->contentSize) != EOK) {
        LOG_ERROR("copy failed");
        Free(buf);
        return RESULT_NO_MEMORY;
    }
    Free(object->buf);
    object->buf = buf;
    object->maxSize = targetSize;
    return RESULT_SUCCESS;
}

ResultCode StreamWrite(Buffer *parcel, void *from, uint32_t size)
{
    if (!IsBufferValid(parcel) || from == NULL) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    if (GetRemainSpace(parcel) < size) {
        ResultCode result = CapacityExpansion(parcel, size);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("CapacityExpansion failed");
            return result;
        }
    }
    if (memcpy_s(GetStreamAddress(parcel), GetRemainSpace(parcel), from, size) != EOK) {
        LOG_ERROR("copy failed");
        return RESULT_NO_MEMORY;
    }
    parcel->contentSize += size;
    return RESULT_SUCCESS;
}

ResultCode StreamRead(Buffer *parcel, uint32_t *index, void *to, uint32_t size)
{
    if (parcel->contentSize <= *index || parcel->contentSize - *index < size) {
        LOG_ERROR("the buffer length is insufficient");
        return RESULT_BAD_PARAM;
    }
    if (memcpy_s(to, size, parcel->buf + *index, size) != EOK) {
        LOG_ERROR("copy failed");
        return RESULT_NO_MEMORY;
    }
    *index += size;
    return RESULT_SUCCESS;
}
