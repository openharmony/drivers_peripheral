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

#include "buffer.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"

#define MAX_BUFFER_SIZE 512000

bool IsBufferValid(const Buffer *buffer)
{
    if ((buffer == NULL) || (buffer->buf == NULL) ||
        (buffer->maxSize == 0) || (buffer->maxSize > MAX_BUFFER_SIZE) ||
        (buffer->contentSize > buffer->maxSize)) {
        return false;
    }

    return true;
}

Buffer GetTmpBuffer(uint8_t *buf, uint32_t contentSize, uint32_t maxSize)
{
    Buffer ret = {
        .buf = buf,
        .contentSize = contentSize,
        .maxSize = maxSize,
    };
    return ret;
}

bool CheckBufferWithSize(const Buffer *buffer, const uint32_t size)
{
    if ((!IsBufferValid(buffer)) || (buffer->contentSize != size)) {
        return false;
    }

    return true;
}

Buffer *CreateBufferBySize(const uint32_t size)
{
    if ((size == 0) || (size > MAX_BUFFER_SIZE)) {
        LOG_ERROR("invalid param, size: %u", size);
        return NULL;
    }

    Buffer *buffer = (Buffer *)Malloc(sizeof(Buffer));
    if (buffer == NULL) {
        LOG_ERROR("malloc buffer struct failed");
        return NULL;
    }

    buffer->buf = (uint8_t *)Malloc(size);
    if (buffer->buf == NULL) {
        LOG_ERROR("malloc buffer data failed");
        Free(buffer);
        return NULL;
    }

    if (memset_s(buffer->buf, size, 0, size) != EOK) {
        Free(buffer->buf);
        Free(buffer);
        return NULL;
    }
    buffer->maxSize = size;
    buffer->contentSize = 0;

    return buffer;
}

Buffer *CreateBufferByData(const uint8_t *data, const uint32_t dataSize)
{
    if ((data == NULL) || (dataSize == 0) || (dataSize > MAX_BUFFER_SIZE)) {
        LOG_ERROR("invalid param, dataSize: %u", dataSize);
        return NULL;
    }

    Buffer *buffer = (Buffer *)Malloc(sizeof(Buffer));
    if (buffer == NULL) {
        LOG_ERROR("malloc buffer struct failed");
        return NULL;
    }

    buffer->buf = (uint8_t *)Malloc(dataSize);
    if (buffer->buf == NULL) {
        LOG_ERROR("malloc buffer data failed");
        Free(buffer);
        return NULL;
    }

    if (memcpy_s(buffer->buf, dataSize, data, dataSize) != EOK) {
        LOG_ERROR("copy buffer failed");
        DestoryBuffer(buffer);
        return NULL;
    }
    buffer->maxSize = dataSize;
    buffer->contentSize = dataSize;

    return buffer;
}

void DestoryBuffer(Buffer *buffer)
{
    if (buffer != NULL) {
        if (buffer->buf != NULL) {
            if (memset_s(buffer->buf, buffer->maxSize, 0, buffer->maxSize) != EOK) {
                LOG_ERROR("memset_s failed");
            }
            Free(buffer->buf);
            buffer->buf = NULL;
            buffer->contentSize = 0;
            buffer->maxSize = 0;
        }
        Free(buffer);
    }
}

Buffer *CopyBuffer(const Buffer *buffer)
{
    if (!IsBufferValid(buffer)) {
        LOG_ERROR("invalid buffer");
        return NULL;
    }

    Buffer *copyBuffer = CreateBufferBySize(buffer->maxSize);
    if (copyBuffer == NULL) {
        LOG_ERROR("create buffer failed");
        return NULL;
    }

    if (memcpy_s(copyBuffer->buf, copyBuffer->maxSize, buffer->buf, buffer->contentSize) != EOK) {
        LOG_ERROR("copy buffer failed");
        goto FAIL;
    }
    copyBuffer->contentSize = buffer->contentSize;

    return copyBuffer;

FAIL:
    DestoryBuffer(copyBuffer);
    return NULL;
}

bool CompareBuffer(const Buffer *buffer1, const Buffer *buffer2)
{
    if (!IsBufferValid(buffer1) || !IsBufferValid(buffer2) || (buffer1->contentSize != buffer2->contentSize)) {
        return false;
    }

    if (memcmp(buffer1->buf, buffer2->buf, buffer1->contentSize) == 0) {
        return true;
    }

    return false;
}

ResultCode GetBufferData(const Buffer *buffer, uint8_t *data, uint32_t *dataSize)
{
    if (!IsBufferValid(buffer) || (data == NULL) || (dataSize == NULL)) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    if (memcpy_s(data, *dataSize, buffer->buf, buffer->contentSize) != EOK) {
        LOG_ERROR("copy buffer failed");
        return RESULT_BAD_COPY;
    }
    *dataSize = buffer->contentSize;
    return RESULT_SUCCESS;
}

Buffer *MergeBuffers(const Buffer *buffer1, const Buffer *buffer2)
{
    if (!IsBufferValid(buffer1) || !IsBufferValid(buffer2)) {
        LOG_ERROR("invalid params");
        return NULL;
    }
    Buffer *merged = CreateBufferBySize(buffer1->maxSize + buffer2->maxSize);
    if (!IsBufferValid(merged)) {
        LOG_ERROR("create buffer failed");
        return NULL;
    }

    if (memcpy_s(merged->buf, merged->maxSize, buffer1->buf, buffer1->contentSize) != EOK) {
        LOG_ERROR("memcpy buffer1 failed");
        goto FAIL;
    }
    if (memcpy_s(merged->buf + buffer1->contentSize, merged->maxSize - buffer1->contentSize,
        buffer2->buf, buffer2->contentSize) != EOK) {
        LOG_ERROR("memcpy buffer2 failed");
        goto FAIL;
    }
    merged->contentSize = buffer1->contentSize + buffer2->contentSize;
    return merged;

FAIL:
    DestoryBuffer(merged);
    return NULL;
}