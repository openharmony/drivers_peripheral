/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "securec.h"

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
        LOG_ERROR("Bad param size:%u", size);
        return NULL;
    }

    Buffer *buffer = (Buffer *)Malloc(sizeof(Buffer));
    if (buffer == NULL) {
        LOG_ERROR("Get buffer struct error");
        return NULL;
    }

    buffer->buf = (uint8_t *)Malloc(size);
    if (buffer->buf == NULL) {
        LOG_ERROR("Get buffer error");
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
        LOG_ERROR("Bad param size:%u", dataSize);
        return NULL;
    }

    Buffer *buffer = (Buffer *)Malloc(sizeof(Buffer));
    if (buffer == NULL) {
        LOG_ERROR("Get buffer struct error");
        return NULL;
    }

    buffer->buf = (uint8_t *)Malloc(dataSize);
    if (buffer->buf == NULL) {
        LOG_ERROR("Get buffer error");
        Free(buffer);
        return NULL;
    }

    if (memcpy_s(buffer->buf, dataSize, data, dataSize) != EOK) {
        LOG_ERROR("Cpy buffer error");
        DestroyBuffer(buffer);
        return NULL;
    }
    buffer->maxSize = dataSize;
    buffer->contentSize = dataSize;

    return buffer;
}

ResultCode InitBuffer(Buffer *buffer, const uint8_t *buf, const uint32_t bufSize)
{
    if (!IsBufferValid(buffer) || (buf == NULL) || (bufSize == 0)) {
        LOG_ERROR("Bad param");
        return RESULT_BAD_PARAM;
    }

    if (memcpy_s(buffer->buf, buffer->maxSize, buf, bufSize) != EOK) {
        LOG_ERROR("Copy buffer fail");
        return RESULT_BAD_COPY;
    }
    buffer->contentSize = bufSize;

    return RESULT_SUCCESS;
}

void DestroyBuffer(Buffer *buffer)
{
    if (buffer != NULL) {
        if (buffer->buf != NULL) {
            if (memset_s(buffer->buf, buffer->maxSize, 0, buffer->maxSize) != EOK) {
                LOG_ERROR("DestroyBuffer memset fail!");
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
        LOG_ERROR("Invalid buffer");
        return NULL;
    }

    Buffer *copyBuffer = CreateBufferBySize(buffer->maxSize);
    if (copyBuffer == NULL) {
        LOG_ERROR("Invalid buffer");
        return NULL;
    }

    if (memcpy_s(copyBuffer->buf, copyBuffer->maxSize, buffer->buf, buffer->contentSize) != EOK) {
        LOG_ERROR("Copy buffer fail");
        goto FAIL;
    }
    copyBuffer->contentSize = buffer->contentSize;

    return copyBuffer;

FAIL:
    DestroyBuffer(copyBuffer);

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
        LOG_ERROR("Bad param");
        return RESULT_BAD_PARAM;
    }
    if (memcpy_s(data, *dataSize, buffer->buf, buffer->contentSize) != EOK) {
        LOG_ERROR("Copy buffer fail");
        return RESULT_BAD_COPY;
    }
    *dataSize = buffer->contentSize;
    return RESULT_SUCCESS;
}