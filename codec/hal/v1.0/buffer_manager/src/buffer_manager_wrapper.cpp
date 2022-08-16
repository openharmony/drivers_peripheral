/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "buffer_manager_wrapper.h"
#include "buffer_manager.h"
#include "hdf_log.h"

#ifdef __cplusplus
extern "C"
{
#endif

static bool IsInputDataBufferReadyImpl(const struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return false;
    }

    CodecBuffer *buffer =
        ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->inputBufferManager))->GetBuffer(timeoutMs, true);
    return (buffer != nullptr);
}

static CodecBuffer* GetInputDataBufferImpl(const struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return nullptr;
    }

    CodecBuffer *buffer =
        ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->inputBufferManager))->GetBuffer(timeoutMs, false);
    return buffer;
}

static CodecBuffer* GetUsedInputDataBufferImpl(const struct BufferManagerWrapper *bufferManagerWrapper,
                                               uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return nullptr;
    }

    CodecBuffer *buffer =
        ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->inputBufferManager))->GetUsedBuffer(timeoutMs, false);
    return buffer;
}

static void PutInputDataBufferImpl(const struct BufferManagerWrapper *bufferManagerWrapper, CodecBuffer *info)
{
    if (bufferManagerWrapper == nullptr || info == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return;
    }

    ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->inputBufferManager))->PutBuffer(info);
}

static void PutUsedInputDataBufferImpl(const struct BufferManagerWrapper *bufferManagerWrapper, CodecBuffer *info)
{
    if (bufferManagerWrapper == nullptr || info == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return;
    }
    ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->inputBufferManager))->PutUsedBuffer(info);
}

static bool IsUsedOutputDataBufferReadyImpl(const struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return false;
    }

    CodecBuffer *buffer =
        ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->outputBufferManager))->GetUsedBuffer(timeoutMs, true);
    return (buffer != nullptr);
}

static CodecBuffer* GetOutputDataBufferImpl(const struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return nullptr;
    }

    CodecBuffer *buffer =
        ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->outputBufferManager))->GetBuffer(timeoutMs, false);
    return buffer;
}

static CodecBuffer* GetUsedOutputDataBufferImpl(const struct BufferManagerWrapper *bufferManagerWrapper,
                                                uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return nullptr;
    }

    CodecBuffer *buffer =
        ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->outputBufferManager))->GetUsedBuffer(timeoutMs, false);
    return buffer;
}

static void PutOutputDataBufferImpl(const struct BufferManagerWrapper *bufferManagerWrapper, CodecBuffer *info)
{
    if (bufferManagerWrapper == nullptr || info == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return;
    }

    ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->outputBufferManager))->PutBuffer(info);
}

static void PutUsedOutputDataBufferImpl(const struct BufferManagerWrapper *bufferManagerWrapper, CodecBuffer *info)
{
    if (bufferManagerWrapper == nullptr || info == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return;
    }
    ((BufferManager<CodecBuffer>*)(bufferManagerWrapper->outputBufferManager))->PutUsedBuffer(info);
}

static void ConstructBufferManager(struct BufferManagerWrapper *bufferManager)
{
    bufferManager->IsInputDataBufferReady = IsInputDataBufferReadyImpl;
    bufferManager->GetInputDataBuffer = GetInputDataBufferImpl;
    bufferManager->GetUsedInputDataBuffer = GetUsedInputDataBufferImpl;
    bufferManager->PutInputDataBuffer = PutInputDataBufferImpl;
    bufferManager->PutUsedInputDataBuffer = PutUsedInputDataBufferImpl;
    bufferManager->IsUsedOutputDataBufferReady = IsUsedOutputDataBufferReadyImpl;
    bufferManager->GetOutputDataBuffer = GetOutputDataBufferImpl;
    bufferManager->GetUsedOutputDataBuffer = GetUsedOutputDataBufferImpl;
    bufferManager->PutOutputDataBuffer = PutOutputDataBufferImpl;
    bufferManager->PutUsedOutputDataBuffer = PutUsedOutputDataBufferImpl;
}

struct BufferManagerWrapper* GetBufferManager(void)
{
    struct BufferManagerWrapper *bufferManager = new struct BufferManagerWrapper;
    bufferManager->inputBufferManager = new BufferManager<CodecBuffer>();
    bufferManager->outputBufferManager = new BufferManager<CodecBuffer>();
    ConstructBufferManager(bufferManager);
    return bufferManager;
}

void DeleteBufferManager(struct BufferManagerWrapper **ppBufferManager)
{
    delete (BufferManager<CodecBuffer>*)((*ppBufferManager)->inputBufferManager);
    delete (BufferManager<CodecBuffer>*)((*ppBufferManager)->outputBufferManager);
    delete *ppBufferManager;
}

#ifdef __cplusplus
}
#endif
