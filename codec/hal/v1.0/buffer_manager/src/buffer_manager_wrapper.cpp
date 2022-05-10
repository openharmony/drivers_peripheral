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

static bool IsInputDataBufferReadyImpl(struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return false;
    }

    InputInfo *buffer =
        ((BufferManager<InputInfo>*)(bufferManagerWrapper->inputBufferManager))->GetBuffer(timeoutMs, true);
    return (buffer != nullptr);
}

static InputInfo* GetInputDataBufferImpl(struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return nullptr;
    }

    InputInfo *buffer =
        ((BufferManager<InputInfo>*)(bufferManagerWrapper->inputBufferManager))->GetBuffer(timeoutMs, false);
    return buffer;
}

static InputInfo* GetUsedInputDataBufferImpl(struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return nullptr;
    }

    InputInfo *buffer =
        ((BufferManager<InputInfo>*)(bufferManagerWrapper->inputBufferManager))->GetUsedBuffer(timeoutMs, false);
    return buffer;
}

static void PutInputDataBufferImpl(struct BufferManagerWrapper *bufferManagerWrapper, InputInfo *info)
{
    if (bufferManagerWrapper == nullptr || info == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return;
    }

    ((BufferManager<InputInfo>*)(bufferManagerWrapper->inputBufferManager))->PutBuffer(info);
}

static void PutUsedInputDataBufferImpl(struct BufferManagerWrapper *bufferManagerWrapper, InputInfo *info)
{
    if (bufferManagerWrapper == nullptr || info == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return;
    }
    ((BufferManager<InputInfo>*)(bufferManagerWrapper->inputBufferManager))->PutUsedBuffer(info);
}

static bool IsUsedOutputDataBufferReadyImpl(struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return false;
    }

    OutputInfo *buffer =
        ((BufferManager<OutputInfo>*)(bufferManagerWrapper->outputBufferManager))->GetUsedBuffer(timeoutMs, true);
    return (buffer != nullptr);
}

static OutputInfo* GetOutputDataBufferImpl(struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return nullptr;
    }

    OutputInfo *buffer =
        ((BufferManager<OutputInfo>*)(bufferManagerWrapper->outputBufferManager))->GetBuffer(timeoutMs, false);
    return buffer;
}

static OutputInfo* GetUsedOutputDataBufferImpl(struct BufferManagerWrapper *bufferManagerWrapper, uint32_t timeoutMs)
{
    if (bufferManagerWrapper == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return nullptr;
    }

    OutputInfo *buffer =
        ((BufferManager<OutputInfo>*)(bufferManagerWrapper->outputBufferManager))->GetUsedBuffer(timeoutMs, false);
    return buffer;
}

static void PutOutputDataBufferImpl(struct BufferManagerWrapper *bufferManagerWrapper, OutputInfo *info)
{
    if (bufferManagerWrapper == nullptr || info == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return;
    }

    ((BufferManager<OutputInfo>*)(bufferManagerWrapper->outputBufferManager))->PutBuffer(info);
}

static void PutUsedOutputDataBufferImpl(struct BufferManagerWrapper *bufferManagerWrapper, OutputInfo *info)
{
    if (bufferManagerWrapper == nullptr || info == nullptr) {
        HDF_LOGE("%{public}s: invalid params!", __func__);
        return;
    }
    ((BufferManager<OutputInfo>*)(bufferManagerWrapper->outputBufferManager))->PutUsedBuffer(info);
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
    bufferManager->inputBufferManager = new BufferManager<InputInfo>();
    bufferManager->outputBufferManager = new BufferManager<OutputInfo>();
    ConstructBufferManager(bufferManager);
    return bufferManager;
}

void DeleteBufferManager(struct BufferManagerWrapper **ppBufferManager)
{
    delete (BufferManager<InputInfo>*)((*ppBufferManager)->inputBufferManager);
    delete (BufferManager<OutputInfo>*)((*ppBufferManager)->outputBufferManager);
    delete *ppBufferManager;
}

#ifdef __cplusplus
}
#endif
