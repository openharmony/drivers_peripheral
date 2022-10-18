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

#include "codec_instance.h"
#include <buffer_handle_utils.h>
#include <dlfcn.h>
#include <securec.h>
#include "hdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG codec_hdi_instance

#define CODEC_OEM_INTERFACE_LIB_NAME    "libcodec_oem_interface.z.so"
#define CODEC_BUFFER_MANAGER_LIB_NAME   "libcodec_buffer_manager.z.so"
#define BUFFER_COUNT    1

static int32_t InitCodecOemIf(struct CodecInstance *instance)
{
    if (instance == NULL || instance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }

    void *libHandle = dlopen(CODEC_OEM_INTERFACE_LIB_NAME, RTLD_NOW);
    if (libHandle == NULL) {
        HDF_LOGE("%{public}s: lib %{public}s dlopen failed, error code[%{public}s]",
            __func__, CODEC_OEM_INTERFACE_LIB_NAME, dlerror());
        return HDF_FAILURE;
    }

    struct CodecOemIf *iface = instance->codecOemIface;
    iface->codecInit = (CodecInitType)dlsym(libHandle, "CodecInit");
    iface->codecDeinit = (CodecDeinitType)dlsym(libHandle, "CodecDeinit");
    iface->codecCreate = (CodecCreateType)dlsym(libHandle, "CodecCreate");
    iface->codecDestroy = (CodecDestroyType)dlsym(libHandle, "CodecDestroy");
    iface->codecSetParameter = (CodecSetParameterType)dlsym(libHandle, "CodecSetParameter");
    iface->codecGetParameter = (CodecGetParameterType)dlsym(libHandle, "CodecGetParameter");
    iface->codecStart = (CodecStartType)dlsym(libHandle, "CodecStart");
    iface->codecStop = (CodecStopType)dlsym(libHandle, "CodecStop");
    iface->codecFlush = (CodecFlushType)dlsym(libHandle, "CodecFlush");
    iface->codecSetCallback = (CodecSetCallbackType)dlsym(libHandle, "CodecSetCallback");
    iface->codecDecode = (CodecDecodeType)dlsym(libHandle, "CodecDecode");
    iface->codecEncode = (CodecEncodeType)dlsym(libHandle, "CodecEncode");
    iface->codecEncodeHeader = (CodecEncodeHeaderType)dlsym(libHandle, "CodecEncodeHeader");

    instance->oemLibHandle = libHandle;
    return HDF_SUCCESS;
}

static int32_t InitBufferManagerIf(struct CodecInstance *instance)
{
    if (instance == NULL || instance->bufferManagerIface == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }

    void *libHandle = dlopen(CODEC_BUFFER_MANAGER_LIB_NAME, RTLD_NOW);
    if (libHandle == NULL) {
        HDF_LOGE("%{public}s: lib %{public}s dlopen failed, error code[%{public}s]",
            __func__, CODEC_BUFFER_MANAGER_LIB_NAME, dlerror());
        return HDF_FAILURE;
    }

    struct BufferManagerIf *iface = instance->bufferManagerIface;
    iface->getBufferManager = (GetBufferManagerType)dlsym(libHandle, "GetBufferManager");
    iface->deleteBufferManager = (DeleteBufferManagerType)dlsym(libHandle, "DeleteBufferManager");
    if (iface->getBufferManager != NULL) {
        HDF_LOGI("%{public}s:  dlsym ok", __func__);
        instance->bufferManagerWrapper = iface->getBufferManager();
    } else {
        HDF_LOGE("%{public}s: lib %{public}s dlsym failed, error code[%{public}s]",
            __func__, CODEC_BUFFER_MANAGER_LIB_NAME, dlerror());
        return HDF_FAILURE;
    }

    instance->bufferManagerLibHandle = libHandle;
    return HDF_SUCCESS;
}

static int32_t WaitForOutputDataBuffer(struct CodecInstance *instance, CodecBuffer *outputData)
{
    struct BufferManagerWrapper *bmWrapper = instance->bufferManagerWrapper;
    CodecBuffer *output = NULL;
    while (instance->codecStatus == CODEC_STATUS_STARTED) {
        if (bmWrapper->IsInputDataBufferReady(bmWrapper, QUEUE_TIME_OUT)
            && bmWrapper->IsUsedOutputDataBufferReady(bmWrapper, QUEUE_TIME_OUT)) {
            output = bmWrapper->GetUsedOutputDataBuffer(bmWrapper, QUEUE_TIME_OUT);
            if (output == NULL) {
                continue;
            }
            if (!SetOemCodecBufferType(outputData, output)) {
                HDF_LOGE("%{public}s: SetOemCodecBufferType failed!", __func__);
                return HDF_FAILURE;
            }
            if (!CopyCodecBufferWithTypeSwitch(instance, outputData, output, false)) {
                HDF_LOGE("%{public}s: CopyCodecBuffer failed!", __func__);
                return HDF_FAILURE;
            }
            break;
        }
    }
    return HDF_SUCCESS;
}

static int32_t PrepareInputDataBuffer(struct BufferManagerWrapper *bmWrapper,
    struct CodecInstance *instance, CodecBuffer *bufferToOemCodec)
{
    if (!bmWrapper->IsInputDataBufferReady(bmWrapper, QUEUE_TIME_OUT)) {
        return HDF_ERR_TIMEOUT;
    }
    CodecBuffer *bufferInQueue = bmWrapper->GetInputDataBuffer(bmWrapper, QUEUE_TIME_OUT);
    if (bufferInQueue == NULL) {
        return HDF_ERR_TIMEOUT;
    }

    if (!SetOemCodecBufferType(bufferToOemCodec, bufferInQueue)) {
        HDF_LOGE("%{public}s: SetOemCodecBufferType failed!", __func__);
        return HDF_FAILURE;
    }
    if (!CopyCodecBufferWithTypeSwitch(instance, bufferToOemCodec, bufferInQueue, false)) {
        HDF_LOGE("%{public}s: CopyCodecBuffer failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static void *CodecTaskThread(void *arg)
{
    if (arg == NULL) {
        HDF_LOGE("%{public}s: Invalid arg, exit CodecTaskThread!", __func__);
        return NULL;
    }
    struct CodecInstance *instance = (struct CodecInstance *)arg;
    struct BufferManagerWrapper *bmWrapper = instance->bufferManagerWrapper;
    if (bmWrapper == NULL) {
        HDF_LOGE("%{public}s: BufferManager not ready!", __func__);
        return NULL;
    }
    HDF_LOGI("%{public}s: CodecTaskThread start!", __func__);

    int32_t codecBufferSize = sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * BUFFER_COUNT;
    CodecBuffer *inputData = (CodecBuffer *)OsalMemCalloc(codecBufferSize);
    CodecBuffer *outputData = (CodecBuffer *)OsalMemCalloc(codecBufferSize);
    int32_t ret = HDF_FAILURE;

    inputData->bufferCnt = BUFFER_COUNT;
    outputData->bufferCnt = BUFFER_COUNT;
    if (WaitForOutputDataBuffer(instance, outputData) != HDF_SUCCESS) {
        return NULL;
    }
    while (instance->codecStatus == CODEC_STATUS_STARTED) {
        if (PrepareInputDataBuffer(bmWrapper, instance, inputData) != HDF_SUCCESS) {
            continue;
        }

        if (instance->codecType == VIDEO_DECODER) {
            ret = instance->codecOemIface->codecDecode(instance->handle, inputData, outputData, QUEUE_TIME_OUT);
        } else if (instance->codecType == VIDEO_ENCODER) {
            ret = instance->codecOemIface->codecEncode(instance->handle, inputData, outputData, QUEUE_TIME_OUT);
        }
        if (ret == HDF_SUCCESS || (outputData->flag & STREAM_FLAG_EOS)) {
            HDF_LOGI("%{public}s: output reach STREAM_FLAG_EOS!", __func__);
            instance->codecStatus = CODEC_STATUS_STOPED;
        }
    }

    OsalMemFree(inputData);
    OsalMemFree(outputData);
    HDF_LOGI("%{public}s: codec task thread finished!", __func__);
    return NULL;
}

struct CodecInstance* GetCodecInstance(void)
{
    struct CodecInstance *instance = (struct CodecInstance *)OsalMemCalloc(sizeof(struct CodecInstance));
    if (instance == NULL) {
        HDF_LOGE("%{public}s: instance mem alloc failed", __func__);
        return NULL;
    }

    instance->codecStatus = CODEC_STATUS_IDLE;
    instance->hasCallback = false;
    return instance;
}

int32_t InitCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }
    
    instance->codecOemIface = (struct CodecOemIf *)OsalMemCalloc(sizeof(struct CodecOemIf));
    if (instance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: codecOemIface mem alloc failed", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = InitCodecOemIf(instance);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: InitCodecOemIf failed", __func__);
        return HDF_FAILURE;
    }
    instance->bufferManagerIface = (struct BufferManagerIf *)OsalMemAlloc(sizeof(struct BufferManagerIf));
    if (instance->bufferManagerIface == NULL) {
        HDF_LOGE("%{public}s: bufferManagerIface mem alloc failed", __func__);
        return HDF_FAILURE;
    }
    return InitBufferManagerIf(instance);
}

int32_t RunCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    instance->codecStatus = CODEC_STATUS_STARTED;
    int32_t ret = pthread_create(&instance->task, NULL, CodecTaskThread, instance);
    if (ret != 0) {
        HDF_LOGE("%{public}s: run codec task thread failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t StopCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }
    instance->codecStatus = CODEC_STATUS_STOPED;
    return HDF_SUCCESS;
}

int32_t DestroyCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }

    if (instance->codecStatus == CODEC_STATUS_STARTED) {
        HDF_LOGE("%{public}s: wait codec task stop!", __func__);
        instance->codecStatus = CODEC_STATUS_STOPED;
        pthread_join(instance->task, NULL);
    }

    ReleaseInputShm(instance);
    ReleaseOutputShm(instance);
    ReleaseInputInfo(instance);
    ReleaseOutputInfo(instance);

    if (instance->codecOemIface != NULL) {
        OsalMemFree(instance->codecOemIface);
    }
    dlclose(instance->oemLibHandle);
    if (instance->bufferManagerIface != NULL) {
        instance->bufferManagerIface->deleteBufferManager(&(instance->bufferManagerWrapper));
        OsalMemFree(instance->bufferManagerIface);
    }
    dlclose(instance->bufferManagerLibHandle);
    OsalMemFree(instance);
    return HDF_SUCCESS;
}

bool SetOemCodecBufferType(CodecBuffer *bufferToOemCodec, CodecBuffer *bufferInQueue)
{
    if (bufferToOemCodec == NULL || bufferInQueue == NULL) {
        HDF_LOGE("%{public}s: Invalid params!", __func__);
        return false;
    }
    if (bufferInQueue->buffer[0].type == BUFFER_TYPE_HANDLE) {
        bufferToOemCodec->buffer[0].type = BUFFER_TYPE_HANDLE;
    } else {
        bufferToOemCodec->buffer[0].type = BUFFER_TYPE_VIRTUAL;
    }
    return true;
}

int32_t AddInputShm(struct CodecInstance *instance, const CodecBufferInfo *bufferInfo, int32_t bufferId)
{
    if (instance == NULL || bufferInfo == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }
    int32_t count = instance->inputBuffersCount;
    if (count >= MAX_BUFFER_NUM) {
        HDF_LOGE("%{public}s: ShareMemory buffer array full!", __func__);
        return HDF_FAILURE;
    }
    instance->inputBuffers[count].id = bufferId;
    instance->inputBuffers[count].size = bufferInfo->capacity;
    instance->inputBuffers[count].type = bufferInfo->type;
    if (bufferInfo->type == BUFFER_TYPE_HANDLE) {
        BufferHandle *bufferHandle = (BufferHandle *)bufferInfo->buf;
        if (bufferHandle == NULL) {
            HDF_LOGE("%{public}s: null bufferHandle!", __func__);
            return HDF_FAILURE;
        }
        instance->inputBuffers[count].fd = bufferHandle->fd;
    } else if (bufferInfo->type == BUFFER_TYPE_FD) {
        instance->inputBuffers[count].fd = (int32_t)bufferInfo->buf;
        if (OpenFdShareMemory(&instance->inputBuffers[count]) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    }
    instance->inputBuffersCount++;
    return HDF_SUCCESS;
}

int32_t AddOutputShm(struct CodecInstance *instance, const CodecBufferInfo *bufferInfo, int32_t bufferId)
{
    if (instance == NULL || bufferInfo == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }
    int32_t count = instance->outputBuffersCount;
    if (count >= MAX_BUFFER_NUM) {
        HDF_LOGE("%{public}s: ShareMemory buffer array full!", __func__);
        return HDF_FAILURE;
    }
    instance->outputBuffers[count].id = bufferId;
    instance->outputBuffers[count].size = bufferInfo->capacity;
    instance->outputBuffers[count].type = bufferInfo->type;
    if (bufferInfo->type == BUFFER_TYPE_HANDLE) {
        BufferHandle *bufferHandle = (BufferHandle *)bufferInfo->buf;
        if (bufferHandle == NULL) {
            HDF_LOGE("%{public}s: null bufferHandle!", __func__);
            return HDF_FAILURE;
        }
        instance->outputBuffers[count].fd = bufferHandle->fd;
    } else if (bufferInfo->type == BUFFER_TYPE_FD) {
        instance->outputBuffers[count].fd = (int32_t)bufferInfo->buf;
        if (OpenFdShareMemory(&instance->outputBuffers[count]) != HDF_SUCCESS) {
            return HDF_FAILURE;
        }
    }
    instance->outputBuffersCount++;
    return HDF_SUCCESS;
}

static ShareMemory* GetShmById(struct CodecInstance *instance, int32_t id)
{
    int32_t i;
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return NULL;
    }
    for (i = 0; i < instance->inputBuffersCount; i++) {
        if (instance->inputBuffers[i].id == id) {
            return &(instance->inputBuffers[i]);
        }
    }
    for (i = 0; i < instance->outputBuffersCount; i++) {
        if (instance->outputBuffers[i].id == id) {
            return &(instance->outputBuffers[i]);
        }
    }
    HDF_LOGE("%{public}s: not found for bufferId:%{public}d!", __func__, id);
    return NULL;
}

int32_t GetFdById(struct CodecInstance *instance, int32_t id)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }
    int32_t i;
    for (i = 0; i < instance->inputBuffersCount; i++) {
        if (instance->inputBuffers[i].id == id) {
            return instance->inputBuffers[i].fd;
        }
    }
    for (i = 0; i < instance->outputBuffersCount; i++) {
        if (instance->outputBuffers[i].id == id) {
            return instance->outputBuffers[i].fd;
        }
    }
    HDF_LOGE("%{public}s: failed to find! bufferId:%{public}d!", __func__, id);
    return HDF_FAILURE;
}

void ReleaseInputShm(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    for (int32_t i = 0; i < instance->inputBuffersCount; i++) {
        if (instance->inputBuffers[i].type == BUFFER_TYPE_FD) {
            ReleaseFdShareMemory(&instance->inputBuffers[i]);
        }
    }
}
void ReleaseOutputShm(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    for (int32_t i = 0; i < instance->outputBuffersCount; i++) {
        if (instance->outputBuffers[i].type == BUFFER_TYPE_FD) {
            ReleaseFdShareMemory(&instance->outputBuffers[i]);
        }
    }
}

int32_t AddInputInfo(struct CodecInstance *instance, CodecBuffer *info)
{
    if (instance == NULL || info == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }
    if (instance->inputInfoCount >= MAX_BUFFER_NUM) {
        HDF_LOGE("%{public}s: CodecBuffer array full!", __func__);
        return HDF_FAILURE;
    }
    instance->inputInfos[instance->inputInfoCount] = info;
    instance->inputInfoCount++;
    return HDF_SUCCESS;
}

int32_t AddOutputInfo(struct CodecInstance *instance, CodecBuffer *info)
{
    if (instance == NULL || info == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }
    if (instance->outputInfoCount >= MAX_BUFFER_NUM) {
        HDF_LOGE("%{public}s: CodecBuffer array full!", __func__);
        return HDF_FAILURE;
    }
    instance->outputInfos[instance->outputInfoCount] = info;
    instance->outputInfoCount++;
    return HDF_SUCCESS;
}

CodecBuffer* GetInputInfo(struct CodecInstance *instance, uint32_t id)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return NULL;
    }
    for (int32_t i = 0; i < instance->inputInfoCount; i++) {
        if (instance->inputInfos[i]->bufferId == id) {
            return instance->inputInfos[i];
        }
    }
    return NULL;
}

CodecBuffer* GetOutputInfo(struct CodecInstance *instance, uint32_t id)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return NULL;
    }
    for (int32_t i = 0; i < instance->outputInfoCount; i++) {
        if (instance->outputInfos[i]->bufferId == id) {
            return instance->outputInfos[i];
        }
    }
    return NULL;
}

void ReleaseCodecBuffer(CodecBuffer *info)
{
    if (info == NULL) {
        HDF_LOGI("%{public}s: Invalid param!", __func__);
        return;
    }
    for (uint32_t i = 0; i < info->bufferCnt; i++) {
        if (info->buffer[i].type == BUFFER_TYPE_HANDLE) {
            FreeBufferHandle((BufferHandle *)info->buffer[i].buf);
        }
    }
    OsalMemFree(info);
}

void ReleaseInputInfo(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    for (int32_t i = 0; i < instance->inputInfoCount; i++) {
        ReleaseCodecBuffer(instance->inputInfos[i]);
        instance->inputInfos[i] = NULL;
    }
}

void ReleaseOutputInfo(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    for (int32_t i = 0; i < instance->outputInfoCount; i++) {
        ReleaseCodecBuffer(instance->outputInfos[i]);
        instance->outputInfos[i] = NULL;
    }
}

void ResetBuffers(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    int32_t i;
    ReleaseInputShm(instance);
    ReleaseOutputShm(instance);
    for (i = 0; i< instance->inputInfoCount; i++) {
        ReleaseCodecBuffer(instance->inputInfos[i]);
    }
    for (i = 0; i< instance->outputInfoCount; i++) {
        ReleaseCodecBuffer(instance->outputInfos[i]);
    }

    instance->inputBuffersCount = 0;
    instance->outputBuffersCount = 0;
    instance->inputInfoCount = 0;
    instance->outputInfoCount = 0;
}

void EmptyCodecBuffer(CodecBuffer *buf)
{
    if (buf == NULL) {
        return;
    }
    for (uint32_t i = 0; i < buf->bufferCnt; i++) {
        buf->buffer[i].length = 0;
        buf->buffer[i].offset = 0;
    }
}

bool CopyCodecBufferWithTypeSwitch(struct CodecInstance *instance, CodecBuffer *dst,
    const CodecBuffer *src, bool ignoreBuf)
{
    if (dst == NULL || src == NULL) {
        HDF_LOGE("%{public}s: Nullpoint, dst: %{public}p, src: %{public}p", __func__, dst, src);
        return false;
    }
    if (dst->bufferCnt != src->bufferCnt) {
        HDF_LOGE("%{public}s: size not match", __func__);
        return false;
    }
    dst->bufferId = src->bufferId;
    dst->timeStamp = src->timeStamp;
    dst->flag = src->flag;
    for (uint32_t i = 0; i < src->bufferCnt; i++) {
        dst->buffer[i].offset = src->buffer[i].offset;
        dst->buffer[i].length = src->buffer[i].length;
        dst->buffer[i].capacity = src->buffer[i].capacity;
        if (ignoreBuf) {
            continue;
        } else if (dst->buffer[i].type == src->buffer[i].type) {
            dst->buffer[i].buf = src->buffer[i].buf;
        } else if (dst->buffer[i].type == BUFFER_TYPE_VIRTUAL && src->buffer[i].type == BUFFER_TYPE_FD) {
            dst->buffer[i].buf = (intptr_t)GetShmById(instance, src->bufferId)->virAddr;
        } else if (dst->buffer[i].type == BUFFER_TYPE_VIRTUAL && src->buffer[i].type == BUFFER_TYPE_HANDLE) {
            dst->buffer[i].buf = (intptr_t)GetShmById(instance, src->bufferId)->virAddr;
        }
        if (dst->buffer[i].buf == 0) {
            HDF_LOGE("%{public}s: buf value invalid! bufferId:%{public}d", __func__, src->bufferId);
            return false;
        }
    }
    return true;
}

static BufferHandle *DupBufferHandle(const BufferHandle *handle)
{
    if (handle == NULL) {
        HDF_LOGE("%{public}s handle is NULL", __func__);
        return NULL;
    }

    BufferHandle *newHandle = AllocateBufferHandle(handle->reserveFds, handle->reserveInts);
    if (newHandle == NULL) {
        HDF_LOGE("%{public}s AllocateBufferHandle failed, newHandle is NULL", __func__);
        return NULL;
    }

    newHandle->fd = handle->fd;
    newHandle->width = handle->width;
    newHandle->stride = handle->stride;
    newHandle->height = handle->height;
    newHandle->size = handle->size;
    newHandle->format = handle->format;
    newHandle->usage = handle->usage;
    newHandle->virAddr = handle->virAddr;
    newHandle->phyAddr = handle->phyAddr;
    newHandle->key = handle->key;

    return newHandle;
}

CodecBuffer* DupCodecBuffer(const CodecBuffer *src)
{
    if (src == NULL) {
        HDF_LOGE("%{public}s: CodecBuffer src Nullpoint", __func__);
        return NULL;
    }
    int32_t size = sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * src->bufferCnt;
    CodecBuffer *dst = (CodecBuffer *)OsalMemAlloc(size);
    if (dst == NULL) {
        HDF_LOGE("%{public}s: malloc dst failed", __func__);
        return NULL;
    }
    int32_t ret = memcpy_s(dst, size, src, size);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed, error code: %{public}d", __func__, ret);
        OsalMemFree(dst);
        return NULL;
    }
    for (uint32_t i = 0; i < src->bufferCnt; i++) {
        if (dst->buffer[i].type == BUFFER_TYPE_HANDLE) {
            dst->buffer[i].buf = (intptr_t)DupBufferHandle((BufferHandle *)src->buffer[i].buf);
        }
    }
    return dst;
}

