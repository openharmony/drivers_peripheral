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
#include <dlfcn.h>
#include <securec.h>
#include "hdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG codec_hdi_instance

#define CODEC_OEM_INTERFACE_LIB_NAME    "libcodec_oem_interface.z.so"
#define CODEC_BUFFER_MANAGER_LIB_NAME   "libcodec_buffer_manager.z.so"
#define BUFFER_COUNT    1

static void InitCodecOemIf(struct CodecInstance *instance)
{
    if (instance == NULL || instance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }

    void *libHandle = dlopen(CODEC_OEM_INTERFACE_LIB_NAME, RTLD_NOW);
    if (libHandle == NULL) {
        HDF_LOGE("%{public}s: lib %{public}s dlopen failed, error code[%{public}s]",
            __func__, CODEC_OEM_INTERFACE_LIB_NAME, dlerror());
        return;
    }

    struct CodecOemIf *iface = instance->codecOemIface;
    iface->CodecInit = (CodecInitType)dlsym(libHandle, "CodecInit");
    iface->CodecDeinit = (CodecDeinitType)dlsym(libHandle, "CodecDeinit");
    iface->CodecCreate = (CodecCreateType)dlsym(libHandle, "CodecCreate");
    iface->CodecDestroy = (CodecDestroyType)dlsym(libHandle, "CodecDestroy");
    iface->CodecSetParameter = (CodecSetParameterType)dlsym(libHandle, "CodecSetParameter");
    iface->CodecGetParameter = (CodecGetParameterType)dlsym(libHandle, "CodecGetParameter");
    iface->CodecStart = (CodecStartType)dlsym(libHandle, "CodecStart");
    iface->CodecStop = (CodecStopType)dlsym(libHandle, "CodecStop");
    iface->CodecFlush = (CodecFlushType)dlsym(libHandle, "CodecFlush");
    iface->CodecSetCallback = (CodecSetCallbackType)dlsym(libHandle, "CodecSetCallback");
    iface->CodecDecode = (CodecDecodeType)dlsym(libHandle, "CodecDecode");
    iface->CodecEncode = (CodecEncodeType)dlsym(libHandle, "CodecEncode");
    iface->CodecEncodeHeader = (CodecEncodeHeaderType)dlsym(libHandle, "CodecEncodeHeader");

    instance->oemLibHandle = libHandle;
}

static void InitBufferManagerIf(struct CodecInstance *instance)
{
    if (instance == NULL || instance->bufferManagerIface == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }

    void *libHandle = dlopen(CODEC_BUFFER_MANAGER_LIB_NAME, RTLD_NOW);
    if (libHandle == NULL) {
        HDF_LOGE("%{public}s: lib %{public}s dlopen failed, error code[%{public}s]",
            __func__, CODEC_BUFFER_MANAGER_LIB_NAME, dlerror());
        return;
    }

    struct BufferManagerIf *iface = instance->bufferManagerIface;
    iface->GetBufferManager = (GetBufferManagerType)dlsym(libHandle, "GetBufferManager");
    iface->DeleteBufferManager = (DeleteBufferManagerType)dlsym(libHandle, "DeleteBufferManager");
    if (iface->GetBufferManager != NULL) {
        HDF_LOGI("%{public}s:  dlsym ok", __func__);
        instance->bufferManagerWrapper = iface->GetBufferManager();
    } else {
        HDF_LOGE("%{public}s: lib %{public}s dlsym failed, error code[%{public}s]",
            __func__, CODEC_BUFFER_MANAGER_LIB_NAME, dlerror());
    }

    instance->bufferManagerLibHandle = libHandle;
}

static int32_t WaitForBufferData(struct CodecInstance *instance, CodecBuffer *outputData)
{
    struct BufferManagerWrapper *bmWrapper = instance->bufferManagerWrapper;
    CodecBuffer *output = NULL;
    while (instance->codecStatus == CODEC_STATUS_STARTED) {
        if (bmWrapper->IsInputDataBufferReady(bmWrapper, QUEUE_TIME_OUT)
            && bmWrapper->IsUsedOutputDataBufferReady(bmWrapper, QUEUE_TIME_OUT)) {
            output = bmWrapper->GetUsedOutputDataBuffer(bmWrapper, QUEUE_TIME_OUT);
            if (output != NULL) {
                CopyCodecBuffer(outputData, output);
                outputData->buffer[0].type = BUFFER_TYPE_VIRTUAL;
                outputData->buffer[0].buf = (intptr_t)GetOutputShm(instance, output->bufferId)->virAddr;
                break;
            }
        }
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
    CodecBuffer *input = NULL;
    int32_t ret = HDF_FAILURE;

    inputData->bufferCnt = BUFFER_COUNT;
    outputData->bufferCnt = BUFFER_COUNT;
    if (WaitForBufferData(instance, outputData) != HDF_SUCCESS) {
        return NULL;
    }
    
    while (instance->codecStatus == CODEC_STATUS_STARTED) {
        if (!bmWrapper->IsInputDataBufferReady(bmWrapper, QUEUE_TIME_OUT)) {
            continue;
        }
        
        input = bmWrapper->GetInputDataBuffer(bmWrapper, QUEUE_TIME_OUT);
        if (input == NULL) {
            continue;
        }

        CopyCodecBuffer(inputData, input);
        inputData->buffer[0].type = BUFFER_TYPE_VIRTUAL;
        inputData->buffer[0].buf = (intptr_t)GetInputShm(instance, input->bufferId)->virAddr;
        if (instance->codecType == VIDEO_DECODER) {
            ret = instance->codecOemIface->CodecDecode(instance->handle, inputData, outputData, QUEUE_TIME_OUT);
        } else if (instance->codecType == VIDEO_ENCODER) {
            ret = instance->codecOemIface->CodecEncode(instance->handle, inputData, outputData, QUEUE_TIME_OUT);
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

void InitCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    
    instance->codecOemIface = (struct CodecOemIf *)OsalMemCalloc(sizeof(struct CodecOemIf));
    if (instance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: codecOemIface mem alloc failed", __func__);
        return;
    }
    InitCodecOemIf(instance);
    instance->bufferManagerIface = (struct BufferManagerIf *)OsalMemAlloc(sizeof(struct BufferManagerIf));
    if (instance->bufferManagerIface == NULL) {
        HDF_LOGE("%{public}s: bufferManagerIface mem alloc failed", __func__);
        return;
    }
    InitBufferManagerIf(instance);
}

void RunCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    instance->codecStatus = CODEC_STATUS_STARTED;
    int32_t ret = pthread_create(&instance->task, NULL, CodecTaskThread, instance);
    if (ret != 0) {
        HDF_LOGE("%{public}s: run codec task thread failed!", __func__);
    }
}

void StopCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    instance->codecStatus = CODEC_STATUS_STOPED;
}

void DestroyCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }

    instance->codecStatus = CODEC_STATUS_STOPED;
    pthread_join(instance->task, NULL);

    ReleaseInputShm(instance);
    ReleaseOutputShm(instance);
    ReleaseInputInfo(instance);
    ReleaseOutputInfo(instance);

    dlclose(instance->oemLibHandle);
    if (instance->codecOemIface != NULL) {
        OsalMemFree(instance->codecOemIface);
    }
    instance->bufferManagerIface->DeleteBufferManager(&(instance->bufferManagerWrapper));
    dlclose(instance->bufferManagerLibHandle);
    if (instance->bufferManagerIface != NULL) {
        OsalMemFree(instance->bufferManagerIface);
    }
}

void AddInputShm(struct CodecInstance *instance, const CodecBufferInfo *bufferInfo, int32_t bufferId)
{
    if (instance == NULL || bufferInfo == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    int32_t count = instance->inputBuffersCount;
    instance->inputBuffers[count].id = bufferId;
    instance->inputBuffers[count].fd = (int32_t)bufferInfo->buf;
    instance->inputBuffers[count].size = bufferInfo->capacity;
    OpenShareMemory(&instance->inputBuffers[count]);
    instance->inputBuffersCount++;
}

void AddOutputShm(struct CodecInstance *instance, const CodecBufferInfo *bufferInfo, int32_t bufferId)
{
    if (instance == NULL || bufferInfo == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    int32_t count = instance->outputBuffersCount;
    instance->outputBuffers[count].id = bufferId;
    instance->outputBuffers[count].fd = (int32_t)bufferInfo->buf;
    instance->outputBuffers[count].size = bufferInfo->capacity;
    OpenShareMemory(&instance->outputBuffers[count]);
    instance->outputBuffersCount++;
}

ShareMemory* GetInputShm(struct CodecInstance *instance, int32_t id)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return NULL;
    }
    for (int32_t i = 0; i < instance->inputBuffersCount; i++) {
        if (instance->inputBuffers[i].id == id) {
            return &(instance->inputBuffers[i]);
        }
    }
    HDF_LOGE("%{public}s: not found for bufferId:%{public}d!", __func__, id);
    return NULL;
}

ShareMemory* GetOutputShm(struct CodecInstance *instance, int32_t id)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return NULL;
    }
    for (int32_t i = 0; i < instance->outputBuffersCount; i++) {
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

    HDF_LOGE("%{public}s: failed to found bufferId:%{public}d!", __func__, id);
    return HDF_FAILURE;
}

void ReleaseInputShm(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    for (int32_t i = 0; i < instance->inputBuffersCount; i++) {
        ReleaseShareMemory(&instance->inputBuffers[i]);
    }
}
void ReleaseOutputShm(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    for (int32_t i = 0; i < instance->outputBuffersCount; i++) {
        ReleaseShareMemory(&instance->outputBuffers[i]);
    }
}

void AddInputInfo(struct CodecInstance *instance, CodecBuffer *info)
{
    if (instance == NULL || info == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    instance->inputInfos[instance->inputInfoCount] = info;
    instance->inputInfoCount++;
}

void AddOutputInfo(struct CodecInstance *instance, CodecBuffer *info)
{
    if (instance == NULL || info == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    instance->outputInfos[instance->outputInfoCount] = info;
    instance->outputInfoCount++;
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

void ReleaseInputInfo(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    CodecBuffer *info;
    for (int32_t i = 0; i < instance->inputInfoCount; i++) {
        info = instance->inputInfos[i];
        if (info != NULL) {
            OsalMemFree(info);
            instance->outputInfos[i] = NULL;
        }
    }
}

void ReleaseOutputInfo(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    CodecBuffer *info;
    for (int32_t i = 0; i < instance->outputInfoCount; i++) {
        info = instance->outputInfos[i];
        if (info != NULL) {
            OsalMemFree(info);
            instance->outputInfos[i] = NULL;
        }
    }
}

void ResetBuffers(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    int32_t i;
    for (i = 0; i< instance->inputBuffersCount; i++) {
        ReleaseShareMemory(&instance->inputBuffers[i]);
    }
    for (i = 0; i< instance->outputBuffersCount; i++) {
        ReleaseShareMemory(&instance->outputBuffers[i]);
    }
    for (i = 0; i< instance->inputInfoCount; i++) {
        OsalMemFree(instance->inputInfos[i]);
    }
    for (i = 0; i< instance->outputInfoCount; i++) {
        OsalMemFree(instance->outputInfos[i]);
    }

    instance->inputBuffersCount = 0;
    instance->outputBuffersCount = 0;
    instance->inputInfoCount = 0;
    instance->outputInfoCount = 0;
}

bool CopyCodecBuffer(CodecBuffer *dst, const CodecBuffer *src)
{
    if (dst == NULL || src == NULL) {
        HDF_LOGE("%{public}s: Nullpoint, dst: %{public}p, src: %{public}p", __func__, dst, src);
        return false;
    }
    if (dst->bufferCnt != src->bufferCnt) {
        HDF_LOGE("%{public}s: size not match", __func__);
        return false;
    }
    int32_t size = sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * src->bufferCnt;
    int32_t ret = memcpy_s(dst, size, src, size);
    if (ret != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed, error code: %{public}d", __func__, ret);
        return false;
    }
    return true;
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
    return dst;
}

