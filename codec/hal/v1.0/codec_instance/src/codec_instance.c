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

static int32_t WaitForBufferData(struct CodecInstance *instance, CodecBufferInfo *outputDataBuffer,
    OutputInfo *outputData)
{
    struct BufferManagerWrapper *bmWrapper = instance->bufferManagerWrapper;
    OutputInfo *output = NULL;
    while (instance->codecStatus == CODEC_STATUS_STARTED) {
        if (bmWrapper->IsInputDataBufferReady(bmWrapper, QUEUE_TIME_OUT)
            && bmWrapper->IsUsedOutputDataBufferReady(bmWrapper, QUEUE_TIME_OUT)) {
            output = bmWrapper->GetUsedOutputDataBuffer(bmWrapper, QUEUE_TIME_OUT);
            if (output != NULL) {
                memset_s(outputDataBuffer, sizeof(CodecBufferInfo), 0, sizeof(CodecBufferInfo));
                outputDataBuffer->type = BUFFER_TYPE_VIRTUAL;
                outputDataBuffer->addr = GetOutputShm(instance, output->buffers->offset)->virAddr;
                outputDataBuffer->size = output->buffers->size;
                outputDataBuffer->offset = output->buffers->offset;
                memset_s(outputData, sizeof(OutputInfo), 0, sizeof(OutputInfo));
                outputData->buffers = outputDataBuffer;
                outputData->bufferCnt = 1;
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

    CodecBufferInfo inputDataBuffer;
    InputInfo inputData;
    CodecBufferInfo outputDataBuffer;
    OutputInfo outputData;
    InputInfo *input = NULL;
    int32_t ret;

    if (WaitForBufferData(instance, &outputDataBuffer, &outputData) != HDF_SUCCESS) {
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

        memset_s(&inputDataBuffer, sizeof(CodecBufferInfo), 0, sizeof(CodecBufferInfo));
        inputDataBuffer.type = BUFFER_TYPE_VIRTUAL;
        inputDataBuffer.addr = GetInputShm(instance, input->buffers->offset)->virAddr;
        inputDataBuffer.size = input->buffers->size;
        inputDataBuffer.offset = input->buffers->offset;
        memset_s(&inputData, sizeof(InputInfo), 0, sizeof(InputInfo));
        inputData.buffers = &inputDataBuffer;
        inputData.bufferCnt = 1;
        inputData.flag = input->flag;
        
        if (instance->codecType == VIDEO_DECODER) {
            ret = instance->codecOemIface->CodecDecode(instance->handle, inputData, outputData, QUEUE_TIME_OUT);
        } else if (instance->codecType == VIDEO_ENCODER) {
            ret = instance->codecOemIface->CodecEncode(instance->handle, inputData, outputData, QUEUE_TIME_OUT);
        }
        if (ret == HDF_SUCCESS || (outputData.flag & STREAM_FLAG_EOS)) {
            HDF_LOGI("%{public}s: output reach STREAM_FLAG_EOS!", __func__);
            instance->codecStatus = CODEC_STATUS_STOPED;
        }
    }
    
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

void AddInputShm(struct CodecInstance *instance, CodecBufferInfo *bufferInfo)
{
    if (instance == NULL || bufferInfo == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    int32_t count = instance->inputBuffersCount;
    instance->inputBuffers[count].id = bufferInfo->offset;
    instance->inputBuffers[count].fd = bufferInfo->fd;
    instance->inputBuffers[count].size = bufferInfo->size;
    OpenShareMemory(&instance->inputBuffers[count]);
    instance->inputBuffersCount++;
}

void AddOutputShm(struct CodecInstance *instance, CodecBufferInfo *bufferInfo)
{
    if (instance == NULL || bufferInfo == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    int32_t count = instance->outputBuffersCount;
    instance->outputBuffers[count].id = bufferInfo->offset;
    instance->outputBuffers[count].fd = bufferInfo->fd;
    instance->outputBuffers[count].size = bufferInfo->size;
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

void AddInputInfo(struct CodecInstance *instance, InputInfo *info)
{
    if (instance == NULL || info == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    instance->inputInfos[instance->inputInfoCount] = info;
    instance->inputInfoCount++;
}

void AddOutputInfo(struct CodecInstance *instance, OutputInfo *info)
{
    if (instance == NULL || info == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    instance->outputInfos[instance->outputInfoCount] = info;
    instance->outputInfoCount++;
}

InputInfo* GetInputInfo(struct CodecInstance *instance, int32_t id)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return NULL;
    }
    for (int32_t i = 0; i < instance->inputInfoCount; i++) {
        if (instance->inputInfos[i]->buffers[0].offset == (uint32_t)id) {
            return instance->inputInfos[i];
        }
    }
    return NULL;
}

OutputInfo* GetOutputInfo(struct CodecInstance *instance, int32_t id)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return NULL;
    }
    for (int32_t i = 0; i < instance->outputInfoCount; i++) {
        if (instance->outputInfos[i]->buffers[0].offset == (uint32_t)id) {
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
    InputInfo *info;
    for (int32_t i = 0; i < instance->inputInfoCount; i++) {
        info = instance->inputInfos[i];
        OsalMemFree(info->buffers);
        OsalMemFree(info);
    }
}

void ReleaseOutputInfo(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return;
    }
    OutputInfo *info;
    for (int32_t i = 0; i < instance->outputInfoCount; i++) {
        info = instance->outputInfos[i];
        OsalMemFree(info->buffers);
        OsalMemFree(info);
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
