/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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
#define BUFFER_COUNT                    1

static bool InitData(CodecBuffer **inputData, CodecBuffer **outputData)
{
    if (inputData == NULL || outputData == NULL) {
        HDF_LOGE("%{public}s: inputData or outputData NULL!", __func__);
        return false;
    }
    int32_t codecBufferSize = sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * BUFFER_COUNT;
    *inputData = (CodecBuffer *)OsalMemCalloc(codecBufferSize);
    if (*inputData == NULL) {
        HDF_LOGE("%{public}s: inputData is NULL!", __func__);
        return false;
    }
    *outputData = (CodecBuffer *)OsalMemCalloc(codecBufferSize);
    if (*outputData == NULL) {
        OsalMemFree(*inputData);
        *inputData = NULL;
        HDF_LOGE("%{public}s: outputData is NULL!", __func__);
        return false;
    }
    return true;
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
    HDF_LOGI("%{public}s: codec task thread started!", __func__);

    CodecBuffer *inputData = NULL;
    CodecBuffer *outputData = NULL;
    int32_t ret = HDF_FAILURE;
    if (!InitData(&inputData, &outputData)) {
        HDF_LOGE("%{public}s: InitData failed!", __func__);
        return NULL;
    }

    inputData->bufferCnt = BUFFER_COUNT;
    outputData->bufferCnt = BUFFER_COUNT;
    if (WaitForOutputDataBuffer(instance, outputData) != HDF_SUCCESS) {
        OsalMemFree(inputData);
        OsalMemFree(outputData);
        HDF_LOGE("%{public}s: WaitForOutputDataBuffer failed!", __func__);
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
            break;
        }
    }
    OsalMutexLock(&instance->codecStatusLock);
    instance->codecStatus = CODEC_STATUS_STOPPED;
    pthread_cond_signal(&instance->codecStatusCond);
    OsalMutexUnlock(&instance->codecStatusLock);

    OsalMemFree(inputData);
    OsalMemFree(outputData);
    HDF_LOGI("%{public}s: codec task thread finished!", __func__);
    return NULL;
}

static int32_t GetUsedInputInfo(struct CodecInstance *instance, CodecBuffer *inputInfoSendToClient)
{
    if (instance == NULL || instance->bufferManagerWrapper == NULL || inputInfoSendToClient == NULL) {
        HDF_LOGE("%{public}s failed: invalid parameter!", __func__);
        return HDF_FAILURE;
    }
    
    CodecBuffer *inputInfo = instance->bufferManagerWrapper->GetUsedInputDataBuffer(
        instance->bufferManagerWrapper, QUEUE_TIME_OUT);
    if (inputInfo == NULL) {
        return HDF_ERR_TIMEOUT;
    }

    inputInfoSendToClient->bufferCnt = inputInfo->bufferCnt;
    inputInfoSendToClient->buffer[0].type = inputInfo->buffer[0].type;
    if (!CopyCodecBufferWithTypeSwitch(instance, inputInfoSendToClient, inputInfo, false)) {
        HDF_LOGE("%{public}s: copy CodecBuffer failed!", __func__);
        return HDF_FAILURE;
    }
    // fd has been transmitted at the initial time, here set invalid to avoid being transmitted again
    if (inputInfoSendToClient->buffer[0].type == BUFFER_TYPE_FD) {
        inputInfoSendToClient->buffer[0].buf = NO_TRANSMIT_FD;
    } else if (inputInfoSendToClient->buffer[0].type == BUFFER_TYPE_HANDLE) {
        inputInfoSendToClient->buffer[0].buf = NO_TRANSMIT_BUFFERHANDLE;
    }
    return HDF_SUCCESS;
}

static int32_t GetFilledOutputInfo(struct CodecInstance *instance, CodecBuffer *outputInfoSendToClient)
{
    if (instance == NULL || instance->bufferManagerWrapper == NULL || outputInfoSendToClient == NULL) {
        HDF_LOGE("%{public}s failed: invalid parameter!", __func__);
        return HDF_FAILURE;
    }
    
    CodecBuffer *outputInfo = instance->bufferManagerWrapper->GetOutputDataBuffer(
        instance->bufferManagerWrapper, QUEUE_TIME_OUT);
    if (outputInfo == NULL) {
        return HDF_ERR_TIMEOUT;
    }

    outputInfoSendToClient->bufferCnt = outputInfo->bufferCnt;
    outputInfoSendToClient->buffer[0].type = outputInfo->buffer[0].type;
    if (!CopyCodecBufferWithTypeSwitch(instance, outputInfoSendToClient, outputInfo, false)) {
        HDF_LOGE("%{public}s: copy CodecBuffer failed!", __func__);
        return HDF_FAILURE;
    }
    // fd has been transmitted at the initial time, here set invalid to avoid being transmitted again
    if (outputInfoSendToClient->buffer[0].type == BUFFER_TYPE_FD) {
        outputInfoSendToClient->buffer[0].buf = NO_TRANSMIT_FD;
    } else if (outputInfoSendToClient->buffer[0].type == BUFFER_TYPE_HANDLE) {
        outputInfoSendToClient->buffer[0].buf = NO_TRANSMIT_BUFFERHANDLE;
    }
    return HDF_SUCCESS;
}

static void CallbackTaskLoop(struct CodecInstance *instance, CodecBuffer *inputInfoSendToClient,
    CodecBuffer *outputInfoSendToClient)
{
    int32_t acquireFd = 1;
    bool codecTaskFinished = false;
    int32_t getResult;
    if (instance == NULL || inputInfoSendToClient == NULL || outputInfoSendToClient == NULL) {
        HDF_LOGE("%{public}s failed: invalid parameter!", __func__);
        return;
    }
    while (instance->codecCallbackStatus == CODEC_STATUS_STARTED) {
        if (instance->codecStatus != CODEC_STATUS_STARTED) {
            codecTaskFinished = true;
        }
        if (!instance->inputEos && GetUsedInputInfo(instance, inputInfoSendToClient) == HDF_SUCCESS) {
#ifndef CODEC_HAL_PASSTHROUGH
            instance->callbackProxy->InputBufferAvailable(instance->callbackProxy, instance->callbackUserData,
                inputInfoSendToClient, &acquireFd);
#else
            instance->codecCallback->InputBufferAvailable(instance->callbackUserData,
                inputInfoSendToClient, &acquireFd);
#endif
        }
        getResult = GetFilledOutputInfo(instance, outputInfoSendToClient);
        if (getResult == HDF_SUCCESS) {
#ifndef CODEC_HAL_PASSTHROUGH
            instance->callbackProxy->OutputBufferAvailable(instance->callbackProxy, instance->callbackUserData,
                outputInfoSendToClient, &acquireFd);
#else
            instance->codecCallback->OutputBufferAvailable(instance->callbackUserData,
                outputInfoSendToClient, &acquireFd);
#endif
        } else if (getResult == HDF_ERR_TIMEOUT && codecTaskFinished) {
            HDF_LOGI("%{public}s: no output any more!", __func__);
            EmptyCodecBuffer(outputInfoSendToClient);
            outputInfoSendToClient->flag = STREAM_FLAG_EOS;
#ifndef CODEC_HAL_PASSTHROUGH
            instance->callbackProxy->OutputBufferAvailable(instance->callbackProxy, instance->callbackUserData,
                outputInfoSendToClient, &acquireFd);
#else
            instance->codecCallback->OutputBufferAvailable(instance->callbackUserData,
                outputInfoSendToClient, &acquireFd);
#endif
            break;
        }
        if (outputInfoSendToClient->flag & STREAM_FLAG_EOS) {
            HDF_LOGI("%{public}s: output reach STREAM_FLAG_EOS!", __func__);
            break;
        }
    }
}

static void *CodecCallbackTaskThread(void *arg)
{
    HDF_LOGI("%{public}s: codec callback task thread started!", __func__);
    if (arg == NULL) {
        HDF_LOGE("%{public}s: Invalid arg, exit CodecTaskThread!", __func__);
        return NULL;
    }
    struct CodecInstance *instance = (struct CodecInstance *)arg;

    CodecBuffer *inputInfoSendToClient = NULL;
    CodecBuffer *outputInfoSendToClient = NULL;
    if (!InitData(&inputInfoSendToClient, &outputInfoSendToClient)) {
        HDF_LOGE("%{public}s: InitData failed!", __func__);
        return NULL;
    }

    CallbackTaskLoop(instance, inputInfoSendToClient, outputInfoSendToClient);

    OsalMutexLock(&instance->codecCallbackStatusLock);
    instance->codecCallbackStatus = CODEC_STATUS_STOPPED;
    pthread_cond_signal(&instance->codecCallbackStatusCond);
    OsalMutexUnlock(&instance->codecCallbackStatusLock);

    OsalMemFree(inputInfoSendToClient);
    OsalMemFree(outputInfoSendToClient);
    HDF_LOGI("%{public}s: codec callback task thread finished!", __func__);
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
    instance->codecCallbackStatus = CODEC_STATUS_IDLE;
    instance->inputEos = false;
    instance->hasCustomerCallback = false;
    return instance;
}

int32_t InitCodecInstance(struct CodecInstance *instance, struct CodecOemIf *oemIf)
{
    if (instance == NULL || oemIf == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }
    instance->codecOemIface = oemIf;
    instance->bufferManagerWrapper = GetBufferManager();
    if (instance->bufferManagerWrapper == NULL) {
        HDF_LOGE("%{public}s: GetBufferManager failed", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = OsalMutexInit(&instance->codecStatusLock);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: OsalMutexInit failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = pthread_cond_init(&instance->codecStatusCond, NULL);
    if (ret != 0) {
        HDF_LOGE("%{public}s: pthread_cond_init failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = OsalMutexInit(&instance->codecCallbackStatusLock);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: OsalMutexInit failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    ret = pthread_cond_init(&instance->codecCallbackStatusCond, NULL);
    if (ret != 0) {
        HDF_LOGE("%{public}s: pthread_cond_init failed, ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t RunCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }

    instance->codecStatus = CODEC_STATUS_STARTED;
    pthread_attr_init(&instance->codecTaskAttr);
    pthread_attr_setdetachstate(&instance->codecTaskAttr, PTHREAD_CREATE_JOINABLE);
    int32_t ret = pthread_create(&instance->codecTask, NULL, CodecTaskThread, instance);
    if (ret != 0) {
        HDF_LOGE("%{public}s: run codec task thread failed!", __func__);
        instance->codecStatus = CODEC_STATUS_STOPPED;
        return HDF_FAILURE;
    }

    if (instance->hasCustomerCallback) {
        instance->codecCallbackStatus = CODEC_STATUS_STARTED;
        pthread_attr_init(&instance->codecCallbackTaskAttr);
        pthread_attr_setdetachstate(&instance->codecCallbackTaskAttr, PTHREAD_CREATE_JOINABLE);
        ret = pthread_create(&instance->codecCallbackTask, NULL, CodecCallbackTaskThread, instance);
        if (ret != 0) {
            HDF_LOGE("%{public}s: run codec callback task thread failed!", __func__);
            instance->codecStatus = CODEC_STATUS_STOPPING;
            instance->codecCallbackStatus = CODEC_STATUS_STOPPED;
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int32_t StopCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }

    OsalMutexLock(&instance->codecStatusLock);
    if (instance->codecStatus == CODEC_STATUS_STARTED) {
        instance->codecStatus = CODEC_STATUS_STOPPING;
    } else {
        instance->codecStatus = CODEC_STATUS_STOPPED;
    }
    OsalMutexUnlock(&instance->codecStatusLock);

    OsalMutexLock(&instance->codecCallbackStatusLock);
    if (instance->codecCallbackStatus == CODEC_STATUS_STARTED) {
        instance->codecCallbackStatus = CODEC_STATUS_STOPPING;
    } else {
        instance->codecCallbackStatus = CODEC_STATUS_STOPPED;
    }
    OsalMutexUnlock(&instance->codecCallbackStatusLock);

    return HDF_SUCCESS;
}

int32_t DestroyCodecInstance(struct CodecInstance *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: Invalid param!", __func__);
        return HDF_FAILURE;
    }

    OsalMutexLock(&instance->codecStatusLock);
    if (instance->codecStatus == CODEC_STATUS_STARTED ||
        instance->codecStatus == CODEC_STATUS_STOPPING) {
        HDF_LOGI("%{public}s: wait codec task stop!", __func__);
        if (instance->codecStatusLock.realMutex != NULL) {
            pthread_cond_wait(&instance->codecStatusCond,
                (pthread_mutex_t *)instance->codecStatusLock.realMutex);
        }
    }
    OsalMutexUnlock(&instance->codecStatusLock);
    pthread_cond_destroy(&instance->codecStatusCond);
    OsalMutexDestroy(&instance->codecStatusLock);
    pthread_attr_destroy(&instance->codecTaskAttr);

    OsalMutexLock(&instance->codecCallbackStatusLock);
    if (instance->codecCallbackStatus == CODEC_STATUS_STARTED ||
        instance->codecCallbackStatus == CODEC_STATUS_STOPPING) {
        HDF_LOGI("%{public}s: wait codec callback task stop!", __func__);
        if (instance->codecStatusLock.realMutex != NULL) {
            pthread_cond_wait(&instance->codecCallbackStatusCond,
                (pthread_mutex_t *)instance->codecCallbackStatusLock.realMutex);
        }
    }
    OsalMutexUnlock(&instance->codecCallbackStatusLock);
    pthread_cond_destroy(&instance->codecCallbackStatusCond);
    OsalMutexDestroy(&instance->codecCallbackStatusLock);
    pthread_attr_destroy(&instance->codecCallbackTaskAttr);

    ReleaseInputShm(instance);
    ReleaseOutputShm(instance);
    ReleaseInputInfo(instance);
    ReleaseOutputInfo(instance);

    DeleteBufferManager(&(instance->bufferManagerWrapper));
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
    HDF_LOGE("%{public}s: not found bufferId:%{public}d!", __func__, id);
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
    HDF_LOGE("%{public}s: not found bufferId:%{public}d!", __func__, id);
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
    HDF_LOGE("%{public}s: not found bufferId:%{public}d!", __func__, id);
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
        HDF_LOGE("%{public}s: dst or src is Nullpoint", __func__);
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
        HDF_LOGE("%{public}s buffer handle is NULL", __func__);
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

