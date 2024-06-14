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

#include "codec_service.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <securec.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "ashmem_wrapper.h"
#ifndef CODEC_HAL_PASSTHROUGH
#include "codec_callback_proxy.h"
#include "codec_config_parser.h"
#endif
#include "codec_instance_manager.h"
#include "hdf_log.h"
#include "osal_mem.h"
#include "osal_mutex.h"

#define HDF_LOG_TAG codec_hdi_service
#define VIDEO_HARDWARE_ENCODER_INDEX 0
#define VIDEO_HARDWARE_DECODER_INDEX 1
#define AUDIO_HARDWARE_ENCODER_INDEX 4
#define AUDIO_HARDWARE_DECODER_INDEX 5
#define CODEC_OEM_INTERFACE_LIB_NAME "libcodec_oem_interface.z.so"

struct CodecOemIf *g_codecOemIface = NULL;
void *g_oemLibHandle = NULL;
#ifndef CODEC_HAL_PASSTHROUGH
struct OsalMutex g_oemIfaceLock;
int g_oemIfaceRefCount = 0;     /** Client process reference count. */
#endif

static int32_t CodecOnEvent(UINTPTR userData, EventType event, uint32_t length, int32_t eventData[])
{
    struct CodecInstance *instance = FindInCodecInstanceManager((CODEC_HANDLETYPE)userData);
    if (instance == NULL) {
        HDF_LOGE("%{public}s: instance is NULL!", __func__);
        return HDF_FAILURE;
    }
#ifdef CODEC_HAL_PASSTHROUGH
    if (instance->hasCustomerCallback && instance->codecCallback != NULL) {
        instance->codecCallback->OnEvent(instance->callbackUserData, event, length, eventData);
    }
#else
    if (instance->hasCustomerCallback && instance->callbackProxy != NULL) {
        instance->callbackProxy->OnEvent(instance->callbackProxy, instance->callbackUserData,
            event, length, eventData);
    }
#endif
    return HDF_SUCCESS;
}

static int32_t CodecInputBufferAvailable(UINTPTR userData, CodecBuffer *inBuf, int32_t *acquireFd)
{
    struct CodecInstance *instance = FindInCodecInstanceManager((CODEC_HANDLETYPE)userData);
    if (instance == NULL) {
        HDF_LOGE("%{public}s: instance is NULL!", __func__);
        return HDF_FAILURE;
    }
    if (inBuf == NULL || inBuf->bufferCnt == 0) {
        HDF_LOGE("%{public}s: inBuf Nullpoint or buf not assigned", __func__);
        return HDF_FAILURE;
    }
    CodecBuffer *inputInfo = GetInputInfo(instance, inBuf->bufferId);
    if (inputInfo == NULL || inputInfo->bufferCnt == 0) {
        HDF_LOGE("%{public}s: inputInfo Nullpoint or buf not assigned", __func__);
        return HDF_FAILURE;
    }
    CopyCodecBufferWithTypeSwitch(instance, inputInfo, inBuf, true);
    EmptyCodecBuffer(inputInfo);
    instance->bufferManagerWrapper->PutUsedInputDataBuffer(instance->bufferManagerWrapper, inputInfo);
    return HDF_SUCCESS;
}

static int32_t CodecOutputBufferAvailable(UINTPTR userData, CodecBuffer *outBuf, int32_t *acquireFd)
{
    struct CodecInstance *instance = FindInCodecInstanceManager((CODEC_HANDLETYPE)userData);
    if (instance == NULL) {
        HDF_LOGE("%{public}s: instance is NULL!", __func__);
        return HDF_FAILURE;
    }
    if (outBuf == NULL || outBuf->bufferCnt == 0) {
        HDF_LOGE("%{public}s: outBuf Nullpoint or buf not assigned", __func__);
        return HDF_FAILURE;
    }
    CodecBuffer *outputInfo = GetOutputInfo(instance, outBuf->bufferId);
    if (outputInfo == NULL || outputInfo->bufferCnt == 0) {
        HDF_LOGE("%{public}s: outputInfo Nullpoint or buf not assigned", __func__);
        return HDF_FAILURE;
    }
    CopyCodecBufferWithTypeSwitch(instance, outputInfo, outBuf, true);
    instance->bufferManagerWrapper->PutOutputDataBuffer(instance->bufferManagerWrapper, outputInfo);
    // get a new OutputBuffer
    CodecBuffer *output = NULL;
    while (output == NULL && instance->codecStatus == CODEC_STATUS_STARTED) {
        output = instance->bufferManagerWrapper->GetUsedOutputDataBuffer(
            instance->bufferManagerWrapper, QUEUE_TIME_OUT);
    }
    if (output == NULL) {
        HDF_LOGE("%{public}s: output is NULL", __func__);
        return HDF_FAILURE;
    }
    SetOemCodecBufferType(outBuf, output);
    CopyCodecBufferWithTypeSwitch(instance, outBuf, output, false);

    return HDF_SUCCESS;
}

#ifndef CODEC_HAL_PASSTHROUGH
void InitOemIfaceLock(void)
{
    OsalMutexInit(&g_oemIfaceLock);
}

void DeinitOemIfaceLock(void)
{
    OsalMutexDestroy(&g_oemIfaceLock);
}
#endif

static int32_t InitCodecOemIf(struct CodecOemIf **codecOemIface)
{
    *codecOemIface = (struct CodecOemIf *)OsalMemCalloc(sizeof(struct CodecOemIf));
    if (*codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecOemIface mem alloc failed", __func__);
        return HDF_FAILURE;
    }
    g_oemLibHandle = dlopen(CODEC_OEM_INTERFACE_LIB_NAME, RTLD_NOW);
    if (g_oemLibHandle == NULL) {
        HDF_LOGE("%{public}s: lib %{public}s dlopen failed, error code[%{public}s]",
            __func__, CODEC_OEM_INTERFACE_LIB_NAME, dlerror());
        OsalMemFree(*codecOemIface);
        *codecOemIface = NULL;
        return HDF_FAILURE;
    }

    (*codecOemIface)->codecInit = (CodecInitType)dlsym(g_oemLibHandle, "CodecInit");
    (*codecOemIface)->codecDeinit = (CodecDeinitType)dlsym(g_oemLibHandle, "CodecDeinit");
    (*codecOemIface)->codecCreate = (CodecCreateType)dlsym(g_oemLibHandle, "CodecCreate");
    (*codecOemIface)->codecDestroy = (CodecDestroyType)dlsym(g_oemLibHandle, "CodecDestroy");
    (*codecOemIface)->codecSetParameter = (CodecSetParameterType)dlsym(g_oemLibHandle, "CodecSetParameter");
    (*codecOemIface)->codecGetParameter = (CodecGetParameterType)dlsym(g_oemLibHandle, "CodecGetParameter");
    (*codecOemIface)->codecStart = (CodecStartType)dlsym(g_oemLibHandle, "CodecStart");
    (*codecOemIface)->codecStop = (CodecStopType)dlsym(g_oemLibHandle, "CodecStop");
    (*codecOemIface)->codecFlush = (CodecFlushType)dlsym(g_oemLibHandle, "CodecFlush");
    (*codecOemIface)->codecSetCallback = (CodecSetCallbackType)dlsym(g_oemLibHandle, "CodecSetCallback");
    (*codecOemIface)->codecDecode = (CodecDecodeType)dlsym(g_oemLibHandle, "CodecDecode");
    (*codecOemIface)->codecEncode = (CodecEncodeType)dlsym(g_oemLibHandle, "CodecEncode");
    (*codecOemIface)->codecEncodeHeader = (CodecEncodeHeaderType)dlsym(g_oemLibHandle, "CodecEncodeHeader");

    return HDF_SUCCESS;
}

static void DeinitCodecOemIf(void)
{
    if (g_codecOemIface != NULL) {
        OsalMemFree(g_codecOemIface);
        g_codecOemIface = NULL;
    }
}

int32_t CodecInit(void)
{
#ifndef CODEC_HAL_PASSTHROUGH
    OsalMutexLock(&g_oemIfaceLock);
#endif
    if (g_codecOemIface == NULL) {
        HDF_LOGI("%{public}s: g_codecOemIface is NULL, do init!", __func__);
        if (InitCodecOemIf(&g_codecOemIface) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: InitCodecOemIf failed!", __func__);
#ifndef CODEC_HAL_PASSTHROUGH
            OsalMutexUnlock(&g_oemIfaceLock);
#endif
            return HDF_FAILURE;
        }
    }
#ifndef CODEC_HAL_PASSTHROUGH
    g_oemIfaceRefCount++;
    HDF_LOGI("%{public}s: oemIface ref increased to: %{public}d", __func__, g_oemIfaceRefCount);
    OsalMutexUnlock(&g_oemIfaceLock);
#endif
    return g_codecOemIface->codecInit();
}

int32_t CodecDeinit(void)
{
    if (g_codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecOemIface is NULL!", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = g_codecOemIface->codecDeinit();
#ifndef CODEC_HAL_PASSTHROUGH
    OsalMutexLock(&g_oemIfaceLock);
    g_oemIfaceRefCount--;
    HDF_LOGI("%{public}s: oemIface ref decreased to: %{public}d", __func__, g_oemIfaceRefCount);
    if (g_oemIfaceRefCount <= 0) {
#endif
        DeinitCodecOemIf();
        HDF_LOGI("%{public}s: call DeinitCodecOemIf", __func__);
#ifndef CODEC_HAL_PASSTHROUGH
        g_oemIfaceRefCount = 0;
    }
    OsalMutexUnlock(&g_oemIfaceLock);
#endif

    return ret;
}

int32_t CodecEnumerateCapability(uint32_t index, CodecCapability *cap)
{
#ifndef CODEC_HAL_PASSTHROUGH
    int32_t loopIndex;
    uint32_t cursor = index;
    CodecCapablityGroup *group = NULL;
    if (cursor + 1 < cursor) {
        HDF_LOGE("%{public}s: the index out of bounds!", __func__);
        return HDF_FAILURE;
    }
    for (loopIndex = 0; loopIndex < CODEC_CAPABLITY_GROUP_NUM; loopIndex++) {
        group = GetCapablityGroup(loopIndex);
        if (group == NULL) {
            continue;
        }
        if (cursor + 1 <= (uint32_t)group->num) {
            *cap = group->capablitis[cursor];
            return HDF_SUCCESS;
        } else {
            cursor -= (uint32_t)group->num;
        }
    }
#endif
    return HDF_FAILURE;
}

int32_t CodecGetCapability(AvCodecMime mime, CodecType type, uint32_t flags, CodecCapability *cap)
{
#ifndef CODEC_HAL_PASSTHROUGH
    int32_t groupIndex;
    int32_t capIndex;
    CodecCapablityGroup *group = NULL;
    CodecCapability *capItem;
    bool inputHardwareFlag = flags == 0;

    for (groupIndex = 0; groupIndex < CODEC_CAPABLITY_GROUP_NUM; groupIndex++) {
        group = GetCapablityGroup(groupIndex);
        if (group == NULL) {
            continue;
        }
        bool curHardwareFlag = (groupIndex == VIDEO_HARDWARE_ENCODER_INDEX)
            || (groupIndex == VIDEO_HARDWARE_DECODER_INDEX) || (groupIndex == AUDIO_HARDWARE_ENCODER_INDEX)
            || (groupIndex == AUDIO_HARDWARE_DECODER_INDEX);
        if (inputHardwareFlag != curHardwareFlag) {
            continue;
        }
        for (capIndex = 0; capIndex < group->num; capIndex++) {
            capItem = &group->capablitis[capIndex];
            if (mime == capItem->mime && type == capItem->type) {
                *cap = group->capablitis[capIndex];
                return HDF_SUCCESS;
            }
        }
    }
#endif
    return HDF_FAILURE;
}

int32_t CodecCreate(const char* name, CODEC_HANDLETYPE *handle)
{
    struct CodecInstance *instance = GetCodecInstance();
    if (instance == NULL || g_codecOemIface == NULL) {
        HDF_LOGE("%{public}s: instance or g_codecOemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    int32_t ret = InitCodecInstance(instance, g_codecOemIface);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: InitCodecInstance failed!", __func__);
        return ret;
    }
    ret = g_codecOemIface->codecCreate(name, handle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: g_codecOemIface->codecCreate failed!", __func__);
        return ret;
    }
    instance->handle = *handle;
    HDF_LOGI("%{public}s codec created", __func__);
    if (!AddToCodecInstanceManager(*handle, instance)) {
        HDF_LOGE("%{public}s: AddToCodecInstanceManager failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CodecCreateByType(CodecType type, AvCodecMime mime, CODEC_HANDLETYPE *handle)
{
    (void)type;
    (void)mime;
    (void)handle;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t CodecDestroy(CODEC_HANDLETYPE handle)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    int32_t destroyInstanceResult;
    if (instance != NULL) {
#ifndef CODEC_HAL_PASSTHROUGH
        CodecProxyCallbackRelease(instance->callbackProxy);
#endif
        destroyInstanceResult = DestroyCodecInstance(instance);
        RemoveFromCodecInstanceManager(handle);
        OsalMemFree(instance);
    } else {
        HDF_LOGE("%{public}s: instance is NULL!", __func__);
        destroyInstanceResult = HDF_FAILURE;
    }

    int32_t destroyIfaceResult;
    if (g_codecOemIface != NULL) {
        destroyIfaceResult = g_codecOemIface->codecDestroy(handle);
    } else {
        HDF_LOGE("%{public}s: g_codecOemIface is NULL!", __func__);
        destroyIfaceResult = HDF_FAILURE;
    }

    if (destroyInstanceResult != HDF_SUCCESS || destroyIfaceResult != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: destroyInstanceResult or destroyIfaceResult not HDF_SUCCESS!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CodecSetPortMode(CODEC_HANDLETYPE handle, DirectionType direct, AllocateBufferMode mode, BufferType type)
{
    (void)handle;
    (void)direct;
    (void)mode;
    (void)type;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t CodecGetPortMode(CODEC_HANDLETYPE handle, DirectionType direct, AllocateBufferMode *mode, BufferType *type)
{
    (void)handle;
    (void)direct;
    (void)mode;
    (void)type;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t CodecSetParameter(CODEC_HANDLETYPE handle, const Param *params, int32_t paramCnt)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    if (instance == NULL || g_codecOemIface == NULL) {
        HDF_LOGE("%{public}s: instance or g_codecOemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    if (params == NULL || paramCnt <= 0) {
        HDF_LOGE("%{public}s: params empty!", __func__);
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (params[i].key != KEY_CODEC_TYPE) {
            continue;
        }
        int32_t codecType = 0;
        if (memcpy_s(&codecType, sizeof(codecType), params[i].val, params[i].size) != EOK) {
            HDF_LOGE("%{public}s: memcpy_s params failed!", __func__);
            return HDF_FAILURE;
        }
        instance->codecType = codecType;
    }
    return g_codecOemIface->codecSetParameter(handle, params, paramCnt);
}

int32_t CodecGetParameter(CODEC_HANDLETYPE handle, Param *params, int32_t paramCnt)
{
    if (g_codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecOemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    if (params == NULL || paramCnt <= 0) {
        HDF_LOGE("%{public}s: params empty!", __func__);
        return HDF_FAILURE;
    }
    return g_codecOemIface->codecGetParameter(handle, params, paramCnt);
}

int32_t CodecStart(CODEC_HANDLETYPE handle)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    if (instance == NULL || g_codecOemIface == NULL) {
        HDF_LOGE("%{public}s: instance or g_codecOemIface is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (!instance->hasCustomerCallback) {
        instance->defaultCb.OnEvent = CodecOnEvent;
        instance->defaultCb.InputBufferAvailable = CodecInputBufferAvailable;
        instance->defaultCb.OutputBufferAvailable = CodecOutputBufferAvailable;
        if (g_codecOemIface->codecSetCallback(handle, &(instance->defaultCb), 0) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: call oem codecSetCallback failed!", __func__);
            return HDF_FAILURE;
        }
    }

    if (g_codecOemIface->codecStart(handle) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call oem codecStart failed!", __func__);
        return HDF_FAILURE;
    }
    return RunCodecInstance(instance);
}

int32_t CodecStop(CODEC_HANDLETYPE handle)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    if (instance == NULL) {
        HDF_LOGE("%{public}s: instance is NULL!", __func__);
        return HDF_FAILURE;
    }
    return StopCodecInstance(instance);
}

int32_t CodecReset(CODEC_HANDLETYPE handle)
{
    (void)handle;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t CodecFlush(CODEC_HANDLETYPE handle, DirectionType directType)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    if (instance == NULL || g_codecOemIface == NULL) {
        HDF_LOGE("%{public}s: instance or g_codecOemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    return g_codecOemIface->codecFlush(handle, directType);
}

int32_t CodecQueueInput(CODEC_HANDLETYPE handle, const CodecBuffer *inputData, uint32_t timeoutMs, int releaseFenceFd)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    if (instance == NULL || instance->bufferManagerWrapper == NULL) {
        HDF_LOGE("%{public}s: instance or buffermanager is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (instance->codecStatus == CODEC_STATUS_IDLE) {
        if (instance->codecType != VIDEO_DECODER && instance->codecType != AUDIO_DECODER &&
            instance->codecType != VIDEO_ENCODER && instance->codecType != AUDIO_ENCODER) {
            HDF_LOGE("%{public}s: codecType invalid, queue input buffer failed!", __func__);
            return HDF_FAILURE;
        }
        for (uint32_t i = 0; i < inputData->bufferCnt; i++) {
            if (AddInputShm(instance, &inputData->buffer[i], inputData->bufferId) != HDF_SUCCESS) {
                HDF_LOGE("%{public}s: AddInputShm failed, queue input buffer failed!", __func__);
                return HDF_FAILURE;
            }
        }
        CodecBuffer *dup = DupCodecBuffer(inputData);
        if (AddInputInfo(instance, dup) != HDF_SUCCESS) {
            ReleaseCodecBuffer(dup);
            HDF_LOGE("%{public}s: AddInputInfo failed, queue input buffer failed!", __func__);
            return HDF_FAILURE;
        }
        instance->bufferManagerWrapper->PutUsedInputDataBuffer(instance->bufferManagerWrapper, dup);
        return HDF_SUCCESS;
    } else if (instance->codecStatus == CODEC_STATUS_STARTED) {
        CodecBuffer *info = GetInputInfo(instance, inputData->bufferId);
        CopyCodecBufferWithTypeSwitch(instance, info, inputData, true);
        instance->bufferManagerWrapper->PutInputDataBuffer(instance->bufferManagerWrapper, info);
        if ((inputData->flag & STREAM_FLAG_EOS) != 0) {
            instance->inputEos = true;
            HDF_LOGI("%{public}s: input reach STREAM_FLAG_EOS!", __func__);
        }
        return HDF_SUCCESS;
    }
    return HDF_SUCCESS;
}

int32_t CodecDequeueInput(CODEC_HANDLETYPE handle, uint32_t timeoutMs, int32_t *acquireFd, CodecBuffer *inputData)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    if (instance == NULL || instance->bufferManagerWrapper == NULL) {
        HDF_LOGE("%{public}s: instance or buffermanager is NULL!", __func__);
        return HDF_FAILURE;
    }

    CodecBuffer *info = instance->bufferManagerWrapper->GetUsedInputDataBuffer(
        instance->bufferManagerWrapper, timeoutMs);
    if (info != NULL) {
        *acquireFd = -1;
        inputData->buffer[0].type = info->buffer[0].type;
        CopyCodecBufferWithTypeSwitch(instance, inputData, info, false);
        // fd has been transmitted at the initial time, here set invalid to avoid being transmitted again
        if (inputData->buffer[0].type == BUFFER_TYPE_FD) {
            inputData->buffer[0].buf = NO_TRANSMIT_FD;
        } else if (inputData->buffer[0].type == BUFFER_TYPE_HANDLE) {
            inputData->buffer[0].buf = NO_TRANSMIT_BUFFERHANDLE;
        }
    } else {
        return HDF_ERR_TIMEOUT;
    }
    
    return HDF_SUCCESS;
}

int32_t CodecQueueOutput(CODEC_HANDLETYPE handle, CodecBuffer *outInfo, uint32_t timeoutMs, int releaseFenceFd)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    if (instance == NULL || instance->bufferManagerWrapper == NULL) {
        HDF_LOGE("%{public}s: instance or buffermanager is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (instance->codecStatus == CODEC_STATUS_IDLE) {
        if (instance->codecType != VIDEO_DECODER && instance->codecType != AUDIO_DECODER &&
            instance->codecType != VIDEO_ENCODER && instance->codecType != AUDIO_ENCODER) {
            HDF_LOGE("%{public}s: codecType invalid, queue output buffer failed!", __func__);
            return HDF_FAILURE;
        }
        for (uint32_t i = 0; i < outInfo->bufferCnt; i++) {
            if (AddOutputShm(instance, &outInfo->buffer[i], outInfo->bufferId) != HDF_SUCCESS) {
                HDF_LOGE("%{public}s: AddOutputShm failed, queue output buffer failed!", __func__);
            }
        }
        CodecBuffer *dup = DupCodecBuffer(outInfo);
        if (AddOutputInfo(instance, dup) != HDF_SUCCESS) {
            ReleaseCodecBuffer(dup);
            HDF_LOGE("%{public}s: AddOutputInfo failed, queue output buffer failed!", __func__);
            return HDF_FAILURE;
        }
        instance->bufferManagerWrapper->PutUsedOutputDataBuffer(instance->bufferManagerWrapper, dup);
        return HDF_SUCCESS;
    } else if (instance->codecStatus == CODEC_STATUS_STARTED ||
        instance->codecCallbackStatus == CODEC_STATUS_STARTED) {
        CodecBuffer *info = GetOutputInfo(instance, outInfo->bufferId);
        CopyCodecBufferWithTypeSwitch(instance, info, outInfo, true);
        EmptyCodecBuffer(info);
        instance->bufferManagerWrapper->PutUsedOutputDataBuffer(instance->bufferManagerWrapper, info);
        return HDF_SUCCESS;
    } else if (instance->codecStatus == CODEC_STATUS_STOPPED || instance->codecStatus == CODEC_STATUS_STOPPING) {
        CodecBuffer *dup = DupCodecBuffer(outInfo);
        instance->bufferManagerWrapper->PutOutputDataBuffer(instance->bufferManagerWrapper, dup);
    }
    return HDF_SUCCESS;
}

int32_t CodecDequeueOutput(CODEC_HANDLETYPE handle, uint32_t timeoutMs, int32_t *acquireFd, CodecBuffer *outInfo)
{
    struct CodecInstance *instance = FindInCodecInstanceManager(handle);
    if (instance == NULL || instance->bufferManagerWrapper == NULL) {
        HDF_LOGE("%{public}s: instance or buffermanager is NULL!", __func__);
        return HDF_FAILURE;
    }
    
    CodecBuffer *info = instance->bufferManagerWrapper->GetOutputDataBuffer(
        instance->bufferManagerWrapper, timeoutMs);
    if (info != NULL) {
        *acquireFd = -1;
        outInfo->buffer[0].type = info->buffer[0].type;
        CopyCodecBufferWithTypeSwitch(instance, outInfo, info, false);
        // fd has been transmitted at the initial time, here set invalid to avoid being transmitted again
        if (outInfo->buffer[0].type == BUFFER_TYPE_FD) {
            outInfo->buffer[0].buf = NO_TRANSMIT_FD;
        } else if (outInfo->buffer[0].type == BUFFER_TYPE_HANDLE) {
            outInfo->buffer[0].buf = NO_TRANSMIT_BUFFERHANDLE;
        }
    } else {
        return HDF_ERR_TIMEOUT;
    }
    
    return HDF_SUCCESS;
}

#ifndef CODEC_HAL_PASSTHROUGH
int32_t CodecSetCallbackProxy(CODEC_HANDLETYPE handle, struct ICodecCallbackProxy *cb, UINTPTR instance)
{
    struct CodecInstance *codecInstance = FindInCodecInstanceManager(handle);
    if (codecInstance == NULL || g_codecOemIface == NULL) {
        HDF_LOGE("%{public}s: instance or g_codecOemIface is NULL!", __func__);
        return HDF_FAILURE;
    }

    codecInstance->callbackUserData = instance;
    codecInstance->callbackProxy = cb;
    codecInstance->hasCustomerCallback = true;

    codecInstance->defaultCb.OnEvent = CodecOnEvent;
    codecInstance->defaultCb.InputBufferAvailable = CodecInputBufferAvailable;
    codecInstance->defaultCb.OutputBufferAvailable = CodecOutputBufferAvailable;
    if (g_codecOemIface->codecSetCallback(handle, &(codecInstance->defaultCb), 0) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call oem codecSetCallback failed!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
#else
int32_t CodecSetCallback(CODEC_HANDLETYPE handle, CodecCallback *cb, UINTPTR instance)
{
    struct CodecInstance *codecInstance = FindInCodecInstanceManager(handle);
    if (codecInstance == NULL || g_codecOemIface == NULL) {
        HDF_LOGE("%{public}s: instance or g_codecOemIface is NULL!", __func__);
        return HDF_FAILURE;
    }

    codecInstance->callbackUserData = instance;
    codecInstance->codecCallback = cb;
    codecInstance->hasCustomerCallback = true;

    codecInstance->defaultCb.OnEvent = CodecOnEvent;
    codecInstance->defaultCb.InputBufferAvailable = CodecInputBufferAvailable;
    codecInstance->defaultCb.OutputBufferAvailable = CodecOutputBufferAvailable;
    if (g_codecOemIface->codecSetCallback(handle, &(codecInstance->defaultCb), 0) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call oem codecSetCallback failed!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}
#endif

