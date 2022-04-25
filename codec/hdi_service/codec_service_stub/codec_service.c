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

#include "codec_service.h"
#include <errno.h>
#include <fcntl.h>
#include <securec.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "ashmem_wrapper.h"
#include "hdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG codec_hdi_service

struct CodecInstance *g_codecInstance = NULL;

static void CopyInputInfo(InputInfo *dst, const InputInfo *src)
{
    if (dst == NULL || src == NULL) {
        HDF_LOGE("%{public}s: Nullpoint, dst: %{public}p, src: %{public}p", __func__, dst, src);
        return;
    }
    dst->bufferCnt = src->bufferCnt;
    dst->pts = src->pts;
    dst->flag = src->flag;
    if (dst->bufferCnt > 0) {
        int32_t size = sizeof(CodecBufferInfo) * dst->bufferCnt;
        memcpy_s(dst->buffers, size, src->buffers, size);
    }
}

static InputInfo* DupInputInfo(const InputInfo *src)
{
    if (src == NULL) {
        HDF_LOGE("%{public}s: inputinfo src Nullpoint", __func__);
        return NULL;
    }
    InputInfo *dst = (InputInfo *)OsalMemAlloc(sizeof(InputInfo));
    if (dst == NULL) {
        HDF_LOGE("%{public}s: dst Nullpoint", __func__);
        return NULL;
    }
    dst->bufferCnt = src->bufferCnt;
    dst->pts = src->pts;
    dst->flag = src->flag;
    if (dst->bufferCnt > 0) {
        int32_t size = sizeof(CodecBufferInfo) * dst->bufferCnt;
        dst->buffers = (CodecBufferInfo *)OsalMemAlloc(size);
        if (dst->buffers != NULL) {
            memcpy_s(dst->buffers, size, src->buffers, size);
        }
    }
    return dst;
}

static void CopyOutputInfo(OutputInfo *dst, OutputInfo *src)
{
    if (dst == NULL || src == NULL) {
        HDF_LOGE("%{public}s: Nullpoint, dst: %{public}p, src: %{public}p", __func__, dst, src);
        return;
    }
    dst->bufferCnt = src->bufferCnt;
    dst->timeStamp = src->timeStamp;
    dst->sequence = src->sequence;
    dst->flag = src->flag;
    dst->type = src->type;
    dst->vendorPrivate = src->vendorPrivate;
    if (dst->bufferCnt > 0) {
        int32_t size = sizeof(CodecBufferInfo) * dst->bufferCnt;
        memcpy_s(dst->buffers, size, src->buffers, size);
    }
}

static OutputInfo* DupOutputInfo(OutputInfo *src)
{
    if (src == NULL) {
        HDF_LOGE("%{public}s: src Nullpoint", __func__);
        return NULL;
    }
    OutputInfo *dst = (OutputInfo *)OsalMemAlloc(sizeof(OutputInfo));
    if (dst == NULL) {
        HDF_LOGE("%{public}s: dst Nullpoint", __func__);
        return NULL;
    }
    dst->bufferCnt = src->bufferCnt;
    dst->timeStamp = src->timeStamp;
    dst->sequence = src->sequence;
    dst->flag = src->flag;
    dst->type = src->type;
    dst->vendorPrivate = src->vendorPrivate;
    if (dst->bufferCnt > 0) {
        int32_t size = sizeof(CodecBufferInfo) * dst->bufferCnt;
        dst->buffers = (CodecBufferInfo *)OsalMemAlloc(size);
        if (dst->buffers != NULL) {
            memcpy_s(dst->buffers, size, src->buffers, size);
        }
    }
    return dst;
}

static int32_t DefaultCbOnEvent(UINTPTR comp, UINTPTR appData, EventType event,
    uint32_t data1, uint32_t data2, UINTPTR eventData)
{
    return HDF_SUCCESS;
}

static int32_t DefaultCbInputBufferAvailable(UINTPTR comp, UINTPTR appData, InputInfo *inBuf)
{
    if (inBuf == NULL || inBuf->buffers == NULL) {
        HDF_LOGE("%{public}s: inBuf Nullpoint", __func__);
        return HDF_FAILURE;
    }
    InputInfo *inputInfo = GetInputInfo(g_codecInstance, inBuf->buffers->offset);
    if (inputInfo == NULL || inputInfo->buffers == NULL) {
        HDF_LOGE("%{public}s: inputInfo Nullpoint", __func__);
        return HDF_FAILURE;
    }
    inputInfo->buffers->fd = GetFdById(g_codecInstance, inBuf->buffers->offset);
    inputInfo->buffers->type = BUFFER_TYPE_FD;
    g_codecInstance->bufferManagerWrapper->PutUsedInputDataBuffer(g_codecInstance->bufferManagerWrapper, inputInfo);
    return HDF_SUCCESS;
}

static int32_t DefaultCbOutputBufferAvailable(UINTPTR comp, UINTPTR appData, OutputInfo *outBuf)
{
    if (outBuf == NULL || outBuf->buffers == NULL) {
        HDF_LOGE("%{public}s: outBuf Nullpoint", __func__);
        return HDF_FAILURE;
    }
    struct BufferManagerWrapper *bmWrapper = g_codecInstance->bufferManagerWrapper;
    OutputInfo *outputInfo = GetOutputInfo(g_codecInstance, outBuf->buffers->offset);
    if (outputInfo == NULL || outputInfo->buffers == NULL) {
        HDF_LOGE("%{public}s: outputInfo Nullpoint", __func__);
        return HDF_FAILURE;
    }
    CopyOutputInfo(outputInfo, outBuf);
    outputInfo->buffers->fd = GetFdById(g_codecInstance, outBuf->buffers->offset);
    outputInfo->buffers->type = BUFFER_TYPE_FD;
    bmWrapper->PutOutputDataBuffer(bmWrapper, outputInfo);

    // get a new OutputBuffer
    OutputInfo *output = NULL;
    while (output == NULL && g_codecInstance->codecStatus == CODEC_STATUS_STARTED) {
        output = bmWrapper->GetUsedOutputDataBuffer(bmWrapper, QUEUE_TIME_OUT);
    }
    outBuf->buffers->type = BUFFER_TYPE_VIRTUAL;
    outBuf->buffers->offset = output->buffers->offset;
    outBuf->buffers->addr = GetOutputShm(g_codecInstance, output->buffers->offset)->virAddr;

    return HDF_SUCCESS;
}

int32_t CodecInit()
{
    g_codecInstance = GetCodecInstance();
    InitCodecInstance(g_codecInstance);

    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    g_codecInstance->codecOemIface->CodecInit();
    return HDF_SUCCESS;
}

int32_t CodecDeinit()
{
    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    g_codecInstance->codecOemIface->CodecDeinit();
    DestroyCodecInstance(g_codecInstance);
    g_codecInstance = NULL;
    return HDF_SUCCESS;
}

int32_t CodecEnumerateCapbility(uint32_t index, CodecCapbility *cap)
{
    return HDF_SUCCESS;
}

int32_t CodecGetCapbility(AvCodecMime mime, CodecType type, uint32_t flags, CodecCapbility *cap)
{
    return HDF_SUCCESS;
}

int32_t CodecCreate(const char* name, const Param *attr, int32_t len, CODEC_HANDLETYPE *handle)
{
    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    g_codecInstance->codecOemIface->CodecCreate(name, attr, len, handle);
    g_codecInstance->handle = *handle;
    HDF_LOGI("%{public}s codec created", __func__);
    return HDF_SUCCESS;
}

int32_t CodecDestroy(CODEC_HANDLETYPE handle)
{
    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    g_codecInstance->codecOemIface->CodecDestroy(handle);
    return HDF_SUCCESS;
}

int32_t CodecSetPortMode(CODEC_HANDLETYPE handle, DirectionType type, BufferMode mode)
{
    return HDF_SUCCESS;
}

int32_t CodecSetParameter(CODEC_HANDLETYPE handle, const Param *params, int32_t paramCnt)
{
    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (params[i].key == KEY_CODEC_TYPE) {
            int32_t codecType = 0;
            memcpy_s(&codecType, sizeof(codecType), params[i].val, params[i].size);
            g_codecInstance->codecType = codecType;
        }
    }
    g_codecInstance->codecOemIface->CodecSetParameter(handle, params, paramCnt);
    return HDF_SUCCESS;
}

int32_t CodecGetParameter(CODEC_HANDLETYPE handle, Param *params, int32_t paramCnt)
{
    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    g_codecInstance->codecOemIface->CodecGetParameter(handle, params, paramCnt);
    return HDF_SUCCESS;
}

int32_t CodecStart(CODEC_HANDLETYPE handle)
{
    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    if (!g_codecInstance->hasCallback) {
        g_codecInstance->defaultCb.OnEvent = DefaultCbOnEvent;
        g_codecInstance->defaultCb.InputBufferAvailable = DefaultCbInputBufferAvailable;
        g_codecInstance->defaultCb.OutputBufferAvailable = DefaultCbOutputBufferAvailable;
        g_codecInstance->codecOemIface->CodecSetCallback(handle, &(g_codecInstance->defaultCb), 0);
    }
    RunCodecInstance(g_codecInstance);
    return HDF_SUCCESS;
}

int32_t CodecStop(CODEC_HANDLETYPE handle)
{
    if (g_codecInstance == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance is NULL!", __func__);
        return HDF_FAILURE;
    }
    StopCodecInstance(g_codecInstance);
    return HDF_SUCCESS;
}

int32_t CodecFlush(CODEC_HANDLETYPE handle, DirectionType directType)
{
    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    g_codecInstance->codecOemIface->CodecFlush(handle, directType);
    return HDF_SUCCESS;
}

int32_t CodecQueueInput(CODEC_HANDLETYPE handle, const InputInfo *inputInfo, uint32_t timeoutMs)
{
    if (g_codecInstance == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (g_codecInstance->codecStatus == CODEC_STATUS_IDLE) {
        uint32_t i;
        if (g_codecInstance->codecType == VIDEO_DECODER || g_codecInstance->codecType == AUDIO_DECODER ||
            g_codecInstance->codecType == VIDEO_ENCODER || g_codecInstance->codecType == AUDIO_ENCODER) {
            for (i = 0; i < inputInfo->bufferCnt; i++) {
                AddInputShm(g_codecInstance, &inputInfo->buffers[i]);
            }
        } else {
            HDF_LOGE("%{public}s: codecType invalid, queue input buffer failed!", __func__);
            return HDF_FAILURE;
        }
        InputInfo *dup = DupInputInfo(inputInfo);
        AddInputInfo(g_codecInstance, dup);
        g_codecInstance->bufferManagerWrapper->PutUsedInputDataBuffer(g_codecInstance->bufferManagerWrapper, dup);
        return HDF_SUCCESS;
    } else if (g_codecInstance->codecStatus == CODEC_STATUS_STARTED) {
        InputInfo *info = GetInputInfo(g_codecInstance, inputInfo->buffers[0].offset);
        CopyInputInfo(info, inputInfo);
        g_codecInstance->bufferManagerWrapper->PutInputDataBuffer(g_codecInstance->bufferManagerWrapper, info);
        return HDF_SUCCESS;
    }
    return HDF_SUCCESS;
}

int32_t CodecDequeInput(CODEC_HANDLETYPE handle, uint32_t timeoutMs, InputInfo *inputData)
{
    if (g_codecInstance == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance is NULL!", __func__);
        return HDF_FAILURE;
    }

    InputInfo *info = g_codecInstance->bufferManagerWrapper->GetUsedInputDataBuffer(
        g_codecInstance->bufferManagerWrapper, QUEUE_TIME_OUT);
    if (info != NULL) {
        CopyInputInfo(inputData, info);
    } else {
        return HDF_ERR_TIMEOUT;
    }
    
    return HDF_SUCCESS;
}

int32_t CodecQueueOutput(CODEC_HANDLETYPE handle, OutputInfo *outInfo, uint32_t timeoutMs, int32_t releaseFenceFd)
{
    if (g_codecInstance == NULL || g_codecInstance->bufferManagerWrapper == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or buffermanager is NULL!", __func__);
        return HDF_FAILURE;
    }

    if (g_codecInstance->codecStatus == CODEC_STATUS_IDLE) {
        uint32_t i;
        if (g_codecInstance->codecType == VIDEO_DECODER || g_codecInstance->codecType == AUDIO_DECODER ||
            g_codecInstance->codecType == VIDEO_ENCODER || g_codecInstance->codecType == AUDIO_ENCODER) {
            for (i = 0; i < outInfo->bufferCnt; i++) {
                AddOutputShm(g_codecInstance, &outInfo->buffers[i]);
            }
        } else {
            HDF_LOGE("%{public}s: codecType invalid, queue output buffer failed!", __func__);
            return HDF_FAILURE;
        }
        OutputInfo *dup = DupOutputInfo(outInfo);
        AddOutputInfo(g_codecInstance, dup);
        g_codecInstance->bufferManagerWrapper->PutUsedOutputDataBuffer(g_codecInstance->bufferManagerWrapper, dup);
        return HDF_SUCCESS;
    } else if (g_codecInstance->codecStatus == CODEC_STATUS_STARTED) {
        OutputInfo *info = GetOutputInfo(g_codecInstance, outInfo->buffers->offset);
        CopyOutputInfo(info, outInfo);
        g_codecInstance->bufferManagerWrapper->PutUsedOutputDataBuffer(g_codecInstance->bufferManagerWrapper, info);
        return HDF_SUCCESS;
    } else if (g_codecInstance->codecStatus == CODEC_STATUS_STOPED) {
        OutputInfo *dup = DupOutputInfo(outInfo);
        g_codecInstance->bufferManagerWrapper->PutOutputDataBuffer(g_codecInstance->bufferManagerWrapper, dup);
    }
    return HDF_SUCCESS;
}

int32_t CodecDequeueOutput(CODEC_HANDLETYPE handle, uint32_t timeoutMs, int32_t *acquireFd, OutputInfo *outInfo)
{
    if (g_codecInstance == NULL || g_codecInstance->bufferManagerWrapper == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or buffermanager is NULL!", __func__);
        return HDF_FAILURE;
    }
    
    OutputInfo *info = g_codecInstance->bufferManagerWrapper->GetOutputDataBuffer(
        g_codecInstance->bufferManagerWrapper, QUEUE_TIME_OUT);
    if (info != NULL) {
        *acquireFd = 1;
        CopyOutputInfo(outInfo, info);
    } else {
        return HDF_ERR_TIMEOUT;
    }
    
    return HDF_SUCCESS;
}

int32_t CodecSetCallback(CODEC_HANDLETYPE handle, const CodecCallback *cb, UINTPTR instance)
{
    if (g_codecInstance == NULL || g_codecInstance->codecOemIface == NULL) {
        HDF_LOGE("%{public}s: g_codecInstance or oemIface is NULL!", __func__);
        return HDF_FAILURE;
    }
    g_codecInstance->codecOemIface->CodecSetCallback(handle, cb, instance);
    g_codecInstance->hasCallback = true;
    return HDF_SUCCESS;
}
