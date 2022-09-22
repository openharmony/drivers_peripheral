/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "codec_stub.h"
#include <hdf_device_object.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include "codec_callback_proxy.h"
#include "codec_config_parser.h"
#include "codec_interface.h"
#include "codec_service.h"
#include "icodec.h"
#include "stub_msgproc.h"

#define HDF_LOG_TAG codec_hdi_stub
#define HDF_CODEC_NAME_LEN 50

static int32_t SerCodecInit(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum = CodecInit();
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecInit fuc failed!", __func__);
        return errNum;
    }
    if (!HdfSbufWriteUint32(reply, errNum)) {
        HDF_LOGE("%{public}s: write errNum failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return errNum;
}

static int32_t SerCodecDeinit(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum = CodecDeinit();
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecDeinit fuc failed!", __func__);
        return errNum;
    }
    if (!HdfSbufWriteUint32(reply, errNum)) {
        HDF_LOGE("%{public}s: write errNum failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return errNum;
}

static int32_t SerCodecEnumerateCapability(struct HdfDeviceIoClient *client, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    uint32_t index;
    CodecCapability capability;

    if (!HdfSbufReadUint32(data, &index)) {
        HDF_LOGE("%{public}s: read index failed!", __func__);
        return HDF_FAILURE;
    }
    if (!CodecCapablitesInited()) {
        HDF_LOGE("%{public}s: codec capabilities not inited!", __func__);
        return HDF_FAILURE;
    }
    if (CodecEnumerateCapability(index, &capability) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: EnumrateCapablity - no more capability to Enumrate!", __func__);
        return HDF_FAILURE;
    }
    if (capability.mime == MEDIA_MIMETYPE_INVALID) {
        HDF_LOGE("%{public}s: Capability invalid, discard!", __func__);
        return HDF_FAILURE;
    }
    if (CodecSerPackCapability(reply, &capability) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: write capability to sbuf failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SerCodecGetCapability(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t flags;
    AvCodecMime mime;
    CodecType type;
    CodecCapability capability;

    if (!HdfSbufReadUint32(data, (uint32_t*)&mime)) {
        HDF_LOGE("%{public}s: read input mime failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, (uint32_t*)&type)) {
        HDF_LOGE("%{public}s: read input type failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &flags)) {
        HDF_LOGE("%{public}s: read input flags failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecGetCapability(mime, type, flags, &capability) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetCapability - got nothing!", __func__);
        return HDF_FAILURE;
    }
    if (CodecSerPackCapability(reply, &capability) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: write capability to sbuf failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SerCodecCreate(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum;
    uint64_t handle = 0;
    const char *name = NULL;

    name = HdfSbufReadString(data);
    if (name == NULL) {
        HDF_LOGE("%{public}s: Read name failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    errNum = CodecCreate(name, (CODEC_HANDLETYPE *)&handle);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecCreate fuc failed! errNum:%{public}d", __func__, errNum);
        return errNum;
    }
    if (!HdfSbufWriteUint64(reply, handle)) {
        HDF_LOGE("%{public}s: write handle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return errNum;
}

static int32_t SerCodecCreateByType(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    int32_t errNum;
    CodecType type;
    AvCodecMime mime;
    uint64_t handle = 0;

    if (!HdfSbufReadUint32(data, (uint32_t*)&type)) {
        HDF_LOGE("%{public}s: read input type failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, (uint32_t*)&mime)) {
        HDF_LOGE("%{public}s: read input mime failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    errNum = CodecCreateByType(type, mime, (CODEC_HANDLETYPE *)&handle);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecCreateByType fuc failed! errNum:%{public}d", __func__, errNum);
        return errNum;
    }
    if (!HdfSbufWriteUint64(reply, handle)) {
        HDF_LOGE("%{public}s: write handle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return errNum;
}

static int32_t SerCodecDestroy(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum;
    uint64_t handle = 0;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: Read size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    errNum = CodecDestroy((CODEC_HANDLETYPE)(uintptr_t)handle);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecDestroy fuc failed!", __func__);
        return errNum;
    }
    return errNum;
}

static int32_t SerCodecSetPortMode(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum;
    uint64_t handle = 0;
    DirectionType direct;
    AllocateBufferMode mode;
    BufferType type;

    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: Read handle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, (uint32_t*)&direct)) {
        HDF_LOGE("%{public}s: Read DirectionType failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, (uint32_t*)&mode)) {
        HDF_LOGE("%{public}s: Read AllocateBufferMode failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, (uint32_t*)&type)) {
        HDF_LOGE("%{public}s: Read BufferType failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    errNum = CodecSetPortMode((CODEC_HANDLETYPE)(uintptr_t)handle, direct, mode, type);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecSetPortMode fuc failed!", __func__);
        return errNum;
    }
    return errNum;
}

static int32_t SerCodecGetPortMode(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum;
    uint64_t handle = 0;
    DirectionType direct;
    AllocateBufferMode mode;
    BufferType type;

    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: Read handle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, (uint32_t*)&direct)) {
        HDF_LOGE("%{public}s: Read DirectionType failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    errNum = CodecGetPortMode((CODEC_HANDLETYPE)(uintptr_t)handle, direct, &mode, &type);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecSetPortMode fuc failed!", __func__);
        return errNum;
    }
    if (!HdfSbufWriteUint32(reply, (uint32_t)mode)) {
        HDF_LOGE("%{public}s: write AllocateBufferMode failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(reply, (uint32_t)type)) {
        HDF_LOGE("%{public}s: write BufferType failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

static void FreeParams(Param *params, int32_t paramCnt)
{
    if (params == NULL || paramCnt <= 0) {
        HDF_LOGE("%{public}s: params is null or invalid count!", __func__);
        return;
    }
    for (int32_t j = 0; j < paramCnt; j++) {
        if (params[j].val != NULL && params[j].size > 0) {
            OsalMemFree(params[j].val);
            params[j].val = NULL;
        }
    }
    OsalMemFree(params);
}

static int32_t SerCodecSetParameter(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum;
    int32_t paramCnt = 0;
    uint64_t handle = 0;
    Param *params = NULL;

    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: Read handle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadInt32(data, &paramCnt)) {
        HDF_LOGE("%{public}s: Read paramCnt failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (paramCnt <= 0) {
        HDF_LOGE("%{public}s: Param paramCnt err!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    if (params == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (CodecSerParseParam(data, &params[i]) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Read params failed!", __func__);
            FreeParams(params, paramCnt);
            return HDF_FAILURE;
        }
    }
    errNum = CodecSetParameter((CODEC_HANDLETYPE)(uintptr_t)handle, params, paramCnt);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecSetParameter fuc failed!", __func__);
    }

    FreeParams(params, paramCnt);
    return errNum;
}

static int32_t SerCodecGetParameter(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum;
    int32_t paramCnt = 0;
    uint64_t handle = 0;
    Param *params = NULL;

    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: Read handle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadInt32(data, &paramCnt)) {
        HDF_LOGE("%{public}s: Read paramCnt failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (paramCnt <= 0) {
        HDF_LOGE("%{public}s: Param paramCnt err!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    params = (Param *)OsalMemAlloc(sizeof(Param)*paramCnt);
    if (params == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (CodecSerParseParam(data, &params[i]) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Read params failed!", __func__);
            FreeParams(params, paramCnt);
            return HDF_FAILURE;
        }
    }
    errNum = CodecGetParameter((CODEC_HANDLETYPE)(uintptr_t)handle, params, paramCnt);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecGetParameter fuc failed!", __func__);
        FreeParams(params, paramCnt);
        return errNum;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (CodecSerPackParam(reply, &params[i]) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: CodecSerPackParam err!", __func__);
            FreeParams(params, paramCnt);
            return HDF_FAILURE;
        }
    }

    FreeParams(params, paramCnt);
    return errNum;
}

static int32_t SerCodecStart(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t errNum;
    uint64_t handle = 0;

    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: Read handle failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    errNum = CodecStart((CODEC_HANDLETYPE)(uintptr_t)handle);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call SerCodecStart fuc failed!", __func__);
        return errNum;
    }
    return errNum;
}

static int32_t SerCodecStop(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint64_t handle = 0;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: read handle data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t errNum = CodecStop((CODEC_HANDLETYPE)(uintptr_t)handle);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecStop fuc failed!", __func__);
        return errNum;
    }
    return errNum;
}

static int32_t SerCodecReset(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)reply;
    uint64_t handle = 0;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: read handle data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t errNum = CodecReset((CODEC_HANDLETYPE)(uintptr_t)handle);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecStop fuc failed!", __func__);
        return errNum;
    }
    return errNum;
}

static int32_t SerCodecFlush(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint64_t handle = 0;
    uint32_t directType = 0;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: read handle data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &directType)) {
        HDF_LOGE("%{public}s: read directType data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t errNum = CodecFlush((CODEC_HANDLETYPE)(uintptr_t)handle, (DirectionType)directType);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecFlush fuc failed!", __func__);
        return errNum;
    }
    return errNum;
}

static int32_t SerCodecQueueInput(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t timeoutMs = 0;
    int releaseFenceFd = -1;
    uint64_t handle = 0;
    uint32_t bufCnt = 0;
    CodecBuffer *inputData = NULL;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: read handle data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &bufCnt)) {
        HDF_LOGE("%{public}s: read bufferCnt failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (bufCnt == 0) {
        HDF_LOGE("%{public}s: Param bufCnt err!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    inputData = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCnt);
    if (inputData == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    inputData->bufferCnt = bufCnt;
    if (CodecSerParseCodecBuffer(data, inputData)) {
        HDF_LOGE("%{public}s: read inputData failed!", __func__);
        OsalMemFree(inputData);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &timeoutMs)) {
        HDF_LOGE("%{public}s: read timeoutMs data failed!", __func__);
        OsalMemFree(inputData);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecSerParseFenceFd(data, &releaseFenceFd) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read releaseFenceFd failed!", __func__);
        OsalMemFree(inputData);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t errNum = CodecQueueInput((CODEC_HANDLETYPE)(uintptr_t)handle, inputData, timeoutMs, releaseFenceFd);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecQueueInput fuc failed!", __func__);
        OsalMemFree(inputData);
        return errNum;
    }

    OsalMemFree(inputData);
    return HDF_SUCCESS;
}

static int32_t SerCodecDequeueInput(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t timeoutMs = 0;
    uint64_t handle = 0;
    uint32_t bufCnt = 0;
    int32_t acquireFd = 0;
    CodecBuffer *inputData = NULL;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: read handle data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &timeoutMs)) {
        HDF_LOGE("%{public}s: read timeoutMs data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &bufCnt)) {
        HDF_LOGE("%{public}s: read bufferCnt failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (bufCnt == 0) {
        HDF_LOGE("%{public}s: Param bufCnt err!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    inputData = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCnt);
    if (inputData == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    inputData->bufferCnt = bufCnt;
    int32_t errNum = CodecDequeueInput((CODEC_HANDLETYPE)(uintptr_t)handle, timeoutMs, &acquireFd, inputData);
    if (errNum != HDF_SUCCESS) {
        if (errNum != HDF_ERR_TIMEOUT) {
            HDF_LOGE("%{public}s: call CodecDequeInput fuc failed!", __func__);
        }
        OsalMemFree(inputData);
        return errNum;
    }
    if (CodecSerPackFenceFd(reply, acquireFd) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: write acquireFd failed!", __func__);
        OsalMemFree(inputData);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecSerPackCodecBuffer(reply, inputData)) {
        HDF_LOGE("%{public}s: struct inputData write failed!", __func__);
        OsalMemFree(inputData);
        return HDF_ERR_INVALID_PARAM;
    }
    OsalMemFree(inputData);
    return HDF_SUCCESS;
}

static int32_t SerCodecQueueOutput(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t timeoutMs = 0;
    int releaseFenceFd = -1;
    uint64_t handle = 0;
    uint32_t bufCnt = 0;
    CodecBuffer *outInfo = NULL;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: read handle data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &bufCnt)) {
        HDF_LOGE("%{public}s: read bufferCnt failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (bufCnt == 0) {
        HDF_LOGE("%{public}s: Param bufCnt err!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    outInfo = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCnt);
    if (outInfo == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    outInfo->bufferCnt = bufCnt;
    if (CodecSerParseCodecBuffer(data, outInfo)) {
        HDF_LOGE("%{public}s: read struct data failed!", __func__);
        OsalMemFree(outInfo);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &timeoutMs)) {
        HDF_LOGE("%{public}s: read timeoutMs data failed!", __func__);
        OsalMemFree(outInfo);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecSerParseFenceFd(data, &releaseFenceFd) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read releaseFenceFd failed!", __func__);
        OsalMemFree(outInfo);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t errNum = CodecQueueOutput((CODEC_HANDLETYPE)(uintptr_t)handle, outInfo, timeoutMs, releaseFenceFd);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecQueueOutput fuc failed!", __func__);
        OsalMemFree(outInfo);
        return errNum;
    }

    OsalMemFree(outInfo);
    return HDF_SUCCESS;
}

static int32_t SerCodecDequeueOutput(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t timeoutMs = 0;
    int32_t acquireFd = 0;
    uint64_t handle = 0;
    uint32_t bufCnt = 0;
    CodecBuffer *outInfo = NULL;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: read handle data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &timeoutMs)) {
        HDF_LOGE("%{public}s: read timeoutMs data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &bufCnt)) {
        HDF_LOGE("%{public}s: read bufferCnt failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (bufCnt == 0) {
        HDF_LOGE("%{public}s: Param bufCnt err!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    outInfo = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCnt);
    if (outInfo == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    outInfo->bufferCnt = bufCnt;

    int32_t errNum = CodecDequeueOutput((CODEC_HANDLETYPE)(uintptr_t)handle, timeoutMs, &acquireFd, outInfo);
    if (errNum != HDF_SUCCESS) {
        if (errNum != HDF_ERR_TIMEOUT) {
            HDF_LOGE("%{public}s: call CodecDequeueOutput fuc failed!", __func__);
        }
        OsalMemFree(outInfo);
        return errNum;
    }
    if (CodecSerPackFenceFd(reply, acquireFd) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: write acquireFd failed!", __func__);
        OsalMemFree(outInfo);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecSerPackCodecBuffer(reply, outInfo)) {
        HDF_LOGE("%{public}s: write outInfo buffer failed!", __func__);
        OsalMemFree(outInfo);
        return HDF_ERR_INVALID_PARAM;
    }
    OsalMemFree(outInfo);
    return HDF_SUCCESS;
}

static int32_t SerCodecSetCallback(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint64_t handle = 0;
    UINTPTR instance;
    struct ICodecCallback *cb = NULL;
    if (!HdfSbufReadUint64(data, &handle)) {
        HDF_LOGE("%{public}s: read handle data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct HdfRemoteService *cbRemote = HdfSbufReadRemoteService(data);
    if (cbRemote == NULL) {
        HDF_LOGE("%{public}s: read cbRemote failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    cb = CodecProxyCallbackObtain(cbRemote);
    if (!HdfSbufReadUint32(data, (uint32_t *)&instance)) {
        HDF_LOGE("%{public}s: read instance data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t errNum = CodecSetCallback((CODEC_HANDLETYPE)(uintptr_t)handle, &cb->callback, instance);
    if (errNum != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CodecSetCallback fuc failed!", __func__);
        return errNum;
    }
    return errNum;
}

static int32_t HandleRequestCmdExt(struct HdfDeviceIoClient *client, int cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    switch (cmdId) {
        case CMD_CODEC_QUEQUE_INPUT:
            return SerCodecQueueInput(client, data, reply);
        case CMD_CODEC_DEQUEQUE_INPUT:
            return SerCodecDequeueInput(client, data, reply);
        case CMD_CODEC_QUEQUE_OUTPUT:
            return SerCodecQueueOutput(client, data, reply);
        case CMD_CODEC_DEQUEQUE_OUTPUT:
            return SerCodecDequeueOutput(client, data, reply);
        case CMD_CODEC_SET_CBK:
            return SerCodecSetCallback(client, data, reply);
        default: {
            HDF_LOGE("%{public}s: not support cmd %{public}d", __func__, cmdId);
            return HDF_ERR_INVALID_PARAM;
        }
    }
}

static int32_t HandleRequestCmd(struct HdfDeviceIoClient *client, int cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    switch (cmdId) {
        case CMD_CODEC_INIT:
            return SerCodecInit(client, data, reply);
        case CMD_CODEC_DEINIT:
            return SerCodecDeinit(client, data, reply);
        case CMD_CODEC_ENUM_CAP:
            return SerCodecEnumerateCapability(client, data, reply);
        case CMD_CODEC_GET_CAP:
            return SerCodecGetCapability(client, data, reply);
        case CMD_CODEC_CREATE:
            return SerCodecCreate(client, data, reply);
        case CMD_CODEC_CREATE_BY_TYPE:
            return SerCodecCreateByType(client, data, reply);
        case CMD_CODEC_DESTROY:
            return SerCodecDestroy(client, data, reply);
        case CMD_CODEC_SET_MODE:
            return SerCodecSetPortMode(client, data, reply);
        case CMD_CODEC_GET_MODE:
            return SerCodecGetPortMode(client, data, reply);
        case CMD_CODEC_SET_PARAMS:
            return SerCodecSetParameter(client, data, reply);
        case CMD_CODEC_GET_PARAMS:
            return SerCodecGetParameter(client, data, reply);
        case CMD_CODEC_START:
            return SerCodecStart(client, data, reply);
        case CMD_CODEC_STOP:
            return SerCodecStop(client, data, reply);
        case CMD_CODEC_RESET:
            return SerCodecReset(client, data, reply);
        case CMD_CODEC_FLUSH:
            return SerCodecFlush(client, data, reply);
        default: {
            return HandleRequestCmdExt(client, cmdId, data, reply);
        }
    }
}

int32_t CodecServiceOnRemoteRequest(struct HdfDeviceIoClient *client, int cmdId,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (!HdfDeviceObjectCheckInterfaceDesc(client->device, data)) {
        HDF_LOGE("check interface token failed");
        return HDF_ERR_INVALID_PARAM;
    }
    if ((cmdId == CMD_CODEC_ENUM_CAP) || (cmdId == CMD_CODEC_GET_CAP)) {
        if (!CodecCapablitesInited()) {
            ReloadCapabilities();
        }
    }
    return HandleRequestCmd(client, cmdId, data, reply);
}
