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

#include <hdf_log.h>
#include <osal_mem.h>
#include "hdf_remote_service.h"
#include "codec_callback_service.h"
#include "stub_msgproc.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static int32_t SerCodecOnEvent(struct ICodecCallback *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    UINTPTR userData = 0;
    EventType event = 0;
    uint32_t length = 0;
    int32_t *eventData = NULL;

    if (!HdfSbufReadUint32(data, (uint32_t *)&userData)) {
        HDF_LOGE("%{public}s: read comp data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, (uint32_t *)&event)) {
        HDF_LOGE("%{public}s: read event data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &length)) {
        HDF_LOGE("%{public}s: read data1 data failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (length > 0) {
        eventData = (int32_t *)OsalMemCalloc(length);
        if (eventData == NULL) {
            HDF_LOGE("%{public}s: OsalMemAlloc eventData failed!", __func__);
            return HDF_ERR_INVALID_PARAM;
        }
        for (uint32_t i = 0; i < length; i++) {
            if (!HdfSbufReadInt32(data, &eventData[i])) {
                HDF_LOGE("%{public}s: read eventData failed!", __func__);
                OsalMemFree(eventData);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }
    ret = serviceImpl->callback.OnEvent(userData, event, length, eventData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call OnEvent fuc failed!", __func__);
        OsalMemFree(eventData);
        return ret;
    }
    OsalMemFree(eventData);
    return ret;
}

static int32_t SerCodecInputBufferAvailable(struct ICodecCallback *serviceImpl,
                                            struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret = HDF_FAILURE;
    uint32_t bufCnt = 0;
    UINTPTR userData = 0;
    CodecBuffer *inBuf = NULL;
    int32_t acquireFd;

    if (!HdfSbufReadUint32(data, (uint32_t *)&userData)) {
        HDF_LOGE("%{public}s: read userData failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &bufCnt)) {
        HDF_LOGE("%{public}s: read bufferCnt failed!", __func__);
        return HDF_FAILURE;
    }
    if (bufCnt == 0) {
        HDF_LOGE("%{public}s: invalid bufferCnt!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    inBuf = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCnt);
    if (inBuf == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc inBuf failed!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    inBuf->bufferCnt = bufCnt;
    if (CodecSerParseCodecBuffer(data, inBuf)) {
        HDF_LOGE("%{public}s: read inBuf failed!", __func__);
        OsalMemFree(inBuf);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = serviceImpl->callback.InputBufferAvailable(userData, inBuf, &acquireFd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call InputBufferAvailable fuc failed!", __func__);
        OsalMemFree(inBuf);
        return ret;
    }
    OsalMemFree(inBuf);
    return ret;
}

static int32_t SerCodecOutputBufferAvailable(struct ICodecCallback *serviceImpl,
                                             struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret = HDF_FAILURE;
    uint32_t bufCnt = 0;
    UINTPTR userData = 0;
    CodecBuffer *outBuf = NULL;
    int32_t acquireFd;

    if (!HdfSbufReadUint32(data, (uint32_t *)&userData)) {
        HDF_LOGE("%{public}s: read userData failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, (uint32_t *)&bufCnt)) {
        HDF_LOGE("%{public}s: read bufferCnt failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (bufCnt == 0) {
        HDF_LOGE("%{public}s: invalid bufferCnt!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    outBuf = (CodecBuffer *)OsalMemAlloc(sizeof(CodecBuffer) + sizeof(CodecBufferInfo) * bufCnt);
    if (outBuf == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc outBuf failed!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    outBuf->bufferCnt = bufCnt;
    if (CodecSerParseCodecBuffer(data, outBuf)) {
        HDF_LOGE("%{public}s: read outBuf failed!", __func__);
        OsalMemFree(outBuf);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = serviceImpl->callback.OutputBufferAvailable(userData, outBuf, &acquireFd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call OutputBufferAvailable fuc failed!", __func__);
        OsalMemFree(outBuf);
        return ret;
    }
    OsalMemFree(outBuf);
    return ret;
}

static int32_t CodecCallbackServiceOnRemoteRequest(struct HdfRemoteService *service, int cmdId,
                                                   struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct ICodecCallback *serviceImpl = (struct ICodecCallback *)service;
    switch (cmdId) {
        case CMD_CODEC_ON_EVENT:
            return SerCodecOnEvent(serviceImpl, data, reply);
        case CMD_CODEC_INPUT_BUFFER_AVAILABLE:
            return SerCodecInputBufferAvailable(serviceImpl, data, reply);
        case CMD_CODEC_OUTPUT_BUFFER_AVAILABLE:
            return SerCodecOutputBufferAvailable(serviceImpl, data, reply);
        default: {
            HDF_LOGE("%{public}s: not support cmd %{public}d", __func__, cmdId);
            return HDF_ERR_INVALID_PARAM;
        }
    }
}

struct CodecCallbackStub {
    struct ICodecCallback service;
    struct HdfRemoteDispatcher dispatcher;
};

struct ICodecCallback *CodecCallbackStubObtain(void)
{
    struct CodecCallbackStub *stub = (struct CodecCallbackStub *)OsalMemAlloc(sizeof(struct CodecCallbackStub));
    if (stub == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc CodecCallbackStub obj failed!", __func__);
        return NULL;
    }
    stub->dispatcher.Dispatch = CodecCallbackServiceOnRemoteRequest;
    stub->service.remote = HdfRemoteServiceObtain((struct HdfObject *)stub, &(stub->dispatcher));
    if (stub->service.remote == NULL) {
        HDF_LOGE("%{public}s: stub->service.remote is null", __func__);
        return NULL;
    }
    CodecCallbackServiceConstruct(&stub->service);
    return &stub->service;
}

void CodecCallbackStubRelease(struct ICodecCallback *stub)
{
    if (stub == NULL) {
        return;
    }
    OsalMemFree(stub);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */