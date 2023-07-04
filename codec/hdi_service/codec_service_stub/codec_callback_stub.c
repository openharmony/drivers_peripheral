/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "codec_callback_stub.h"
#include <hdf_log.h>
#include <osal_mem.h>
#include "stub_msgproc.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define HDF_LOG_TAG codec_callback_stub

static int32_t SerCodecOnEvent(struct ICodecCallback *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    uint64_t userData = 0;
    EventType event = 0;
    uint32_t length = 0;
    int32_t *eventData = NULL;

    if (!HdfSbufReadUint64(data, &userData)) {
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
    ret = serviceImpl->callback.OnEvent((UINTPTR)userData, event, length, eventData);
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
    uint64_t userData = 0;
    CodecBuffer *inBuf = NULL;
    int32_t acquireFd;

    if (!HdfSbufReadUint64(data, &userData)) {
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
    ret = serviceImpl->callback.InputBufferAvailable((UINTPTR)userData, inBuf, &acquireFd);
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
    uint64_t userData = 0;
    CodecBuffer *outBuf = NULL;
    int32_t acquireFd;

    if (!HdfSbufReadUint64(data, &userData)) {
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
    ret = serviceImpl->callback.OutputBufferAvailable((UINTPTR)userData, outBuf, &acquireFd);
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
    if (serviceImpl == NULL || serviceImpl->remote == NULL) {
        HDF_LOGE("%{public}s: invalid service object", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (!HdfRemoteServiceCheckInterfaceToken(serviceImpl->remote, data)) {
        HDF_LOGE("%{public}s: interface token check failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
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

struct CodecCallbackStub *CodecCallbackStubObtain(const CodecCallback *callback)
{
    if (callback == NULL) {
        HDF_LOGE("%{public}s: callback is null!", __func__);
        return NULL;
    }
    struct CodecCallbackStub *stub = (struct CodecCallbackStub *)OsalMemAlloc(sizeof(struct CodecCallbackStub));
    if (stub == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc CodecCallbackStub obj failed!", __func__);
        return NULL;
    }
    stub->dispatcher.Dispatch = CodecCallbackServiceOnRemoteRequest;
    stub->service.remote = HdfRemoteServiceObtain((struct HdfObject *)(&stub->service), &(stub->dispatcher));
    if (stub->service.remote == NULL) {
        HDF_LOGE("%{public}s: stub->service.remote is null", __func__);
        OsalMemFree(stub);
        return NULL;
    }
    if (!HdfRemoteServiceSetInterfaceDesc(stub->service.remote, CODEC_CALLBACK_DESC)) {
        HDF_LOGE("%{public}s: set interface token failed!", __func__);
        HdfRemoteServiceRecycle(stub->service.remote);
        OsalMemFree(stub);
        return NULL;
    }

    stub->service.callback = *callback;
    return stub;
}

void CodecCallbackStubRelease(struct CodecCallbackStub *stub)
{
    if (stub == NULL) {
        return;
    }
    HdfRemoteServiceRecycle(stub->service.remote);
    OsalMemFree(stub);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
