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
#include "codec_callback_proxy.h"
#include <hdf_log.h>
#include <hdf_remote_service.h>
#include <osal_mem.h>
#include <servmgr_hdi.h>
#include "proxy_msgproc.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define HDF_LOG_TAG codec_callback_proxy

static int32_t CodecCallbackProxyCall(struct ICodecCallbackProxy *self, int32_t id,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (self->remote == NULL || self->remote->dispatcher == NULL ||
        self->remote->dispatcher->Dispatch == NULL) {
        HDF_LOGE("%{public}s: obj is null", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    return self->remote->dispatcher->Dispatch(self->remote, id, data, reply);
}

static int32_t CodecCallbackProxyReqSBuf(struct HdfSBuf **data, struct HdfSBuf **reply)
{
    *data = HdfSbufTypedObtain(SBUF_IPC);
    if (*data == NULL) {
        HDF_LOGE("%{public}s: Failed to obtain", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (*reply == NULL) {
        HDF_LOGE("%{public}s: Failed to obtain reply", __func__);
        HdfSbufRecycle(*data);
        return HDF_ERR_MALLOC_FAIL;
    }
    return HDF_SUCCESS;
}

static void CodecCallbackProxySBufRecycle(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data != NULL) {
        HdfSbufRecycle(data);
    }
    if (reply != NULL) {
        HdfSbufRecycle(reply);
    }
    return;
}

static int CodecCallbackProxyOnEvent(struct ICodecCallbackProxy *self, UINTPTR userData,
    EventType event, uint32_t length, int32_t eventData[])
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL) {
        HDF_LOGE("%{public}s: self is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecCallbackProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)userData)) {
        HDF_LOGE("%{public}s: write input userData failed!", __func__);
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)event)) {
        HDF_LOGE("%{public}s: write input event failed!", __func__);
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)length)) {
        HDF_LOGE("%{public}s: write input length failed!", __func__);
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < length; i++) {
        if (!HdfSbufWriteInt32(data, eventData[i])) {
            HDF_LOGE("%{public}s: write eventData failed!", __func__);
            CodecCallbackProxySBufRecycle(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }
    ret = CodecCallbackProxyCall(self, CMD_CODEC_ON_EVENT, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecCallbackProxySBufRecycle(data, reply);
        return ret;
    }
    CodecCallbackProxySBufRecycle(data, reply);
    return ret;
}

static int CodecCallbackProxyInputBufferAvailable(struct ICodecCallbackProxy *self, UINTPTR userData,
    CodecBuffer *inBuf, int32_t *acquireFd)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (inBuf == NULL || self == NULL) {
        HDF_LOGE("%{public}s: self or inBuf is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecCallbackProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)userData)) {
        HDF_LOGE("%{public}s: write input userData failed!", __func__);
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyPackCodecBuffer(data, inBuf)) {
        HDF_LOGE("%{public}s: write input buffer failed!", __func__);
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecCallbackProxyCall(self, CMD_CODEC_INPUT_BUFFER_AVAILABLE, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecCallbackProxySBufRecycle(data, reply);
        return ret;
    }
    CodecCallbackProxySBufRecycle(data, reply);
    return ret;
}

static int CodecCallbackProxyOutputBufferAvailable(struct ICodecCallbackProxy *self, UINTPTR userData,
    CodecBuffer *outBuf, int32_t *acquireFd)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (outBuf == NULL || self == NULL) {
        HDF_LOGE("%{public}s: self or outBuf is NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecCallbackProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)userData)) {
        HDF_LOGE("%{public}s: write input userData failed!", __func__);
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyPackCodecBuffer(data, outBuf)) {
        HDF_LOGE("%{public}s: write output buffer failed!", __func__);
        CodecCallbackProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecCallbackProxyCall(self, CMD_CODEC_OUTPUT_BUFFER_AVAILABLE, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecCallbackProxySBufRecycle(data, reply);
        return ret;
    }
    CodecCallbackProxySBufRecycle(data, reply);
    return ret;
}

static void CodecCallbackProxyConstruct(struct ICodecCallbackProxy *callback)
{
    callback->OnEvent = CodecCallbackProxyOnEvent;
    callback->InputBufferAvailable = CodecCallbackProxyInputBufferAvailable;
    callback->OutputBufferAvailable = CodecCallbackProxyOutputBufferAvailable;
}

struct ICodecCallbackProxy *CodecCallbackProxyObtain(struct HdfRemoteService *remote)
{
    if (remote == NULL) {
        HDF_LOGE("%{public}s: remote is null", __func__);
        return NULL;
    }
    
    if (!HdfRemoteServiceSetInterfaceDesc(remote, CODEC_CALLBACK_DESC)) {
        HDF_LOGE("%{public}s: set interface token failed!", __func__);
        return NULL;
    }

    struct ICodecCallbackProxy *callback =
        (struct ICodecCallbackProxy *)OsalMemAlloc(sizeof(struct ICodecCallbackProxy));
    if (callback == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return NULL;
    }
    callback->remote = remote;
    CodecCallbackProxyConstruct(callback);
    return callback;
}

void CodecProxyCallbackRelease(struct ICodecCallbackProxy *callback)
{
    if (callback == NULL) {
        return;
    }
    if (callback->remote != NULL) {
        HdfRemoteServiceRecycle(callback->remote);
    }
    OsalMemFree(callback);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
