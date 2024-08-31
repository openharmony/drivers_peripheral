/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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
#include <hdf_remote_service.h>
#include <osal_mem.h>
#include "codec_callback_if.h"
#include "codec_internal.h"
#include "codec_log_wrapper.h"
#include "codec_types.h"

struct CodecCallbackTypeProxy {
    struct CodecCallbackType instance;
    struct HdfRemoteService *remote;
};

static void ReleaseSbuf(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data != NULL) {
        HdfSbufRecycle(data);
    }
    if (reply != NULL) {
        HdfSbufRecycle(reply);
    }
}

static int32_t CodecCallbackTypeProxyCall(struct CodecCallbackType *self, int32_t id, struct HdfSBuf *data,
                                          struct HdfSBuf *reply)
{
    if (self == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    if (self->remote == NULL || self->remote->dispatcher == NULL || self->remote->dispatcher->Dispatch == NULL) {
        CODEC_LOGE("obj is null");
        return HDF_ERR_INVALID_OBJECT;
    }
    return self->remote->dispatcher->Dispatch(self->remote, id, data, reply);
}

static int32_t WriteArray(struct HdfSBuf *data, int8_t *array, uint32_t arrayLen)
{
    if (!HdfSbufWriteUint32(data, arrayLen)) {
        CODEC_LOGE("write appData failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < arrayLen; i++) {
        if (!HdfSbufWriteInt8(data, array[i])) {
            CODEC_LOGE("write array[i] failed!");
            return HDF_ERR_INVALID_PARAM;
        }
    }
    return HDF_SUCCESS;
}

static int32_t WriteEventInfo(struct HdfSBuf *data, struct EventInfo *info)
{
    if (info == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteInt64(data, info->appData)) {
        CODEC_LOGE("write appData failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, info->data1)) {
        CODEC_LOGE("write data1 failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, info->data2)) {
        CODEC_LOGE("write data2 failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = WriteArray(data, info->eventData, info->eventDataLen);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("write eventData failed!");
    }
    return ret;
}

static int32_t CodecCallbackTypeProxyEventHandler(struct CodecCallbackType *self, enum OMX_EVENTTYPE event,
                                                  struct EventInfo *info)
{
    if (self == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, (uint32_t)event)) {
        CODEC_LOGE("write event failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = WriteEventInfo(data, info);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("write event info failed");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecCallbackTypeProxyCall(self, CMD_EVENT_HANDLER, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecCallbackTypeProxyEmptyBufferDone(struct CodecCallbackType *self, int64_t appData,
                                                     const struct OmxCodecBuffer *buffer)
{
    if (self == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt64(data, appData)) {
        CODEC_LOGE("write appData failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!OmxCodecBufferBlockMarshalling(data, buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecCallbackTypeProxyCall(self, CMD_EMPTY_BUFFER_DONE, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecCallbackTypeProxyFillBufferDone(struct CodecCallbackType *self, int64_t appData,
                                                    const struct OmxCodecBuffer *buffer)
{
    if (self == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt64(data, appData)) {
        CODEC_LOGE("write appData failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!OmxCodecBufferBlockMarshalling(data, buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecCallbackTypeProxyCall(self, CMD_FILL_BUFFER_DONE, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static void CodecCallbackTypeProxyConstruct(struct CodecCallbackType *instance)
{
    if (instance == NULL) {
        CODEC_LOGE("invalid parameter");
        return;
    }
    instance->EventHandler = CodecCallbackTypeProxyEventHandler;
    instance->EmptyBufferDone = CodecCallbackTypeProxyEmptyBufferDone;
    instance->FillBufferDone = CodecCallbackTypeProxyFillBufferDone;
}

struct CodecCallbackType *CodecCallbackTypeGet(struct HdfRemoteService *remote)
{
    if (remote == NULL) {
        CODEC_LOGE("remote is null");
        return NULL;
    }

    struct CodecCallbackType *instance = (struct CodecCallbackType *)OsalMemAlloc(sizeof(struct CodecCallbackType));
    if (instance == NULL) {
        CODEC_LOGE("OsalMemAlloc failed!");
        return NULL;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(remote, "ohos.hdi.codec_service")) {
        OsalMemFree(instance);
        CODEC_LOGE("failed to init interface desc");
        return NULL;
    }

    instance->remote = remote;
    CodecCallbackTypeProxyConstruct(instance);
    return instance;
}

void CodecCallbackTypeRelease(struct CodecCallbackType *instance)
{
    if (instance == NULL) {
        CODEC_LOGE("instance is null");
        return;
    }
    if (instance->remote != NULL) {
        HdfRemoteServiceRecycle(instance->remote);
        instance->remote = NULL;
    }
    OsalMemFree(instance);
}
