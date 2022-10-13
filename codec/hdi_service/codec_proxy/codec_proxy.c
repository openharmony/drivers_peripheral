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
#include <servmgr_hdi.h>
#include "icodec.h"
#include "proxy_msgproc.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define HDF_LOG_TAG codec_hdi_proxy

static int32_t CodecProxyCall(struct ICodec *self,
    int32_t id, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (self->remote == NULL || self->remote->dispatcher == NULL ||
        self->remote->dispatcher->Dispatch == NULL) {
            HDF_LOGE("%{public}s: obj is null", __func__);
            return HDF_ERR_INVALID_OBJECT;
    }
    return self->remote->dispatcher->Dispatch(self->remote, id, data, reply);
}

static int32_t CodecProxyReqSBuf(struct HdfSBuf **data, struct HdfSBuf **reply)
{
    *data = HdfSbufTypedObtain(SBUF_IPC);
    if (*data == NULL) {
        HDF_LOGE("%{public}s: Failed to obtain", __func__);
        return HDF_FAILURE;
    }
    *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (*reply == NULL) {
        HDF_LOGE("%{public}s: Failed to obtain reply", __func__);
        HdfSbufRecycle(*data);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
static void CodecProxySBufRecycle(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data != NULL) {
        HdfSbufRecycle(data);
    }
    if (reply != NULL) {
        HdfSbufRecycle(reply);
    }
    return;
}

static int32_t CodecPorxyInit(struct ICodec *self)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_INIT, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyDeinit(struct ICodec *self)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_DEINIT, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyEnumerateCapability(struct ICodec *self, uint32_t index, CodecCapability *cap)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || cap == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, index)) {
        HDF_LOGE("%{public}s: write input index failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_ENUM_CAP, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    if (CodecProxyParseGottenCapability(reply, cap) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecProxyParseGottenCapability failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyGetCapability(struct ICodec *self, AvCodecMime mime, CodecType type,
    uint32_t flags, CodecCapability *cap)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || cap == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)mime)) {
        HDF_LOGE("%{public}s: write input mime failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)type)) {
        HDF_LOGE("%{public}s: write input type failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, flags)) {
        HDF_LOGE("%{public}s: write input flags failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_GET_CAP, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    if (CodecProxyParseGottenCapability(reply, cap) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CodecProxyParseGottenCapability failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyCreate(struct ICodec *self, const char* name, CODEC_HANDLETYPE *handle)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    uint64_t codecHandle = 0;

    if (self == NULL || name == NULL || handle == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data) || !HdfSbufWriteString(data, name)) {
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = CodecProxyCall(self, CMD_CODEC_CREATE, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call create failed! error code is %{public}d", __func__, ret);
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint64(reply, &codecHandle)) {
        HDF_LOGE("%{public}s: read handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    *handle = (CODEC_HANDLETYPE)codecHandle;
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecCreateByType(struct ICodec *self, CodecType type, AvCodecMime mime, CODEC_HANDLETYPE *handle)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    uint64_t codecHandle = 0;

    if (self == NULL || handle == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)type)) {
        HDF_LOGE("%{public}s: write input type failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)mime)) {
        HDF_LOGE("%{public}s: write input mime failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_CREATE_BY_TYPE, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call CreateByType failed! error code is %{public}d", __func__, ret);
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint64(reply, &codecHandle)) {
        HDF_LOGE("%{public}s: failed to read handle!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    *handle = (CODEC_HANDLETYPE)codecHandle;
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyDestroy(struct ICodec *self, CODEC_HANDLETYPE handle)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;

    if (self == NULL || handle == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: Write handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_DESTROY, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxySetPortMode(struct ICodec *self, CODEC_HANDLETYPE handle,
    DirectionType direct, AllocateBufferMode mode, BufferType type)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)direct)) {
        HDF_LOGE("%{public}s: write DirectionType failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)mode)) {
        HDF_LOGE("%{public}s: write AllocateBufferMode failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)type)) {
        HDF_LOGE("%{public}s: write BufferType failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_SET_MODE, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyGetPortMode(struct ICodec *self, CODEC_HANDLETYPE handle,
    DirectionType direct, AllocateBufferMode *mode, BufferType *type)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)direct)) {
        HDF_LOGE("%{public}s: write DirectionType failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_GET_MODE, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint32(reply, (uint32_t*)mode)) {
        HDF_LOGE("%{public}s: read AllocateBufferMode failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, (uint32_t*)type)) {
        HDF_LOGE("%{public}s: read BufferType failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_FAILURE;
    }
    CodecProxySBufRecycle(data, reply);
    return HDF_SUCCESS;
}

static int32_t CodecProxySetParameter(struct ICodec *self, CODEC_HANDLETYPE handle, const Param *params, int paramCnt)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || params == NULL || paramCnt < 0 || paramCnt > PARAM_COUNT_MAX) {
        HDF_LOGE("%{public}s: param is invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write size failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteInt32(data, paramCnt)) {
        HDF_LOGE("%{public}s: write paramCnt failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (CodecProxyPackParam(data, &params[i]) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: write params failed!", __func__);
            CodecProxySBufRecycle(data, reply);
            return HDF_FAILURE;
        }
    }
    ret = CodecProxyCall(self, CMD_CODEC_SET_PARAMS, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

// params需客户端调用点释放
static int32_t CodecProxyGetParameter(struct ICodec *self, CODEC_HANDLETYPE handle, Param *params, int paramCnt)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || params == NULL || paramCnt < 0 || paramCnt > PARAM_COUNT_MAX) {
        HDF_LOGE("%{public}s: param is invalid!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data) ||
        !HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write interface token or size failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteInt32(data, paramCnt)) {
        HDF_LOGE("%{public}s: write paramCnt failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (CodecProxyPackParam(data, &params[i]) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: CodecProxyPackParam!", __func__);
            CodecProxySBufRecycle(data, reply);
            return HDF_FAILURE;
        }
    }
    ret = CodecProxyCall(self, CMD_CODEC_GET_PARAMS, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    for (int32_t i = 0; i < paramCnt; i++) {
        if (CodecProxyParseParam(reply, &params[i]) != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: read params failed!", __func__);
            CodecProxySBufRecycle(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyStart(struct ICodec *self, CODEC_HANDLETYPE handle)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_START, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyStop(struct ICodec *self, CODEC_HANDLETYPE handle)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write input handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_STOP, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyReset(struct ICodec *self, CODEC_HANDLETYPE handle)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write input handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_RESET, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyFlush(struct ICodec *self, CODEC_HANDLETYPE handle, DirectionType directType)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write input handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)directType)) {
        CodecProxySBufRecycle(data, reply);
        HDF_LOGE("%{public}s: write input directType failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_FLUSH, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecPorxyQueueInput(struct ICodec *self, CODEC_HANDLETYPE handle,
    const CodecBuffer *inputData, uint32_t timeoutMs, int releaseFenceFd)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL || inputData == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write input handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyPackCodecBuffer(data, inputData)) {
        HDF_LOGE("%{public}s: write input buffer failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, timeoutMs)) {
        HDF_LOGE("%{public}s: write input timeoutMs failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyPackFenceFd(data, releaseFenceFd) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: write releaseFenceFd failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_QUEQUE_INPUT, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyDequeueInputParseReply(struct HdfSBuf *reply, int32_t *acquireFd, CodecBuffer *inputData)
{
    if (CodecProxyParseFenceFd(reply, acquireFd) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read acquireFd failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (CodecProxyParseCodecBuffer(reply, inputData)) {
        HDF_LOGE("%{public}s: read input CodecBuffer failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t CodecProxyDequeueInput(struct ICodec *self, CODEC_HANDLETYPE handle,
    uint32_t timeoutMs, int32_t *acquireFd, CodecBuffer *inputData)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL || inputData == NULL || inputData->bufferCnt == 0) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write input handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, timeoutMs)) {
        HDF_LOGE("%{public}s: write input timeoutMs failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, inputData->bufferCnt)) {
        HDF_LOGE("%{public}s: write bufferCnt failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = CodecProxyCall(self, CMD_CODEC_DEQUEQUE_INPUT, data, reply);
    if (ret != HDF_SUCCESS) {
        if (ret != HDF_ERR_TIMEOUT) {
            HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        }
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    ret = CodecProxyDequeueInputParseReply(reply, acquireFd, inputData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read data failed!", __func__);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyQueueOutput(struct ICodec *self, CODEC_HANDLETYPE handle,
    CodecBuffer *outInfo, uint32_t timeoutMs, int releaseFenceFd)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL || outInfo == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyPackCodecBuffer(data, outInfo)) {
        HDF_LOGE("%{public}s: write buffer failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, timeoutMs)) {
        HDF_LOGE("%{public}s: write timeoutMs failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyPackFenceFd(data, releaseFenceFd) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: write releaseFenceFd failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_QUEQUE_OUTPUT, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxyDequeueOutput(struct ICodec *self, CODEC_HANDLETYPE handle,
    uint32_t timeoutMs, int32_t *acquireFd, CodecBuffer *outInfo)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || handle == NULL || acquireFd == NULL || outInfo == NULL || outInfo->bufferCnt == 0) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data) ||
        !HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write interface token or input handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, timeoutMs)) {
        HDF_LOGE("%{public}s: write timeoutMs failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, outInfo->bufferCnt)) {
        HDF_LOGE("%{public}s: read bufferCnt failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_DEQUEQUE_OUTPUT, data, reply);
    if (ret != HDF_SUCCESS) {
        if (ret != HDF_ERR_TIMEOUT) {
            HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        }
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    if (CodecProxyParseFenceFd(reply, acquireFd) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read acquireFd failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyParseCodecBuffer(reply, outInfo)) {
        HDF_LOGE("%{public}s: read output CodecBuffer failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static int32_t CodecProxySetCallback(struct ICodec *self, CODEC_HANDLETYPE handle,
                                     struct ICodecCallback *cb, UINTPTR instance)
{
    int32_t ret;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (self == NULL || cb == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (CodecProxyReqSBuf(&data, &reply) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(self->remote, data)) {
        HDF_LOGE("write interface token failed");
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint64(data, (uint64_t)(uintptr_t)handle)) {
        HDF_LOGE("%{public}s: write input handle failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (HdfSbufWriteRemoteService(data, cb->remote) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: write cb failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, instance)) {
        HDF_LOGE("%{public}s: write input instance failed!", __func__);
        CodecProxySBufRecycle(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    ret = CodecProxyCall(self, CMD_CODEC_SET_CBK, data, reply);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, ret);
        CodecProxySBufRecycle(data, reply);
        return ret;
    }
    CodecProxySBufRecycle(data, reply);
    return ret;
}

static void CodecIpmlConstruct(struct ICodec *instance)
{
    instance->CodecInit = CodecPorxyInit;
    instance->CodecDeinit = CodecProxyDeinit;
    instance->CodecEnumerateCapability = CodecProxyEnumerateCapability;
    instance->CodecGetCapability = CodecProxyGetCapability;
    instance->CodecCreate = CodecProxyCreate;
    instance->CodecCreateByType = CodecCreateByType;
    instance->CodecDestroy = CodecProxyDestroy;
    instance->CodecSetPortMode = CodecProxySetPortMode;
    instance->CodecGetPortMode = CodecProxyGetPortMode;
    instance->CodecSetParameter = CodecProxySetParameter;
    instance->CodecGetParameter = CodecProxyGetParameter;
    instance->CodecStart = CodecProxyStart;
    instance->CodecStop = CodecProxyStop;
    instance->CodecReset = CodecProxyReset;
    instance->CodecFlush = CodecProxyFlush;
    instance->CodecQueueInput = CodecPorxyQueueInput;
    instance->CodecDequeueInput = CodecProxyDequeueInput;
    instance->CodecQueueOutput = CodecProxyQueueOutput;
    instance->CodecDequeueOutput = CodecProxyDequeueOutput;
    instance->CodecSetCallback = CodecProxySetCallback;
    return;
}

struct ICodec *HdiCodecGet(const char *serviceName)
{
    struct HDIServiceManager *serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == NULL) {
        HDF_LOGE("%{public}s: HDIServiceManager not found!", __func__);
        return NULL;
    }

    struct HdfRemoteService *remote = serviceMgr->GetService(serviceMgr, serviceName);
    if (remote == NULL) {
        HDF_LOGE("%{public}s: HdfRemoteService not found!", __func__);
        return NULL;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(remote, "ohos.hdi.codec_service")) {
        HDF_LOGE("%{public}s: failed to init interface desc", __func__);
        HdfRemoteServiceRecycle(remote);
        return NULL;
    }

    struct ICodec *codecClient = (struct ICodec *)OsalMemAlloc(sizeof(struct ICodec));
    if (codecClient == NULL) {
        HDF_LOGE("%{public}s: malloc codec instance failed!", __func__);
        HdfRemoteServiceRecycle(remote);
        return NULL;
    }

    codecClient->remote = remote;
    CodecIpmlConstruct(codecClient);
    return codecClient;
}

void HdiCodecRelease(struct ICodec *instance)
{
    if (instance == NULL) {
        return;
    }
    HdfRemoteServiceRecycle(instance->remote);
    OsalMemFree(instance);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
