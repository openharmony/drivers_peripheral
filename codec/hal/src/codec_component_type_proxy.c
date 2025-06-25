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

#include <hdf_dlist.h>
#include <osal_mem.h>
#include <securec.h>
#include <servmgr_hdi.h>
#include "codec_component_if.h"
#include "codec_internal.h"
#include "codec_log_wrapper.h"
#include "codec_types.h"

struct CodecComponentTypeProxy {
    struct CodecComponentType instance;
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

static int32_t CodecComponentTypeProxyCall(struct CodecComponentType *self, int32_t id, struct HdfSBuf *data,
    struct HdfSBuf *reply)
{
    struct HdfRemoteService *remote = self->AsObject(self);
    if (remote == NULL || remote->dispatcher == NULL || remote->dispatcher->Dispatch == NULL ||
        remote->dispatcher->DispatchAsync == NULL) {
        CODEC_LOGE("Invalid HdfRemoteService obj");
        return HDF_ERR_INVALID_OBJECT;
    }
    return remote->dispatcher->Dispatch(remote, id, data, reply);
}
static int32_t ReadValuesForGetComponentVersion(struct HdfSBuf *reply, struct CompVerInfo *verInfo)
{
    struct CompVerInfo *verInfoCp = (struct CompVerInfo *)HdfSbufReadUnpadBuffer(reply, sizeof(struct CompVerInfo));
    if (verInfoCp == NULL) {
        CODEC_LOGE("read compVerInfo failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = memcpy_s(verInfo, sizeof(struct CompVerInfo), verInfoCp, sizeof(struct CompVerInfo));
    if (ret != EOK) {
        CODEC_LOGE("memcpy_s compVersion failed, error code: %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t CodecComponentTypeProxyGetComponentVersion(struct CodecComponentType *self, struct CompVerInfo *verInfo)
{
    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    int32_t ret = CodecComponentTypeProxyCall(self, CMD_GET_COMPONENT_VERSION, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ret = ReadValuesForGetComponentVersion(reply, verInfo);
    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxySendCommand(struct CodecComponentType *self,
    enum OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, (uint32_t)cmd)) {
        CODEC_LOGE("write cmd failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, param)) {
        CODEC_LOGE("write param failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, cmdDataLen)) {
        CODEC_LOGE("write cmdData failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < cmdDataLen; i++) {
        if (!HdfSbufWriteInt8(data, cmdData[i])) {
            CODEC_LOGE("write cmdData[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = CodecComponentTypeProxyCall(self, CMD_SEND_COMMAND, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyGetParameter(struct CodecComponentType *self,
    uint32_t paramIndex, int8_t *paramStruct, uint32_t paramStructLen)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, paramIndex)) {
        CODEC_LOGE("write paramIndex failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, paramStructLen)) {
        CODEC_LOGE("write paramStructLen failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    for (uint32_t i = 0; i < paramStructLen; i++) {
        if (!HdfSbufWriteInt8(data, paramStruct[i])) {
            CODEC_LOGE("write paramStruct[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = CodecComponentTypeProxyCall(self, CMD_GET_PARAMETER, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    for (uint32_t i = 0; i < paramStructLen; i++) {
        if (!HdfSbufReadInt8(reply, &paramStruct[i])) {
            CODEC_LOGE("read paramStruct[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxySetParameter(struct CodecComponentType *self,
    uint32_t index, int8_t *paramStruct, uint32_t paramStructLen)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, index)) {
        CODEC_LOGE("write index failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, paramStructLen)) {
        CODEC_LOGE("write paramStruct failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < paramStructLen; i++) {
        if (!HdfSbufWriteInt8(data, paramStruct[i])) {
            CODEC_LOGE("write paramStruct[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = CodecComponentTypeProxyCall(self, CMD_SET_PARAMETER, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyGetConfig(struct CodecComponentType *self,
    uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, index)) {
        CODEC_LOGE("write index failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, cfgStructLen)) {
        CODEC_LOGE("write cfgStructLen failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    for (uint32_t i = 0; i < cfgStructLen; i++) {
        if (!HdfSbufWriteInt8(data, cfgStruct[i])) {
            CODEC_LOGE("write cfgStruct[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = CodecComponentTypeProxyCall(self, CMD_GET_CONFIG, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    for (uint32_t i = 0; i < cfgStructLen; i++) {
        if (!HdfSbufReadInt8(reply, &cfgStruct[i])) {
            CODEC_LOGE("read cfgStruct[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxySetConfig(struct CodecComponentType *self,
    uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, index)) {
        CODEC_LOGE("write index failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, cfgStructLen)) {
        CODEC_LOGE("write cfgStruct failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < cfgStructLen; i++) {
        if (!HdfSbufWriteInt8(data, cfgStruct[i])) {
            CODEC_LOGE("write cfgStruct[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = CodecComponentTypeProxyCall(self, CMD_SET_CONFIG, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyGetExtensionIndex(struct CodecComponentType *self,
    const char *paramName, uint32_t *indexType)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(data, paramName)) {
        CODEC_LOGE("write paramName failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_GET_EXTENSION_INDEX, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    if (!HdfSbufReadUint32(reply, indexType)) {
        CODEC_LOGE("read indexType failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyGetState(struct CodecComponentType *self,
    enum OMX_STATETYPE *state)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_GET_STATE, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    if (!HdfSbufReadUint32(reply, (uint32_t*)state)) {
        CODEC_LOGE("read state failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyComponentTunnelRequest(struct CodecComponentType *self,
    uint32_t port, int32_t tunneledComp, uint32_t tunneledPort, struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, port)) {
        CODEC_LOGE("write port failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteInt32(data, tunneledComp)) {
        CODEC_LOGE("write tunneledComp failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, tunneledPort)) {
        CODEC_LOGE("write tunneledPort failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OMX_TUNNELSETUPTYPEBlockMarshalling(data, tunnelSetup)) {
        CODEC_LOGE("write tunnelSetup failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_COMPONENT_TUNNEL_REQUEST, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    if (!OMX_TUNNELSETUPTYPEBlockUnmarshalling(reply, tunnelSetup)) {
        CODEC_LOGE("read tunnelSetup failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyUseBuffer(struct CodecComponentType *self,
    uint32_t portIndex, struct OmxCodecBuffer *buffer)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, portIndex)) {
        CODEC_LOGE("write portIndex failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockMarshalling(data, buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_USE_BUFFER, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    if (!OmxCodecBufferBlockUnmarshalling(reply, buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyAllocateBuffer(struct CodecComponentType *self,
    uint32_t portIndex, struct OmxCodecBuffer *buffer)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, portIndex)) {
        CODEC_LOGE("write portIndex failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockMarshalling(data, buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_ALLOCATE_BUFFER, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    if (!OmxCodecBufferBlockUnmarshalling(reply, buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyFreeBuffer(struct CodecComponentType *self,
    uint32_t portIndex, const struct OmxCodecBuffer *buffer)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, portIndex)) {
        CODEC_LOGE("write portIndex failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockMarshalling(data, buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_FREE_BUFFER, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyEmptyThisBuffer(struct CodecComponentType *self,
    const struct OmxCodecBuffer *buffer)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!OmxCodecBufferBlockMarshalling(data, buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_EMPTY_THIS_BUFFER, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyFillThisBuffer(struct CodecComponentType *self,
    const struct OmxCodecBuffer *buffer)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!OmxCodecBufferBlockMarshalling(data, buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_FILL_THIS_BUFFER, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxySetCallbacks(struct CodecComponentType *self,
    struct CodecCallbackType *callback, int64_t appData)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (HdfSbufWriteRemoteService(data, callback->remote) != 0) {
        CODEC_LOGE("write callback failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteInt64(data, appData)) {
        CODEC_LOGE("write appData failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_SET_CALLBACKS, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyComponentDeInit(struct CodecComponentType *self)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_COMPONENT_DE_INIT, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyUseEglImage(struct CodecComponentType *self,
    struct OmxCodecBuffer *buffer, uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!OmxCodecBufferBlockMarshalling(data, buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, portIndex)) {
        CODEC_LOGE("write portIndex failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, eglImageLen)) {
        CODEC_LOGE("write eglImage failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < eglImageLen; i++) {
        if (!HdfSbufWriteInt8(data, eglImage[i])) {
            CODEC_LOGE("write eglImage[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = CodecComponentTypeProxyCall(self, CMD_USE_EGL_IMAGE, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    if (!OmxCodecBufferBlockUnmarshalling(reply, buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static int32_t CodecComponentTypeProxyComponentRoleEnum(struct CodecComponentType *self,
    uint8_t *role, uint32_t roleLen, uint32_t index)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(self->AsObject(self), data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, roleLen)) {
        CODEC_LOGE("write roleLen failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteUint32(data, index)) {
        CODEC_LOGE("write index failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = CodecComponentTypeProxyCall(self, CMD_COMPONENT_ROLE_ENUM, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    for (uint32_t i = 0; i < roleLen; i++) {
        if (!HdfSbufReadUint8(reply, &role[i])) {
            CODEC_LOGE("read role[i] failed!");
            ReleaseSbuf(data, reply);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ReleaseSbuf(data, reply);
    return ret;
}

static struct HdfRemoteService *CodecComponentTypeProxyAsObject(struct CodecComponentType *self)
{
    if (self == NULL) {
        return NULL;
    }
    struct CodecComponentTypeProxy *proxy = CONTAINER_OF(self, struct CodecComponentTypeProxy, instance);
    return proxy->remote;
}

static void CodecComponentTypeProxyConstruct(struct CodecComponentType *instance)
{
    instance->GetComponentVersion = CodecComponentTypeProxyGetComponentVersion;
    instance->SendCommand = CodecComponentTypeProxySendCommand;
    instance->GetParameter = CodecComponentTypeProxyGetParameter;
    instance->SetParameter = CodecComponentTypeProxySetParameter;
    instance->GetConfig = CodecComponentTypeProxyGetConfig;
    instance->SetConfig = CodecComponentTypeProxySetConfig;
    instance->GetExtensionIndex = CodecComponentTypeProxyGetExtensionIndex;
    instance->GetState = CodecComponentTypeProxyGetState;
    instance->ComponentTunnelRequest = CodecComponentTypeProxyComponentTunnelRequest;
    instance->UseBuffer = CodecComponentTypeProxyUseBuffer;
    instance->AllocateBuffer = CodecComponentTypeProxyAllocateBuffer;
    instance->FreeBuffer = CodecComponentTypeProxyFreeBuffer;
    instance->EmptyThisBuffer = CodecComponentTypeProxyEmptyThisBuffer;
    instance->FillThisBuffer = CodecComponentTypeProxyFillThisBuffer;
    instance->SetCallbacks = CodecComponentTypeProxySetCallbacks;
    instance->ComponentDeInit = CodecComponentTypeProxyComponentDeInit;
    instance->UseEglImage = CodecComponentTypeProxyUseEglImage;
    instance->ComponentRoleEnum = CodecComponentTypeProxyComponentRoleEnum;
    instance->AsObject = CodecComponentTypeProxyAsObject;
}

struct CodecComponentType *CodecComponentTypeGet(struct HdfRemoteService *remote)
{
    if (remote == NULL) {
        CODEC_LOGE("remote is null");
        return NULL;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(remote, CODEC_COMPONENT_INTERFACE_DESC)) {
        CODEC_LOGE("set interface token failed!");
        HdfRemoteServiceRecycle(remote);
        return NULL;
    }
    struct CodecComponentTypeProxy *proxy =
        (struct CodecComponentTypeProxy *)OsalMemAlloc(sizeof(struct CodecComponentTypeProxy));
    if (proxy == NULL) {
        CODEC_LOGE("malloc CodecComponentType proxy failed!");
        HdfRemoteServiceRecycle(remote);
        return NULL;
    }

    proxy->remote = remote;
    CodecComponentTypeProxyConstruct(&proxy->instance);
    return &proxy->instance;
}

void CodecComponentTypeRelease(struct CodecComponentType *instance)
{
    CODEC_LOGE("enter!");
    if (instance == NULL) {
        return;
    }
    struct CodecComponentTypeProxy *proxy = CONTAINER_OF(instance, struct CodecComponentTypeProxy, instance);
    if (proxy->remote) {
        HdfRemoteServiceRecycle(proxy->remote);
        proxy->remote = NULL;
    }
    OsalMemFree(proxy);
}
