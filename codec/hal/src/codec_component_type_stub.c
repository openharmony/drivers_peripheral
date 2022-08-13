/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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

#include "codec_component_type_stub.h"
#include <dlfcn.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>
#include "codec_callback_if.h"
#include "codec_component_capability_config.h"

#define HDF_LOG_TAG codec_hdi_server

#ifdef __ARM64__
#define DRIVER_PATH "/vendor/lib64"
#else
#define DRIVER_PATH "/vendor/lib"
#endif
static void FreeMem(int8_t *mem, uint32_t memLen)
{
    if (memLen > 0 && mem != NULL) {
        OsalMemFree(mem);
    }
}

static int32_t SerStubGetComponentVersion(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                          struct HdfSBuf *reply)
{
    int32_t ret;
    struct CompVerInfo verInfo;
    (void)memset_s(&verInfo, sizeof(verInfo), 0, sizeof(verInfo));
    ret = serviceImpl->GetComponentVersion(serviceImpl, &verInfo);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call GetComponentVersion function failed!", __func__);
        return ret;
    }
    if (!HdfSbufWriteUnpadBuffer(reply, (const uint8_t *)&verInfo, sizeof(struct CompVerInfo))) {
        HDF_LOGE("%{public}s: write verInfo failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t SerStubSendCommand(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    enum OMX_COMMANDTYPE cmd;
    uint32_t param = 0;
    int8_t *cmdData = NULL;
    uint32_t cmdDataLen = 0;

    if (!HdfSbufReadUint32(data, (uint32_t*)&cmd)) {
        HDF_LOGE("%{public}s: read &cmd failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &param)) {
        HDF_LOGE("%{public}s: read &param failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &cmdDataLen)) {
        HDF_LOGE("%{public}s: read cmdData size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (cmdDataLen > 0) {
        cmdData = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (cmdDataLen));
        if (cmdData == NULL) {
            HDF_LOGE("%{public}s: HDF_ERR_MALLOC_FAIL!", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }

        for (uint32_t i = 0; i < cmdDataLen; i++) {
            if (!HdfSbufReadInt8(data, &cmdData[i])) {
                HDF_LOGE("%{public}s: read &cmdData[i] failed!", __func__);
                FreeMem(cmdData, cmdDataLen);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }

    ret = serviceImpl->SendCommand(serviceImpl, cmd, param, cmdData, cmdDataLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call SendCommand function failed!", __func__);
        FreeMem(cmdData, cmdDataLen);
        return ret;
    }

    FreeMem(cmdData, cmdDataLen);
    return HDF_SUCCESS;
}

static int32_t SerStubGetParameter(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    uint32_t paramIndex = 0;
    int8_t *paramStruct = NULL;
    uint32_t paramStructLen = 0;

    if (!HdfSbufReadUint32(data, &paramIndex)) {
        HDF_LOGE("%{public}s: read paramIndex failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &paramStructLen)) {
        HDF_LOGE("%{public}s: read paramStructLen failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    paramStruct = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (paramStructLen));
    if (paramStruct == NULL) {
        HDF_LOGE("%{public}s: HDF_ERR_MALLOC_FAIL!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < paramStructLen; i++) {
        if (!HdfSbufReadInt8(data, &paramStruct[i])) {
            HDF_LOGE("%{public}s: read paramStruct[%{public}d] failed!", __func__, i);
            FreeMem(paramStruct, paramStructLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = serviceImpl->GetParameter(serviceImpl, paramIndex, paramStruct, paramStructLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call GetParameter function failed!", __func__);
        FreeMem(paramStruct, paramStructLen);
        return ret;
    }

    for (uint32_t i = 0; i < paramStructLen; i++) {
        if (!HdfSbufWriteInt8(reply, paramStruct[i])) {
            HDF_LOGE("%{public}s: write paramStruct[i] failed!", __func__);
            FreeMem(paramStruct, paramStructLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    FreeMem(paramStruct, paramStructLen);
    return HDF_SUCCESS;
}

static int32_t SerStubSetParameter(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    uint32_t index = 0;
    int8_t *paramStruct = NULL;
    uint32_t paramStructLen = 0;

    if (!HdfSbufReadUint32(data, &index)) {
        HDF_LOGE("%{public}s: read &index failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &paramStructLen)) {
        HDF_LOGE("%{public}s: read paramStruct size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (paramStructLen > 0) {
        paramStruct = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (paramStructLen));
        if (paramStruct == NULL) {
            HDF_LOGE("%{public}s: HDF_ERR_MALLOC_FAIL!", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }

        for (uint32_t i = 0; i < paramStructLen; i++) {
            if (!HdfSbufReadInt8(data, &paramStruct[i])) {
                HDF_LOGE("%{public}s: read &paramStruct[i] failed!", __func__);
                FreeMem(paramStruct, paramStructLen);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }

    ret = serviceImpl->SetParameter(serviceImpl, index, paramStruct, paramStructLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call SetParameter function failed!", __func__);
        FreeMem(paramStruct, paramStructLen);
        return ret;
    }

    FreeMem(paramStruct, paramStructLen);
    return HDF_SUCCESS;
}

static int32_t SerStubGetConfig(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    uint32_t index = 0;
    int8_t *cfgStruct = NULL;
    uint32_t cfgStructLen = 0;

    if (!HdfSbufReadUint32(data, &index)) {
        HDF_LOGE("%{public}s: read &index failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &cfgStructLen)) {
        HDF_LOGE("%{public}s: read cfgStructLen failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    cfgStruct = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (cfgStructLen));
    if (cfgStruct == NULL) {
        HDF_LOGE("%{public}s: HDF_ERR_MALLOC_FAIL!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < cfgStructLen; i++) {
        if (!HdfSbufReadInt8(data, &cfgStruct[i])) {
            HDF_LOGE("%{public}s: read cfgStruct[i] failed!", __func__);
            FreeMem(cfgStruct, cfgStructLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = serviceImpl->GetConfig(serviceImpl, index, cfgStruct, cfgStructLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call GetConfig function failed!", __func__);
        FreeMem(cfgStruct, cfgStructLen);
        return ret;
    }

    for (uint32_t i = 0; i < cfgStructLen; i++) {
        if (!HdfSbufWriteInt8(reply, cfgStruct[i])) {
            HDF_LOGE("%{public}s: write cfgStruct[i] failed!", __func__);
            FreeMem(cfgStruct, cfgStructLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    FreeMem(cfgStruct, cfgStructLen);
    return ret;
}

static int32_t SerStubSetConfig(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    uint32_t index = 0;
    int8_t *cfgStruct = NULL;
    uint32_t cfgStructLen = 0;

    if (!HdfSbufReadUint32(data, &index)) {
        HDF_LOGE("%{public}s: read &index failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &cfgStructLen)) {
        HDF_LOGE("%{public}s: read cfgStruct size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (cfgStructLen > 0) {
        cfgStruct = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (cfgStructLen));
        if (cfgStruct == NULL) {
            HDF_LOGE("%{public}s: HDF_ERR_MALLOC_FAIL!", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }

        for (uint32_t i = 0; i < cfgStructLen; i++) {
            if (!HdfSbufReadInt8(data, &cfgStruct[i])) {
                HDF_LOGE("%{public}s: read &cfgStruct[i] failed!", __func__);
                FreeMem(cfgStruct, cfgStructLen);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }

    ret = serviceImpl->SetConfig(serviceImpl, index, cfgStruct, cfgStructLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call SetConfig function failed!", __func__);
        FreeMem(cfgStruct, cfgStructLen);
        return ret;
    }

    FreeMem(cfgStruct, cfgStructLen);
    return ret;
}

static int32_t SerStubGetExtensionIndex(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                        struct HdfSBuf *reply)
{
    int32_t ret;
    char *paramName = NULL;
    uint32_t indexType = 0;

    const char *paramNameCp = HdfSbufReadString(data);
    if (paramNameCp == NULL) {
        HDF_LOGE("%{public}s: read paramNameCp failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    paramName = strdup(paramNameCp);

    ret = serviceImpl->GetExtensionIndex(serviceImpl, paramName, &indexType);
    if (paramName != NULL) {
        OsalMemFree(paramName);
        paramName = NULL;
    }
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call GetExtensionIndex function failed!", __func__);
        return ret;
    }

    if (!HdfSbufWriteUint32(reply, indexType)) {
        HDF_LOGE("%{public}s: write indexType failed!", __func__);
        ret = HDF_ERR_INVALID_PARAM;
    }

    return ret;
}

static int32_t SerStubGetState(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    enum OMX_STATETYPE state;

    ret = serviceImpl->GetState(serviceImpl, &state);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call GetState function failed!", __func__);
        return ret;
    }

    if (!HdfSbufWriteUint32(reply, (uint32_t)state)) {
        HDF_LOGE("%{public}s: write state failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return ret;
}

static int32_t SerStubComponentTunnelRequest(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                             struct HdfSBuf *reply)
{
    int32_t ret;
    uint32_t port = 0;
    int32_t tunneledComp = 0;
    uint32_t tunneledPort = 0;
    struct OMX_TUNNELSETUPTYPE tunnelSetup;

    if (!HdfSbufReadUint32(data, &port)) {
        HDF_LOGE("%{public}s: read &port failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadInt32(data, &tunneledComp)) {
        HDF_LOGE("%{public}s: read &tunneledComp failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &tunneledPort)) {
        HDF_LOGE("%{public}s: read &tunneledPort failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OMX_TUNNELSETUPTYPEBlockUnmarshalling(data, &tunnelSetup)) {
        HDF_LOGE("%{public}s: read tunnelSetup failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->ComponentTunnelRequest(serviceImpl, port, tunneledComp, tunneledPort, &tunnelSetup);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call ComponentTunnelRequest function failed!", __func__);
        return ret;
    }

    if (!OMX_TUNNELSETUPTYPEBlockMarshalling(reply, &tunnelSetup)) {
        HDF_LOGE("%{public}s: write tunnelSetup failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return ret;
}

static int32_t SerStubUseBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    struct OmxCodecBuffer buffer;
    uint32_t portIndex = 0;
    InitOmxCodecBuffer(&buffer);

    if (!HdfSbufReadUint32(data, &portIndex)) {
        HDF_LOGE("%{public}s: read &portIndex failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        HDF_LOGE("%{public}s: read buffer failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->UseBuffer(serviceImpl, portIndex, &buffer);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call UseBuffer function failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }

    if (!OmxCodecBufferBlockMarshalling(reply, &buffer)) {
        HDF_LOGE("%{public}s: write buffer failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }
    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t SerStubAllocateBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                     struct HdfSBuf *reply)
{
    int32_t ret;
    struct OmxCodecBuffer buffer;
    uint32_t portIndex = 0;
    InitOmxCodecBuffer(&buffer);

    if (!HdfSbufReadUint32(data, &portIndex)) {
        HDF_LOGE("%{public}s: read &portIndex failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        HDF_LOGE("%{public}s: read buffer failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->AllocateBuffer(serviceImpl, portIndex, &buffer);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call AllocateBuffer function failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }

    if (!OmxCodecBufferBlockMarshalling(reply, &buffer)) {
        HDF_LOGE("%{public}s: write buffer failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }
    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t SerStubFreeBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    uint32_t portIndex = 0;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);
    if (!HdfSbufReadUint32(data, &portIndex)) {
        HDF_LOGE("%{public}s: read &portIndex failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        HDF_LOGE("%{public}s: read buffer failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->FreeBuffer(serviceImpl, portIndex, &buffer);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call FreeBuffer function failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }
    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t SerStubEmptyThisBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                      struct HdfSBuf *reply)
{
    int32_t ret;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);
    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        HDF_LOGE("%{public}s: read buffer failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->EmptyThisBuffer(serviceImpl, &buffer);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call EmptyThisBuffer function failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }
    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t SerStubFillThisBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                     struct HdfSBuf *reply)
{
    int32_t ret;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);
    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        HDF_LOGE("%{public}s: read buffer failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->FillThisBuffer(serviceImpl, &buffer);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call FillThisBuffer function failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }
    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t SerStubSetCallbacks(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    struct CodecCallbackType *callback = NULL;
    int64_t appData = 0;

    struct HdfRemoteService *callbackRemote = HdfSbufReadRemoteService(data);
    if (callbackRemote == NULL) {
        HDF_LOGE("%{public}s: read callbackRemote failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    callback = CodecCallbackTypeGet(callbackRemote);

    if (!HdfSbufReadInt64(data, &appData)) {
        HDF_LOGE("%{public}s: read appData size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->SetCallbacks(serviceImpl, callback, appData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call SetCallbacks function failed!", __func__);
        return ret;
    }
    return ret;
}

static int32_t SerStubComponentDeInit(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                      struct HdfSBuf *reply)
{
    int32_t ret;

    ret = serviceImpl->ComponentDeInit(serviceImpl);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call ComponentDeInit function failed!", __func__);
    }

    return ret;
}

static int32_t SerStubUseEglImage(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    struct OmxCodecBuffer buffer;
    uint32_t portIndex = 0;
    int8_t *eglImage = NULL;
    uint32_t eglImageLen = 0;

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        HDF_LOGE("%{public}s: read buffer failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &portIndex)) {
        HDF_LOGE("%{public}s: read &portIndex failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &eglImageLen)) {
        HDF_LOGE("%{public}s: read eglImage size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (eglImageLen > 0) {
        eglImage = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (eglImageLen));
        if (eglImage == NULL) {
            HDF_LOGE("%{public}s: HDF_ERR_MALLOC_FAIL!", __func__);
            return HDF_ERR_MALLOC_FAIL;
        }

        for (uint32_t i = 0; i < eglImageLen; i++) {
            if (!HdfSbufReadInt8(data, &eglImage[i])) {
                HDF_LOGE("%{public}s: read &eglImage[i] failed!", __func__);
                FreeMem(eglImage, eglImageLen);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }

    ret = serviceImpl->UseEglImage(serviceImpl, &buffer, portIndex, eglImage, eglImageLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call UseEglImage function failed!", __func__);
        FreeMem(eglImage, eglImageLen);
        return ret;
    }

    if (!OmxCodecBufferBlockMarshalling(reply, &buffer)) {
        HDF_LOGE("%{public}s: write buffer failed!", __func__);
        FreeMem(eglImage, eglImageLen);
        return HDF_ERR_INVALID_PARAM;
    }

    FreeMem(eglImage, eglImageLen);
    return ret;
}

static int32_t SerStubComponentRoleEnum(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                        struct HdfSBuf *reply)
{
    int32_t ret;
    uint8_t *role = NULL;
    uint32_t roleLen = 0;
    uint32_t index = 0;

    if (!HdfSbufReadUint32(data, &roleLen)) {
        HDF_LOGE("%{public}s: read &roleLen failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    role = (uint8_t*)OsalMemCalloc(sizeof(uint8_t) * (roleLen));
    if (role == NULL) {
        HDF_LOGE("%{public}s: HDF_ERR_MALLOC_FAIL!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfSbufReadUint32(data, &index)) {
        HDF_LOGE("%{public}s: read &index failed!", __func__);
        FreeMem((int8_t*)role, roleLen);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->ComponentRoleEnum(serviceImpl, role, roleLen, index);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call ComponentRoleEnum function failed!", __func__);
        FreeMem((int8_t*)role, roleLen);
        return ret;
    }

    for (uint32_t i = 0; i < roleLen; i++) {
        if (!HdfSbufWriteUint8(reply, role[i])) {
            HDF_LOGE("%{public}s: write role[i] failed!", __func__);
            FreeMem((int8_t*)role, roleLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    FreeMem((int8_t*)role, roleLen);
    return ret;
}

static int32_t CodecComponentTypeServiceOnRemoteRequest(struct HdfRemoteService *remote,
                                                        int32_t cmdId, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct CodecComponentType *serviceImpl = (struct CodecComponentType *)remote;
    if (!HdfRemoteServiceCheckInterfaceToken(serviceImpl->AsObject(serviceImpl), data)) {
        HDF_LOGE("%{public}s: interface token check failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    switch (cmdId) {
        case CMD_GET_COMPONENT_VERSION:
            return SerStubGetComponentVersion(serviceImpl, data, reply);
        case CMD_SEND_COMMAND:
            return SerStubSendCommand(serviceImpl, data, reply);
        case CMD_GET_PARAMETER:
            return SerStubGetParameter(serviceImpl, data, reply);
        case CMD_SET_PARAMETER:
            return SerStubSetParameter(serviceImpl, data, reply);
        case CMD_GET_CONFIG:
            return SerStubGetConfig(serviceImpl, data, reply);
        case CMD_SET_CONFIG:
            return SerStubSetConfig(serviceImpl, data, reply);
        case CMD_GET_EXTENSION_INDEX:
            return SerStubGetExtensionIndex(serviceImpl, data, reply);
        case CMD_GET_STATE:
            return SerStubGetState(serviceImpl, data, reply);
        case CMD_COMPONENT_TUNNEL_REQUEST:
            return SerStubComponentTunnelRequest(serviceImpl, data, reply);
        case CMD_USE_BUFFER:
            return SerStubUseBuffer(serviceImpl, data, reply);
        case CMD_ALLOCATE_BUFFER:
            return SerStubAllocateBuffer(serviceImpl, data, reply);
        case CMD_FREE_BUFFER:
            return SerStubFreeBuffer(serviceImpl, data, reply);
        case CMD_EMPTY_THIS_BUFFER:
            return SerStubEmptyThisBuffer(serviceImpl, data, reply);
        case CMD_FILL_THIS_BUFFER:
            return SerStubFillThisBuffer(serviceImpl, data, reply);
        case CMD_SET_CALLBACKS:
            return SerStubSetCallbacks(serviceImpl, data, reply);
        case CMD_COMPONENT_DE_INIT:
            return SerStubComponentDeInit(serviceImpl, data, reply);
        case CMD_USE_EGL_IMAGE:
            return SerStubUseEglImage(serviceImpl, data, reply);
        case CMD_COMPONENT_ROLE_ENUM:
            return SerStubComponentRoleEnum(serviceImpl, data, reply);
        default:
            HDF_LOGE("%{public}s: not support cmd %{public}d", __func__, cmdId);
            return HDF_ERR_INVALID_PARAM;
    }
}

static struct HdfRemoteService *CodecComponentTypeAsObject(struct CodecComponentType *self)
{
    if (self == NULL) {
        return NULL;
    }
    struct CodecComponentTypeStub *stub = CONTAINER_OF(self, struct CodecComponentTypeStub, interface);
    return stub->remote;
}

bool CodecComponentTypeStubConstruct(struct CodecComponentTypeStub *stub)
{
    if (stub == NULL) {
        HDF_LOGE("%{public}s: stub is null!", __func__);
        return false;
    }

    stub->dispatcher.Dispatch = CodecComponentTypeServiceOnRemoteRequest;
    stub->remote = HdfRemoteServiceObtain((struct HdfObject *)stub, &(stub->dispatcher));
    if (stub->remote == NULL) {
        HDF_LOGE("%{public}s: stub->remote is null", __func__);
        return false;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(stub->remote, CODEC_COMPONENT_INTERFACE_DESC)) {
        HDF_LOGE("%{public}s: failed to set remote service interface descriptor", __func__);
        CodecComponentTypeStubRelease(stub);
        return false;
    }

    stub->interface.AsObject = CodecComponentTypeAsObject;
    return true;
}

void CodecComponentTypeStubRelease(struct CodecComponentTypeStub *stub)
{
    if (stub == NULL) {
        return;
    }
    if (stub->remote != NULL) {
        HdfRemoteServiceRecycle(stub->remote);
        stub->remote = NULL;
    }
}