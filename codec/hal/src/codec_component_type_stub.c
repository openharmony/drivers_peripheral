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

#include "codec_component_type_stub.h"
#include <dlfcn.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <osal_mem.h>
#include <securec.h>
#include "codec_callback_if.h"
#include "codec_component_capability_config.h"
#include "codec_util.h"
#include "codec_log_wrapper.h"

static void FreeMem(int8_t *mem, uint32_t memLen)
{
    if (memLen > 0 && mem != NULL) {
        OsalMemFree(mem);
    }
}

static int32_t SerStubGetComponentVersion(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                          struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    struct CompVerInfo verInfo;
    ret = memset_s(&verInfo, sizeof(verInfo), 0, sizeof(verInfo));
    if (ret != EOK) {
        CODEC_LOGE("memset_s verInfo err [%{public}d].", ret);
        return ret;
    }
    ret = serviceImpl->GetComponentVersion(serviceImpl, &verInfo);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call GetComponentVersion function failed!");
        return ret;
    }
    if (!HdfSbufWriteUnpadBuffer(reply, (const uint8_t *)&verInfo, sizeof(struct CompVerInfo))) {
        CODEC_LOGE("write verInfo failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t SerStubSendCommand(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    enum OMX_COMMANDTYPE cmd;
    uint32_t param = 0;
    int8_t *cmdData = NULL;
    uint32_t cmdDataLen = 0;

    if (!HdfSbufReadUint32(data, (uint32_t*)&cmd)) {
        CODEC_LOGE("read &cmd failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &param)) {
        CODEC_LOGE("read &param failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &cmdDataLen)) {
        CODEC_LOGE("read cmdData size failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (cmdDataLen > 0) {
        cmdData = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (cmdDataLen));
        if (cmdData == NULL) {
            CODEC_LOGE("HDF_ERR_MALLOC_FAIL!");
            return HDF_ERR_MALLOC_FAIL;
        }

        for (uint32_t i = 0; i < cmdDataLen; i++) {
            if (!HdfSbufReadInt8(data, &cmdData[i])) {
                CODEC_LOGE("read &cmdData[i] failed!");
                FreeMem(cmdData, cmdDataLen);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }

    ret = serviceImpl->SendCommand(serviceImpl, cmd, param, cmdData, cmdDataLen);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call SendCommand function failed!");
        FreeMem(cmdData, cmdDataLen);
        return ret;
    }

    FreeMem(cmdData, cmdDataLen);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return HDF_SUCCESS;
}

static int32_t SerStubGetParameter(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t paramIndex = 0;
    int8_t *paramStruct = NULL;
    uint32_t paramStructLen = 0;

    if (!HdfSbufReadUint32(data, &paramIndex)) {
        CODEC_LOGE("read paramIndex failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &paramStructLen)) {
        CODEC_LOGE("read paramStructLen failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    paramStruct = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (paramStructLen));
    if (paramStruct == NULL) {
        CODEC_LOGE("HDF_ERR_MALLOC_FAIL!");
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < paramStructLen; i++) {
        if (!HdfSbufReadInt8(data, &paramStruct[i])) {
            CODEC_LOGE("read paramStruct[%{public}d] failed!", i);
            FreeMem(paramStruct, paramStructLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = serviceImpl->GetParameter(serviceImpl, paramIndex, paramStruct, paramStructLen);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call GetParameter function failed!");
        FreeMem(paramStruct, paramStructLen);
        return ret;
    }

    for (uint32_t i = 0; i < paramStructLen; i++) {
        if (!HdfSbufWriteInt8(reply, paramStruct[i])) {
            CODEC_LOGE("write paramStruct[i] failed!");
            FreeMem(paramStruct, paramStructLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    FreeMem(paramStruct, paramStructLen);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return HDF_SUCCESS;
}

static int32_t SerStubSetParameter(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t index = 0;
    int8_t *paramStruct = NULL;
    uint32_t paramStructLen = 0;

    if (!HdfSbufReadUint32(data, &index)) {
        CODEC_LOGE("read &index failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &paramStructLen)) {
        CODEC_LOGE("read paramStruct size failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (paramStructLen > 0) {
        paramStruct = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (paramStructLen));
        if (paramStruct == NULL) {
            CODEC_LOGE("HDF_ERR_MALLOC_FAIL!");
            return HDF_ERR_MALLOC_FAIL;
        }

        for (uint32_t i = 0; i < paramStructLen; i++) {
            if (!HdfSbufReadInt8(data, &paramStruct[i])) {
                CODEC_LOGE("read &paramStruct[i] failed!");
                FreeMem(paramStruct, paramStructLen);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }

    ret = serviceImpl->SetParameter(serviceImpl, index, paramStruct, paramStructLen);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call SetParameter function failed!");
        FreeMem(paramStruct, paramStructLen);
        return ret;
    }

    FreeMem(paramStruct, paramStructLen);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return HDF_SUCCESS;
}

static int32_t SerStubGetConfig(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t index = 0;
    int8_t *cfgStruct = NULL;
    uint32_t cfgStructLen = 0;

    if (!HdfSbufReadUint32(data, &index)) {
        CODEC_LOGE("read &index failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &cfgStructLen)) {
        CODEC_LOGE("read cfgStructLen failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    cfgStruct = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (cfgStructLen));
    if (cfgStruct == NULL) {
        CODEC_LOGE("HDF_ERR_MALLOC_FAIL!");
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < cfgStructLen; i++) {
        if (!HdfSbufReadInt8(data, &cfgStruct[i])) {
            CODEC_LOGE("read cfgStruct[i] failed!");
            FreeMem(cfgStruct, cfgStructLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    ret = serviceImpl->GetConfig(serviceImpl, index, cfgStruct, cfgStructLen);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call GetConfig function failed!");
        FreeMem(cfgStruct, cfgStructLen);
        return ret;
    }

    for (uint32_t i = 0; i < cfgStructLen; i++) {
        if (!HdfSbufWriteInt8(reply, cfgStruct[i])) {
            CODEC_LOGE("write cfgStruct[i] failed!");
            FreeMem(cfgStruct, cfgStructLen);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    FreeMem(cfgStruct, cfgStructLen);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t SerStubSetConfig(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t index = 0;
    int8_t *cfgStruct = NULL;
    uint32_t cfgStructLen = 0;

    if (!HdfSbufReadUint32(data, &index)) {
        CODEC_LOGE("read &index failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &cfgStructLen)) {
        CODEC_LOGE("read cfgStruct size failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (cfgStructLen > 0) {
        cfgStruct = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (cfgStructLen));
        if (cfgStruct == NULL) {
            CODEC_LOGE("HDF_ERR_MALLOC_FAIL!");
            return HDF_ERR_MALLOC_FAIL;
        }

        for (uint32_t i = 0; i < cfgStructLen; i++) {
            if (!HdfSbufReadInt8(data, &cfgStruct[i])) {
                CODEC_LOGE("read &cfgStruct[i] failed!");
                FreeMem(cfgStruct, cfgStructLen);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }

    ret = serviceImpl->SetConfig(serviceImpl, index, cfgStruct, cfgStructLen);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call SetConfig function failed!");
        FreeMem(cfgStruct, cfgStructLen);
        return ret;
    }

    FreeMem(cfgStruct, cfgStructLen);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t SerStubGetExtensionIndex(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                        struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    char *paramName = NULL;
    uint32_t indexType = 0;

    const char *paramNameCp = HdfSbufReadString(data);
    if (paramNameCp == NULL) {
        CODEC_LOGE("read paramNameCp failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    paramName = strdup(paramNameCp);

    ret = serviceImpl->GetExtensionIndex(serviceImpl, paramName, &indexType);
    if (paramName != NULL) {
        OsalMemFree(paramName);
        paramName = NULL;
    }
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call GetExtensionIndex function failed!");
        return ret;
    }

    if (!HdfSbufWriteUint32(reply, indexType)) {
        CODEC_LOGE("write indexType failed!");
        ret = HDF_ERR_INVALID_PARAM;
    }

    return ret;
}

static int32_t SerStubGetState(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    enum OMX_STATETYPE state;

    ret = serviceImpl->GetState(serviceImpl, &state);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call GetState function failed!");
        return ret;
    }

    if (!HdfSbufWriteUint32(reply, (uint32_t)state)) {
        CODEC_LOGE("write state failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    return ret;
}

static int32_t SerStubComponentTunnelRequest(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                             struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t port = 0;
    int32_t tunneledComp = 0;
    uint32_t tunneledPort = 0;
    struct OMX_TUNNELSETUPTYPE tunnelSetup;

    if (!HdfSbufReadUint32(data, &port)) {
        CODEC_LOGE("read &port failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadInt32(data, &tunneledComp)) {
        CODEC_LOGE("read &tunneledComp failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &tunneledPort)) {
        CODEC_LOGE("read &tunneledPort failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OMX_TUNNELSETUPTYPEBlockUnmarshalling(data, &tunnelSetup)) {
        CODEC_LOGE("read tunnelSetup failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->ComponentTunnelRequest(serviceImpl, port, tunneledComp, tunneledPort, &tunnelSetup);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call ComponentTunnelRequest function failed!");
        return ret;
    }

    if (!OMX_TUNNELSETUPTYPEBlockMarshalling(reply, &tunnelSetup)) {
        CODEC_LOGE("write tunnelSetup failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    return ret;
}

static int32_t SerStubUseBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    struct OmxCodecBuffer buffer;
    uint32_t portIndex = 0;
    InitOmxCodecBuffer(&buffer);

    if (!HdfSbufReadUint32(data, &portIndex)) {
        CODEC_LOGE("read &portIndex failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->UseBuffer(serviceImpl, portIndex, &buffer);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call UseBuffer function failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }

    if (!OmxCodecBufferBlockMarshalling(reply, &buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }
    ReleaseOmxCodecBuffer(&buffer);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t SerStubAllocateBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                     struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    struct OmxCodecBuffer buffer;
    uint32_t portIndex = 0;
    InitOmxCodecBuffer(&buffer);

    if (!HdfSbufReadUint32(data, &portIndex)) {
        CODEC_LOGE("read &portIndex failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->AllocateBuffer(serviceImpl, portIndex, &buffer);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call AllocateBuffer function failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }

    if (!OmxCodecBufferBlockMarshalling(reply, &buffer)) {
        CODEC_LOGE("write buffer failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }
    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t SerStubFreeBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    uint32_t portIndex = 0;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);
    if (!HdfSbufReadUint32(data, &portIndex)) {
        CODEC_LOGE("read &portIndex failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->FreeBuffer(serviceImpl, portIndex, &buffer);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call FreeBuffer function failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }
    ReleaseOmxCodecBuffer(&buffer);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t SerStubEmptyThisBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                      struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);
    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->EmptyThisBuffer(serviceImpl, &buffer);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call EmptyThisBuffer function failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }
    ReleaseOmxCodecBuffer(&buffer);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t SerStubFillThisBuffer(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                     struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);
    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->FillThisBuffer(serviceImpl, &buffer);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call FillThisBuffer function failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }
    ReleaseOmxCodecBuffer(&buffer);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t SerStubSetCallbacks(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    struct CodecCallbackType *callback = NULL;
    int64_t appData = 0;

    struct HdfRemoteService *callbackRemote = HdfSbufReadRemoteService(data);
    if (callbackRemote == NULL) {
        CODEC_LOGE("read callbackRemote failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    callback = CodecCallbackTypeGet(callbackRemote);

    if (!HdfSbufReadInt64(data, &appData)) {
        CODEC_LOGE("read appData size failed!");
        CodecCallbackTypeRelease(callback);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->SetCallbacks(serviceImpl, callback, appData);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call SetCallbacks function failed!");
        CodecCallbackTypeRelease(callback);
        return ret;
    }
    CodecCallbackTypeRelease(callback);
    return ret;
}

static int32_t SerStubComponentDeInit(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                      struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;

    ret = serviceImpl->ComponentDeInit(serviceImpl);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call ComponentDeInit function failed!");
    }

    return ret;
}

static int32_t SerStubUseEglImage(struct CodecComponentType *serviceImpl, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    struct OmxCodecBuffer buffer;
    uint32_t portIndex = 0;
    int8_t *eglImage = NULL;
    uint32_t eglImageLen = 0;

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        CODEC_LOGE("read buffer failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &portIndex)) {
        CODEC_LOGE("read &portIndex failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &eglImageLen)) {
        CODEC_LOGE("read eglImage size failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (eglImageLen > 0) {
        eglImage = (int8_t*)OsalMemCalloc(sizeof(int8_t) * (eglImageLen));
        if (eglImage == NULL) {
            CODEC_LOGE("HDF_ERR_MALLOC_FAIL!");
            return HDF_ERR_MALLOC_FAIL;
        }

        for (uint32_t i = 0; i < eglImageLen; i++) {
            if (!HdfSbufReadInt8(data, &eglImage[i])) {
                CODEC_LOGE("read &eglImage[i] failed!");
                FreeMem(eglImage, eglImageLen);
                return HDF_ERR_INVALID_PARAM;
            }
        }
    }

    ret = serviceImpl->UseEglImage(serviceImpl, &buffer, portIndex, eglImage, eglImageLen);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call UseEglImage function failed!");
        FreeMem(eglImage, eglImageLen);
        return ret;
    }

    if (!OmxCodecBufferBlockMarshalling(reply, &buffer)) {
        CODEC_LOGE("write buffer failed!");
        FreeMem(eglImage, eglImageLen);
        return HDF_ERR_INVALID_PARAM;
    }

    FreeMem(eglImage, eglImageLen);
    return ret;
}

static int32_t SerStubComponentRoleEnum(struct CodecComponentType *serviceImpl, struct HdfSBuf *data,
                                        struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    uint8_t *role = NULL;
    uint32_t roleLen = 0;
    uint32_t index = 0;

    if (!HdfSbufReadUint32(data, &roleLen)) {
        CODEC_LOGE("read &roleLen failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    role = (uint8_t*)OsalMemCalloc(sizeof(uint8_t) * (roleLen));
    if (role == NULL) {
        CODEC_LOGE("HDF_ERR_MALLOC_FAIL!");
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfSbufReadUint32(data, &index)) {
        CODEC_LOGE("read &index failed!");
        FreeMem((int8_t*)role, roleLen);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->ComponentRoleEnum(serviceImpl, role, roleLen, index);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call ComponentRoleEnum function failed!");
        FreeMem((int8_t*)role, roleLen);
        return ret;
    }

    for (uint32_t i = 0; i < roleLen; i++) {
        if (!HdfSbufWriteUint8(reply, role[i])) {
            CODEC_LOGE("write role[i] failed!");
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
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfRemoteServiceCheckInterfaceToken(serviceImpl->AsObject(serviceImpl), data)) {
        CODEC_LOGE("interface token check failed");
        return HDF_ERR_INVALID_PARAM;
    }
    if (cmdId < 0 || cmdId > CMD_COMPONENT_ROLE_ENUM) {
        CODEC_LOGE("not support cmd %{public}d", cmdId);
        return HDF_ERR_INVALID_PARAM;
    }

    typedef int32_t(*SerStubFunc)(struct CodecComponentType*, struct HdfSBuf*, struct HdfSBuf*);
    static SerStubFunc func[CMD_COMPONENT_ROLE_ENUM + 1] = {
        NULL,
        NULL,
        NULL,
        NULL,
        SerStubGetComponentVersion,
        SerStubSendCommand,
        SerStubGetParameter,
        SerStubSetParameter,
        SerStubGetConfig,
        SerStubSetConfig,
        SerStubGetExtensionIndex,
        SerStubGetState,
        SerStubComponentTunnelRequest,
        SerStubUseBuffer,
        SerStubAllocateBuffer,
        SerStubFreeBuffer,
        SerStubEmptyThisBuffer,
        SerStubFillThisBuffer,
        SerStubSetCallbacks,
        SerStubComponentDeInit,
        SerStubUseEglImage,
        SerStubComponentRoleEnum
    };

    if (func[cmdId] != NULL) {
        return func[cmdId](serviceImpl, data, reply);
    } else {
        CODEC_LOGE("not support cmd %{public}d", cmdId);
        return HDF_ERR_INVALID_PARAM;
    }
}

static struct HdfRemoteService *CodecComponentTypeAsObject(struct CodecComponentType *self)
{
    if (self == NULL) {
        return NULL;
    }
    struct CodecComponentTypeStub *stub = CONTAINER_OF(self, struct CodecComponentTypeStub, interface);
    if (stub == NULL) {
        return NULL;
    }
    return stub->remote;
}

bool CodecComponentTypeStubConstruct(struct CodecComponentTypeStub *stub)
{
    if (stub == NULL) {
        CODEC_LOGE("stub is null!");
        return false;
    }

    stub->dispatcher.Dispatch = CodecComponentTypeServiceOnRemoteRequest;
    stub->remote = HdfRemoteServiceObtain((struct HdfObject *)stub, &(stub->dispatcher));
    if (stub->remote == NULL) {
        CODEC_LOGE("stub->remote is null");
        return false;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(stub->remote, CODEC_COMPONENT_INTERFACE_DESC)) {
        CODEC_LOGE("failed to set remote service interface descriptor");
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
