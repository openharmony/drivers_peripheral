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

#include <osal_mem.h>
#include <servmgr_hdi.h>
#include "codec_component_manager.h"
#include "codec_internal.h"
#include "codec_log_wrapper.h"
#include "codec_util.h"
#include "codec_types.h"

struct CodecComponentManagerProxy {
    struct CodecComponentManager instance;
    struct HdfRemoteService *remoteOmx;
};

static struct CodecComponentManagerProxy g_codecComponentManagerProxy = {
    .instance = {
        .GetComponentNum = NULL,
        .GetComponentCapabilityList = NULL,
        .CreateComponent = NULL,
        .DestroyComponent = NULL,
        .AsObject = NULL,
    },
    .remoteOmx = NULL,
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

static int32_t GetComponentNum()
{
    int32_t num = 0;
    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL) {
        CODEC_LOGE("Failed to obtain");
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (reply == NULL) {
        CODEC_LOGE("Failed to obtain reply");
        HdfSbufRecycle(data);
        return HDF_FAILURE;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(g_codecComponentManagerProxy.remoteOmx, data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (g_codecComponentManagerProxy.remoteOmx->dispatcher->Dispatch(
        g_codecComponentManagerProxy.remoteOmx, CMD_CODEC_GET_COMPONENT_NUM, data, reply) != HDF_SUCCESS) {
        CODEC_LOGE("dispatch request failed!");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadInt32(reply, &num)) {
        CODEC_LOGE("read dataBlock->role failed!");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    ReleaseSbuf(data, reply);
    return num;
}

static int32_t GetComponentCapabilityList(CodecCompCapability *capList, int32_t count)
{
    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL) {
        CODEC_LOGE("Failed to obtain");
        return HDF_FAILURE;
    }
    int32_t num = GetComponentNum();
    if (count <= 0 || count > num) {
        CODEC_LOGE("Failed to get component");
        HdfSbufRecycle(data);
        return HDF_FAILURE;
    }
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (reply == NULL) {
        CODEC_LOGE("Failed to obtain reply");
        HdfSbufRecycle(data);
        return HDF_FAILURE;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(g_codecComponentManagerProxy.remoteOmx, data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(data, count)) {
        CODEC_LOGE("write count failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    if (g_codecComponentManagerProxy.remoteOmx->dispatcher->Dispatch(g_codecComponentManagerProxy.remoteOmx,
                                                                     CMD_CODEC_GET_COMPONENT_CAPABILITY_LIST, data,
                                                                     reply) != HDF_SUCCESS) {
        CODEC_LOGE("dispatch request failed!");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    for (int32_t i = 0; i < count; i++) {
        if (!CodecCompCapabilityBlockUnmarshalling(reply, &(capList)[i])) {
            CODEC_LOGE("read capbility %{public}d from sbuf failed!", i);
            ReleaseSbuf(data, reply);
            return HDF_FAILURE;
        }
    }
    
    ReleaseSbuf(data, reply);
    return HDF_SUCCESS;
}

static int32_t FillHdfSBufData(struct HdfSBuf *data, char *compName, int64_t appData,
                               struct CodecCallbackType *callback)
{
    if (!HdfRemoteServiceWriteInterfaceToken(g_codecComponentManagerProxy.remoteOmx, data)) {
        CODEC_LOGE("write interface token failed");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(data, compName)) {
        CODEC_LOGE("write paramName failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteInt64(data, appData)) {
        CODEC_LOGE("write appData failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    if (HdfSbufWriteRemoteService(data, callback->remote) != 0) {
        CODEC_LOGE("write callback failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

static int32_t CreateComponent(struct CodecComponentType **component, uint32_t *componentId, char *compName,
                               int64_t appData, struct CodecCallbackType *callback)
{
    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL || componentId == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    int32_t ret = FillHdfSBufData(data, compName, appData, callback);
    if (ret != HDF_SUCCESS) {
        ReleaseSbuf(data, reply);
        return ret;
    }
    
    ret = g_codecComponentManagerProxy.remoteOmx->dispatcher->Dispatch(g_codecComponentManagerProxy.remoteOmx,
                                                                       CMD_CREATE_COMPONENT, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }

    struct HdfRemoteService *componentRemote = HdfSbufReadRemoteService(reply);
    if (componentRemote == NULL) {
        CODEC_LOGE("read componentRemote failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(reply, componentId)) {
        CODEC_LOGE("read componentId failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }
    *component = CodecComponentTypeGet(componentRemote);
    ReleaseSbuf(data, reply);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t DestroyComponent(uint32_t componentId)
{
    int32_t ret;

    struct HdfSBuf *data = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *reply = HdfSbufTypedObtain(SBUF_IPC);
    if (data == NULL || reply == NULL) {
        CODEC_LOGE("HdfSubf malloc failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (!HdfRemoteServiceWriteInterfaceToken(g_codecComponentManagerProxy.remoteOmx, data)) {
        CODEC_LOGE("write interface token failed");
        ReleaseSbuf(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(data, componentId)) {
        CODEC_LOGE("write componentId failed!");
        ReleaseSbuf(data, reply);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = g_codecComponentManagerProxy.remoteOmx->dispatcher->Dispatch(g_codecComponentManagerProxy.remoteOmx,
                                                                       CMD_DESTROY_COMPONENT, data, reply);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call failed! error code is %{public}d", ret);
        ReleaseSbuf(data, reply);
        return ret;
    }
    ReleaseSbuf(data, reply);
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t InitCodecComponentManagerProxy(void)
{
    if (g_codecComponentManagerProxy.remoteOmx != NULL) {
        return HDF_SUCCESS;
    }

    struct HDIServiceManager *serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == NULL) {
        CODEC_LOGE("HDIServiceManager not found!");
        return HDF_FAILURE;
    }

    struct HdfRemoteService *remoteOmx = serviceMgr->GetService(serviceMgr, CODEC_HDI_OMX_SERVICE_NAME);
    HDIServiceManagerRelease(serviceMgr);
    if (remoteOmx == NULL) {
        CODEC_LOGE("CodecComponentTypeService not found!");
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceSetInterfaceDesc(remoteOmx, "ohos.hdi.codec_service")) {
        CODEC_LOGE("failed to init interface desc");
        HdfRemoteServiceRecycle(remoteOmx);
        return HDF_FAILURE;
    }

    g_codecComponentManagerProxy.remoteOmx = remoteOmx;
    g_codecComponentManagerProxy.instance.GetComponentNum = GetComponentNum;
    g_codecComponentManagerProxy.instance.GetComponentCapabilityList = GetComponentCapabilityList;
    g_codecComponentManagerProxy.instance.CreateComponent = CreateComponent;
    g_codecComponentManagerProxy.instance.DestroyComponent = DestroyComponent;

    return HDF_SUCCESS;
}

struct CodecComponentManager *GetCodecComponentManager(void)
{
    if (InitCodecComponentManagerProxy() != HDF_SUCCESS) {
        return NULL;
    }
    return &g_codecComponentManagerProxy.instance;
}

void CodecComponentManagerRelease(void)
{
    if (g_codecComponentManagerProxy.remoteOmx != NULL) {
        HdfRemoteServiceRecycle(g_codecComponentManagerProxy.remoteOmx);
        g_codecComponentManagerProxy.remoteOmx = NULL;
    }
}