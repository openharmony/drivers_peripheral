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

#include "codec_callback_type_stub.h"
#include <dlfcn.h>
#include <hdf_base.h>
#include <hdf_dlist.h>
#include <hdf_remote_service.h>
#include <osal_mem.h>
#include <securec.h>
#include "codec_callback_type_service.h"
#include "codec_internal.h"
#include "codec_log_wrapper.h"
#include "codec_types.h"

#define CODEC_CALLBACK_SO_PATH "libcodec_hdi_omx_callback_type_service_impl.z.so"

typedef void (*SERVICE_CONSTRUCT_FUNC)(struct CodecCallbackType *);

struct CodecCallbackTypeStub {
    struct CodecCallbackType service;
    struct HdfRemoteDispatcher dispatcher;
    void *dlHandler;
};

static void FreeMem(int8_t *mem, uint32_t memLen)
{
    if (memLen > 0 && mem != NULL) {
        OsalMemFree(mem);
    }
}

static int32_t ReadArray(struct HdfSBuf *data, int8_t **array, uint32_t *arrayLen)
{
    int8_t *buffer = NULL;
    uint32_t bufferLen = 0;
    if (!HdfSbufReadUint32(data, &bufferLen)) {
        CODEC_LOGE("read buffer size failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (bufferLen == 0) {
        *arrayLen = bufferLen;
        return HDF_SUCCESS;
    }
    
    buffer = (int8_t*)OsalMemCalloc(sizeof(int8_t) * bufferLen);
    if (buffer == NULL) {
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < bufferLen; i++) {
        if (!HdfSbufReadInt8(data, &buffer[i])) {
            CODEC_LOGE("read &buffer[i] failed!");
            OsalMemFree(buffer);
            return HDF_ERR_INVALID_PARAM;
        }
    }
    
    *array = buffer;
    *arrayLen = bufferLen;
    return HDF_SUCCESS;
}

static int32_t ReadEventInfo(struct HdfSBuf *data, struct EventInfo *info)
{
    if (info == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    if (!HdfSbufReadInt64(data, &info->appData)) {
        CODEC_LOGE("read appData failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &info->data1)) {
        CODEC_LOGE("read &data1 failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &info->data2)) {
        CODEC_LOGE("read &data2 failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ReadArray(data, &info->eventData, &info->eventDataLen);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("read eventData failed!");
    }
    return ret;
}

static void ReleaseEventInfo(struct EventInfo *info)
{
    if (info == NULL) {
        CODEC_LOGE("can not free info");
        return;
    }
    FreeMem(info->eventData, info->eventDataLen);
}

static int32_t SerStubEventHandler(struct CodecCallbackType *serviceImpl,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    enum OMX_EVENTTYPE event;
    struct EventInfo info = {0};
    
    if (!HdfSbufReadUint32(data, (uint32_t*)&event)) {
        CODEC_LOGE("read &event failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ReadEventInfo(data, &info);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("read &info failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    
    ret = serviceImpl->EventHandler(serviceImpl, event, &info);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call EventHandler function failed!");
    }
    ReleaseEventInfo(&info);
    return ret;
}

static int32_t SerStubEmptyBufferDone(struct CodecCallbackType *serviceImpl,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    int64_t appData = 0;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);

    if (!HdfSbufReadInt64(data, &appData)) {
        CODEC_LOGE("read appData size failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        CODEC_LOGE("read buffer failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->EmptyBufferDone(serviceImpl, appData, &buffer);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call EmptyBufferDone function failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }

    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t SerStubFillBufferDone(struct CodecCallbackType *serviceImpl,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret;
    int64_t appData = 0;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);
    if (!HdfSbufReadInt64(data, &appData)) {
        CODEC_LOGE("read appData size failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        CODEC_LOGE("read buffer failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->FillBufferDone(serviceImpl, appData, &buffer);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call FillBufferDone function failed!");
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }

    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t CodecCallbackTypeServiceOnRemoteRequest(struct HdfRemoteService *service, int32_t code,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    struct CodecCallbackType *serviceImpl = (struct CodecCallbackType*)service;
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfRemoteServiceCheckInterfaceToken(serviceImpl->remote, data)) {
        CODEC_LOGE("check interface token failed");
        return HDF_ERR_INVALID_PARAM;
    }
    
    switch (code) {
        case CMD_EVENT_HANDLER:
            return SerStubEventHandler(serviceImpl, data, reply);
        case CMD_EMPTY_BUFFER_DONE:
            return SerStubEmptyBufferDone(serviceImpl, data, reply);
        case CMD_FILL_BUFFER_DONE:
            return SerStubFillBufferDone(serviceImpl, data, reply);
        default: {
            CODEC_LOGE("not support cmd %{public}d", code);
            return HDF_ERR_INVALID_PARAM;
        }
    }
}

static void *LoadServiceHandler(void)
{
    void *handler = NULL;
    handler = dlopen(CODEC_CALLBACK_SO_PATH, RTLD_LAZY);
    if (handler == NULL) {
        CODEC_LOGE("dlopen failed %{public}s", dlerror());
        return NULL;
    }

    return handler;
}

struct CodecCallbackType *CodecCallbackTypeStubGetInstance(void)
{
    SERVICE_CONSTRUCT_FUNC serviceConstructFunc = NULL;
    struct CodecCallbackTypeStub *stub
        = (struct CodecCallbackTypeStub *)OsalMemAlloc(sizeof(struct CodecCallbackTypeStub));
    if (stub == NULL) {
        CODEC_LOGE("OsalMemAlloc obj failed!");
        return NULL;
    }

    stub->dispatcher.Dispatch = CodecCallbackTypeServiceOnRemoteRequest;
    stub->service.remote = HdfRemoteServiceObtain((struct HdfObject*)stub, &(stub->dispatcher));
    if (stub->service.remote == NULL) {
        CODEC_LOGE("stub->service.remote is null");
        OsalMemFree(stub);
        return NULL;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(stub->service.remote, "ohos.hdi.codec_service")) {
        CODEC_LOGE("failed to init interface desc");
        OsalMemFree(stub);
        return NULL;
    }

    stub->dlHandler = LoadServiceHandler();
    if (stub->dlHandler == NULL) {
        CODEC_LOGE("stub->dlHanlder is null");
        OsalMemFree(stub);
        return NULL;
    }

    serviceConstructFunc = (SERVICE_CONSTRUCT_FUNC)dlsym(stub->dlHandler, "CodecCallbackTypeServiceConstruct");
    if (serviceConstructFunc == NULL) {
        CODEC_LOGE("dlsym failed %{public}s", dlerror());
        dlclose(stub->dlHandler);
        OsalMemFree(stub);
        return NULL;
    }

    serviceConstructFunc(&stub->service);
    return &stub->service;
}

void CodecCallbackTypeStubRelease(struct CodecCallbackType *instance)
{
    if (instance == NULL) {
        CODEC_LOGE("instance is null");
        return;
    }
    struct CodecCallbackTypeStub *stub = CONTAINER_OF(instance, struct CodecCallbackTypeStub, service);
    dlclose(stub->dlHandler);
    if (stub->service.remote != NULL) {
        HdfRemoteServiceRecycle(stub->service.remote);
        stub->service.remote = NULL;
    }
    OsalMemFree(stub);
}
struct CodecCallbackType *CodecCallbackTypeGet(struct HdfRemoteService *remote)
{
    (void)remote;
    return CodecCallbackTypeStubGetInstance();
}

void CodecCallbackTypeRelease(struct CodecCallbackType *instance)
{
    return CodecCallbackTypeStubRelease(instance);
}
