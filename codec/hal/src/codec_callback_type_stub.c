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

#include "codec_callback_type_stub.h"
#include <dlfcn.h>
#include <hdf_base.h>
#include <hdf_dlist.h>
#include <hdf_log.h>
#include <hdf_remote_service.h>
#include <osal_mem.h>
#include <securec.h>
#include "codec_callback_type_service.h"
#include "codec_internal.h"
#include "codec_types.h"

#define HDF_LOG_TAG codec_hdi_cb_server

#ifdef __ARM64__
#define DRIVER_PATH "/vendor/lib64"
#else
#define DRIVER_PATH "/vendor/lib"
#endif
#define OMX_CALLBACK_IMPLEMENT  "libcodec_hdi_omx_callback_type_service_impl"

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
        HDF_LOGE("%{public}s: read buffer size failed!", __func__);
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
            HDF_LOGE("%{public}s: read &buffer[i] failed!", __func__);
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
    int32_t ret;
    if (!HdfSbufReadInt64(data, &info->appData)) {
        HDF_LOGE("%{public}s: read appData failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &info->data1)) {
        HDF_LOGE("%{public}s: read &data1 failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadUint32(data, &info->data2)) {
        HDF_LOGE("%{public}s: read &data2 failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ReadArray(data, &info->eventData, &info->eventDataLen);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read eventData failed!", __func__);
    }
    return ret;
}

static void ReleaseEventInfo(struct EventInfo *info)
{
    FreeMem(info->eventData, info->eventDataLen);
}

static int32_t SerStubEventHandler(struct CodecCallbackType *serviceImpl,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    enum OMX_EVENTTYPE event;
    struct EventInfo info = {0};
    
    if (!HdfSbufReadUint32(data, (uint32_t*)&event)) {
        HDF_LOGE("%{public}s: read &event failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = ReadEventInfo(data, &info);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: read &info failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    
    ret = serviceImpl->EventHandler(serviceImpl, event, &info);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call EventHandler function failed!", __func__);
    }
    ReleaseEventInfo(&info);
    return ret;
}

static int32_t SerStubEmptyBufferDone(struct CodecCallbackType *serviceImpl,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    int64_t appData = 0;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);

    if (!HdfSbufReadInt64(data, &appData)) {
        HDF_LOGE("%{public}s: read appData size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        HDF_LOGE("%{public}s: read buffer failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->EmptyBufferDone(serviceImpl, appData, &buffer);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call EmptyBufferDone function failed!", __func__);
        ReleaseOmxCodecBuffer(&buffer);
        return ret;
    }

    ReleaseOmxCodecBuffer(&buffer);
    return ret;
}

static int32_t SerStubFillBufferDone(struct CodecCallbackType *serviceImpl,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    int64_t appData = 0;
    struct OmxCodecBuffer buffer;
    InitOmxCodecBuffer(&buffer);
    if (!HdfSbufReadInt64(data, &appData)) {
        HDF_LOGE("%{public}s: read appData size failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!OmxCodecBufferBlockUnmarshalling(data, &buffer)) {
        HDF_LOGE("%{public}s: read buffer failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    ret = serviceImpl->FillBufferDone(serviceImpl, appData, &buffer);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call FillBufferDone function failed!", __func__);
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
    if (!HdfRemoteServiceCheckInterfaceToken(serviceImpl->remote, data)) {
        HDF_LOGE("%{public}s: check interface token failed", __func__);
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
            HDF_LOGE("%{public}s: not support cmd %{public}d", __func__, code);
            return HDF_ERR_INVALID_PARAM;
        }
    }
}

static void *LoadServiceHandler(void)
{
    char *libPath = NULL;
    void *handler = NULL;

    char pathBuf[PATH_MAX] = {'\0'};
    libPath = HDF_LIBRARY_FULL_PATH(OMX_CALLBACK_IMPLEMENT);
    if (realpath(libPath, pathBuf) == NULL) {
        HDF_LOGE("%{public}s: realpath failed!", __func__);
        return NULL;
    }

    handler = dlopen(pathBuf, RTLD_LAZY);
    if (handler == NULL) {
        HDF_LOGE("%{public}s: dlopen failed %{public}s", __func__, dlerror());
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
        HDF_LOGE("%{public}s: OsalMemAlloc obj failed!", __func__);
        return NULL;
    }

    stub->dispatcher.Dispatch = CodecCallbackTypeServiceOnRemoteRequest;
    stub->service.remote = HdfRemoteServiceObtain((struct HdfObject*)stub, &(stub->dispatcher));
    if (stub->service.remote == NULL) {
        HDF_LOGE("%{public}s: stub->service.remote is null", __func__);
        OsalMemFree(stub);
        return NULL;
    }

    if (!HdfRemoteServiceSetInterfaceDesc(stub->service.remote, "ohos.hdi.codec_service")) {
        HDF_LOGE("%{public}s: failed to init interface desc", __func__);
        return NULL;
    }

    stub->dlHandler = LoadServiceHandler();
    if (stub->dlHandler == NULL) {
        HDF_LOGE("%{public}s: stub->dlHanlder is null", __func__);
        OsalMemFree(stub);
        return NULL;
    }

    serviceConstructFunc = (SERVICE_CONSTRUCT_FUNC)dlsym(stub->dlHandler, "CodecCallbackTypeServiceConstruct");
    if (serviceConstructFunc == NULL) {
        HDF_LOGE("%{public}s: dlsym failed %{public}s", __func__, dlerror());
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
        HDF_LOGE("%{public}s: instance is null", __func__);
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