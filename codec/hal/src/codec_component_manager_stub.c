/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "codec_component_manager_stub.h"
#include <dlfcn.h>
#include <hdf_device_desc.h>
#include <hdf_device_object.h>
#include <osal_mem.h>
#include <securec.h>
#include "codec_component_capability_config.h"
#include "codec_component_manager_service.h"
#include "codec_util.h"
#include "codec_log_wrapper.h"

#define CODEC_SERVICE_IMPL "libcodec_hdi_omx_service_impl"
typedef void (*SERVICE_CONSTRUCT_FUNC)(struct OmxComponentManager *);
static int32_t SerStubGetComponentNum(struct CodecComponentManager *serviceImpl, struct HdfSBuf *data,
                                      struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid paramter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t num = serviceImpl->GetComponentNum();
    if (!HdfSbufWriteInt32(reply, num)) {
        CODEC_LOGE("write num failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

static int32_t SerStubGetComponentCapablityList(struct CodecComponentManager *serviceImpl, struct HdfSBuf *data,
                                                struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid paramter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t count = 0;
    int32_t err = HDF_SUCCESS;
    CodecCompCapability *caps = NULL;
    if (!HdfSbufReadInt32(data, &count) || (count <= 0)) {
        CODEC_LOGE("read count failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    caps = (CodecCompCapability *)OsalMemCalloc(sizeof(CodecCompCapability) * (count));
    if (caps == NULL) {
        CODEC_LOGE("alloc caps failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    err = serviceImpl->GetComponentCapabilityList(caps, count);
    if (err != HDF_SUCCESS) {
        OsalMemFree(caps);
        CODEC_LOGE("call GetComponentCapabilityList function failed!");
        return err;
    }

    for (int32_t i = 0; i < count; i++) {
        if (!CodecCompCapabilityBlockMarshalling(reply, &caps[i])) {
            CODEC_LOGE("call CodecCompCapabilityBlockMarshalling function failed!");
            err = HDF_ERR_INVALID_PARAM;
            break;
        }
    }
    OsalMemFree(caps);
    return err;
}

static int32_t ReadParamsForCreateComponent(struct HdfSBuf *data, char **compName, int64_t *appData,
                                            struct CodecCallbackType **callback)
{
    const char *compNameCp = HdfSbufReadString(data);
    if (compNameCp == NULL) {
        CODEC_LOGE("read compNameCp failed!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadInt64(data, appData)) {
        CODEC_LOGE("read appData failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    *compName = strdup(compNameCp);

    struct HdfRemoteService *callbackRemote = HdfSbufReadRemoteService(data);
    if (callbackRemote == NULL) {
        CODEC_LOGE("read callbackRemote failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    *callback = CodecCallbackTypeGet(callbackRemote);

    return HDF_SUCCESS;
}

static int32_t SerStubCreateComponent(struct CodecComponentManager *serviceImpl, struct HdfSBuf *data,
                                      struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid paramter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = HDF_SUCCESS;
    struct CodecComponentType *component = NULL;
    uint32_t componentId = 0;
    int64_t appData = 0;
    struct CodecCallbackType *callback = NULL;
    char *compName = NULL;

    ret = ReadParamsForCreateComponent(data, &compName, &appData, &callback);
    if (ret != HDF_SUCCESS) {
        if (compName != NULL) {
            OsalMemFree(compName);
            compName = NULL;
        }
        return ret;
    }
    ret = serviceImpl->CreateComponent(&component, &componentId, compName, appData, callback);
    if (component == NULL) {
        CODEC_LOGE("fail to create component");
        if (compName != NULL) {
            OsalMemFree(compName);
            compName = NULL;
        }
        return ret;
    }
    if (compName != NULL) {
        OsalMemFree(compName);
        compName = NULL;
    }
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call CreateComponent function failed!");
        return ret;
    }

    if (HdfSbufWriteRemoteService(reply, component->AsObject(component)) != 0) {
        CODEC_LOGE("write component failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(reply, componentId)) {
        CODEC_LOGE("write componentId failed!");
        return HDF_ERR_INVALID_PARAM;
    }
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t SerStubDestroyComponent(struct CodecComponentManager *serviceImpl, struct HdfSBuf *data,
                                       struct HdfSBuf *reply)
{
    if (serviceImpl == NULL) {
        CODEC_LOGE("invalid paramter");
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t componentId = 0;
    if (!HdfSbufReadUint32(data, &componentId)) {
        CODEC_LOGE("read componentId failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = serviceImpl->DestroyComponent(componentId);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("call DestroyComponent function failed!");
    }
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    ReleaseCodecCache();
#endif
    return ret;
}

static int32_t CodecComponentManagerServiceOnRemoteRequest(struct CodecComponentManager *serviceImpl, int32_t cmdId,
                                                           struct HdfSBuf *data, struct HdfSBuf *reply)
{
    switch (cmdId) {
        case CMD_CODEC_GET_COMPONENT_NUM:
            return SerStubGetComponentNum(serviceImpl, data, reply);
        case CMD_CODEC_GET_COMPONENT_CAPABILITY_LIST:
            return SerStubGetComponentCapablityList(serviceImpl, data, reply);
        case CMD_CREATE_COMPONENT:
            return SerStubCreateComponent(serviceImpl, data, reply);
        case CMD_DESTROY_COMPONENT:
            return SerStubDestroyComponent(serviceImpl, data, reply);
        default:
            CODEC_LOGE("not support cmd %{public}d", cmdId);
            return HDF_ERR_INVALID_PARAM;
    }
}

static struct HdfRemoteService *CodecComponentManagerStubAsObject(struct CodecComponentManager *self)
{
    return NULL;
}

bool CodecComponentManagerStubConstruct(struct CodecComponentManagerStub *stub)
{
    if (stub == NULL) {
        CODEC_LOGE("stub is null!");
        return false;
    }

    stub->OnRemoteRequest = CodecComponentManagerServiceOnRemoteRequest;
    stub->interface.AsObject = CodecComponentManagerStubAsObject;
    return true;
}