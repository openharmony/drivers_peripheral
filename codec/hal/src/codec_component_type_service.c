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

#include "codec_component_type_service.h"
#include <hdf_base.h>
#include <osal_mem.h>
#include <securec.h>
#include <unistd.h>
#include "codec_adapter_interface.h"
#include "codec_component_type_stub.h"
#include "codec_log_wrapper.h"

struct CodecComponentTypeService {
    struct CodecComponentTypeStub stub;
    struct CodecComponentNode *codecNode;
};

static int32_t CodecComponentTypeGetComponentVersion(struct CodecComponentType *self, struct CompVerInfo *verInfo)
{
    CODEC_LOGI("service impl!");
    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterComponentVersion(service->codecNode, verInfo);
}

static int32_t CodecComponentTypeSendCommand(struct CodecComponentType *self,
    enum OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen)
{
    CODEC_LOGI("service impl!, type [%{public}d], cmd [%{public}d]", (uint32_t)cmd, param);

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterSendCommand(service->codecNode, cmd, param, cmdData, cmdDataLen);
}

static int32_t CodecComponentTypeGetParameter(struct CodecComponentType *self,
    uint32_t paramIndex, int8_t *paramStruct, uint32_t paramStructLen)
{
    CODEC_LOGI("service impl, index [%{public}x]!", paramIndex);

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t err = OmxAdapterGetParameter(service->codecNode, paramIndex, paramStruct, paramStructLen);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("index [%{public}u], ret value [%{public}x]!", paramIndex, err);
    }

    return err;
}

static int32_t CodecComponentTypeSetParameter(struct CodecComponentType *self,
    uint32_t index, int8_t *paramStruct, uint32_t paramStructLen)
{
    CODEC_LOGI("service impl, index [%{public}x]!", index);

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t err = OmxAdapterSetParameter(service->codecNode, index, paramStruct, paramStructLen);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("index [%{public}u], ret value [%{public}x]!", index, err);
    }
    return err;
}

static int32_t CodecComponentTypeGetConfig(struct CodecComponentType *self,
    uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen)
{
    CODEC_LOGI("service impl, index [%{public}x]!", index);

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t err = OmxAdapterGetConfig(service->codecNode, index, cfgStruct, cfgStructLen);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("index [%{public}u], ret value [%{public}x]!", index, err);
    }
    return err;
}

static int32_t CodecComponentTypeSetConfig(struct CodecComponentType *self,
    uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen)
{
    CODEC_LOGI("service impl, index [%{public}x]!", index);

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t err = OmxAdapterSetConfig(service->codecNode, index, cfgStruct, cfgStructLen);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("index [%{public}u], ret value [%{public}x]!", index, err);
    }
    return err;
}

static int32_t CodecComponentTypeGetExtensionIndex(struct CodecComponentType *self,
    const char *paramName, uint32_t *indexType)
{
    CODEC_LOGI("service impl!");
    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterGetExtensionIndex(service->codecNode, paramName, (enum OMX_INDEXTYPE *)indexType);
}

static int32_t CodecComponentTypeGetState(struct CodecComponentType *self, enum OMX_STATETYPE *state)
{
    CODEC_LOGI("service impl!");

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterGetState(service->codecNode, state);
}

static int32_t CodecComponentTypeComponentTunnelRequest(struct CodecComponentType *self,
    uint32_t port, int32_t tunneledComp, uint32_t tunneledPort,
    struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    CODEC_LOGI("service impl!");

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterComponentTunnelRequest(service->codecNode, port, tunneledComp, tunneledPort, tunnelSetup);
}

static int32_t CodecComponentTypeUseBuffer(struct CodecComponentType *self,
    uint32_t portIndex, struct OmxCodecBuffer *buffer)
{
    CODEC_LOGI("service impl, portIndex: [%{public}d]!", portIndex);

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterUseBuffer(service->codecNode, portIndex, buffer);
}

static int32_t CodecComponentTypeAllocateBuffer(struct CodecComponentType *self,
    uint32_t portIndex, struct OmxCodecBuffer *buffer)
{
    CODEC_LOGI("service impl, portIndex: [%{public}d]!", portIndex);

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterAllocateBuffer(service->codecNode, portIndex, buffer);
}

static int32_t CodecComponentTypeFreeBuffer(struct CodecComponentType *self, uint32_t portIndex,
    const struct OmxCodecBuffer *buffer)
{
    CODEC_LOGI("service impl, portIndex: [%{public}d], bufferId: [%{public}d]!",
        portIndex, buffer->bufferId);

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterFreeBuffer(service->codecNode, portIndex, (struct OmxCodecBuffer *)buffer);
}

static int32_t CodecComponentTypeEmptyThisBuffer(struct CodecComponentType *self,
    const struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterEmptyThisBuffer(service->codecNode, (struct OmxCodecBuffer *)buffer);
}

static int32_t CodecComponentTypeFillThisBuffer(struct CodecComponentType *self,
    const struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterFillThisBuffer(service->codecNode, (struct OmxCodecBuffer *)buffer);
}

static int32_t CodecComponentTypeSetCallbacks(struct CodecComponentType *self, struct CodecCallbackType *callback,
                                              int64_t appData)
{
    CODEC_LOGI("service impl!");

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterSetCallbacks(service->codecNode, callback, appData);
}

static int32_t CodecComponentTypeComponentDeInit(struct CodecComponentType *self)
{
    CODEC_LOGI("service impl!");

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterDeInit(service->codecNode);
}

static int32_t CodecComponentTypeUseEglImage(struct CodecComponentType *self,
    struct OmxCodecBuffer *buffer, uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen)
{
    CODEC_LOGI("service impl!");

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterUseEglImage(service->codecNode, buffer, portIndex, eglImage, eglImageLen);
}

static int32_t CodecComponentTypeComponentRoleEnum(struct CodecComponentType *self,
    uint8_t *role, uint32_t roleLen, uint32_t index)
{
    CODEC_LOGI("service impl!");

    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        CODEC_LOGE("invalid parameter");
        return HDF_ERR_INVALID_PARAM;
    }
    return OmxAdapterComponentRoleEnum(service->codecNode, role, roleLen, index);
}

void CodecComponentTypeServiceConstruct(struct CodecComponentType *instance)
{
    if (instance == NULL) {
        CODEC_LOGE("invalid parameter");
        return;
    }
    instance->GetComponentVersion = CodecComponentTypeGetComponentVersion;
    instance->SendCommand = CodecComponentTypeSendCommand;
    instance->GetParameter = CodecComponentTypeGetParameter;
    instance->SetParameter = CodecComponentTypeSetParameter;
    instance->GetConfig = CodecComponentTypeGetConfig;
    instance->SetConfig = CodecComponentTypeSetConfig;
    instance->GetExtensionIndex = CodecComponentTypeGetExtensionIndex;
    instance->GetState = CodecComponentTypeGetState;
    instance->ComponentTunnelRequest = CodecComponentTypeComponentTunnelRequest;
    instance->UseBuffer = CodecComponentTypeUseBuffer;
    instance->AllocateBuffer = CodecComponentTypeAllocateBuffer;
    instance->FreeBuffer = CodecComponentTypeFreeBuffer;
    instance->EmptyThisBuffer = CodecComponentTypeEmptyThisBuffer;
    instance->FillThisBuffer = CodecComponentTypeFillThisBuffer;
    instance->SetCallbacks = CodecComponentTypeSetCallbacks;
    instance->ComponentDeInit = CodecComponentTypeComponentDeInit;
    instance->UseEglImage = CodecComponentTypeUseEglImage;
    instance->ComponentRoleEnum = CodecComponentTypeComponentRoleEnum;
}
struct CodecComponentType *CodecComponentTypeServiceGet(void)
{
    struct CodecComponentTypeService *service =
        (struct CodecComponentTypeService *)OsalMemCalloc(sizeof(struct CodecComponentTypeService));
    if (service == NULL) {
        CODEC_LOGE("malloc CodecComponentTypeService obj failed!");
        return NULL;
    }

    if (!CodecComponentTypeStubConstruct(&service->stub)) {
        CODEC_LOGE("construct CodecComponentTypeStub obj failed!");
        OsalMemFree(service);
        return NULL;
    }
    CodecComponentTypeServiceConstruct(&service->stub.interface);
    return &service->stub.interface;
}

void CodecComponentTypeServiceRelease(struct CodecComponentType *self)
{
    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        return;
    }

    CodecComponentTypeStubRelease(&service->stub);
    service->codecNode = NULL;
    OsalMemFree(service);
}

void CodecComponentTypeServiceSetCodecNode(struct CodecComponentType *self, struct CodecComponentNode *codecNode)
{
    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        return;
    }
    service->codecNode = codecNode;
}

struct CodecComponentNode *CodecComponentTypeServiceGetCodecNode(struct CodecComponentType *self)
{
    struct CodecComponentTypeService *service = (struct CodecComponentTypeService *)self;
    if (service == NULL) {
        return NULL;
    }
    return service->codecNode;
}