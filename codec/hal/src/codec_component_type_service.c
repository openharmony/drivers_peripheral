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

#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>
#include <unistd.h>
#include "codec_adapter_interface.h"
#include "codec_component_type_stub.h"
#include "codec_component_type_service.h"

#define HDF_LOG_TAG codec_hdi_server

int32_t OmxManagerCreateComponent(OMX_HANDLETYPE *compHandle, char *compName, void *appData, int32_t appDataSize,
    struct CodecCallbackType *callbacks)
{
    HDF_LOGI("%{public}s, service impl!", __func__);
    return OMXAdapterCreateComponent(compHandle, compName, (int8_t*)appData, appDataSize, callbacks);
}

int32_t OmxManagerDestroyComponent(OMX_HANDLETYPE compHandle)
{
    HDF_LOGI("%{public}s, service impl!", __func__);
    return OmxAdapterDestoryComponent(compHandle);
}

int32_t CodecComponentTypeGetComponentVersion(struct CodecComponentType *self, struct CompVerInfo *verInfo)
{
    HDF_LOGI("%{public}s, service impl!", __func__);
    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterComponentVersion(stub->componentHandle, verInfo);
}

int32_t CodecComponentTypeSendCommand(struct CodecComponentType *self,
    enum OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterSendCommand(stub->componentHandle, cmd, param, cmdData, cmdDataLen);
}

int32_t CodecComponentTypeGetParameter(struct CodecComponentType *self,
    uint32_t paramIndex, int8_t *paramStruct, uint32_t paramStructLen)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterGetParameter(stub->componentHandle, paramIndex, paramStruct, paramStructLen);
}

int32_t CodecComponentTypeSetParameter(struct CodecComponentType *self,
    uint32_t index, int8_t *paramStruct, uint32_t paramStructLen)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterSetParameter(stub->componentHandle, index, paramStruct, paramStructLen);
}

int32_t CodecComponentTypeGetConfig(struct CodecComponentType *self,
    uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterGetConfig(stub->componentHandle, index, cfgStruct, cfgStructLen);
}

int32_t CodecComponentTypeSetConfig(struct CodecComponentType *self,
    uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterSetConfig(stub->componentHandle, index, cfgStruct, cfgStructLen);
}

int32_t CodecComponentTypeGetExtensionIndex(struct CodecComponentType *self,
    const char *paramName, uint32_t *indexType)
{
    HDF_LOGI("%{public}s, service impl!", __func__);
    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterGetExtensionIndex(stub->componentHandle, paramName, (enum OMX_INDEXTYPE *)indexType);
}

int32_t CodecComponentTypeGetState(struct CodecComponentType *self, enum OMX_STATETYPE *state)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterGetState(stub->componentHandle, state);
}

int32_t CodecComponentTypeComponentTunnelRequest(struct CodecComponentType *self,
    uint32_t port, int32_t tunneledComp, uint32_t tunneledPort,
    struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterComponentTunnelRequest(stub->componentHandle, port, tunneledComp, tunneledPort, tunnelSetup);
}

int32_t CodecComponentTypeUseBuffer(struct CodecComponentType *self,
    uint32_t portIndex, struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterUseBuffer(stub->componentHandle, portIndex, buffer);
}

int32_t CodecComponentTypeAllocateBuffer(struct CodecComponentType *self,
    uint32_t portIndex, struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterAllocateBuffer(stub->componentHandle, portIndex, buffer);
}

int32_t CodecComponentTypeFreeBuffer(struct CodecComponentType *self, uint32_t portIndex,
    const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterFreeBuffer(stub->componentHandle, portIndex, (struct OmxCodecBuffer *)buffer);
}

int32_t CodecComponentTypeEmptyThisBuffer(struct CodecComponentType *self,
    const struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterEmptyThisBuffer(stub->componentHandle, (struct OmxCodecBuffer *)buffer);
}

int32_t CodecComponentTypeFillThisBuffer(struct CodecComponentType *self,
    const struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterFillThisBuffer(stub->componentHandle, (struct OmxCodecBuffer *)buffer);
}

int32_t CodecComponentTypeSetCallbacks(struct CodecComponentType *self,
    struct CodecCallbackType* callback, int8_t *appData, uint32_t appDataLen)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterSetCallbacks(stub->componentHandle, callback, appData, appDataLen);
}

int32_t CodecComponentTypeComponentDeInit(struct CodecComponentType *self)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterDeInit(stub->componentHandle);
}

int32_t CodecComponentTypeUseEglImage(struct CodecComponentType *self,
    struct OmxCodecBuffer *buffer, uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterUseEglImage(stub->componentHandle, buffer, portIndex, eglImage, eglImageLen);
}

int32_t CodecComponentTypeComponentRoleEnum(struct CodecComponentType *self,
    uint8_t *role, uint32_t roleLen, uint32_t index)
{
    HDF_LOGI("%{public}s, service impl!", __func__);

    struct CodecComponentTypeStub *stub = (struct CodecComponentTypeStub *)self;
    return OmxAdapterComponentRoleEnum(stub->componentHandle, role, roleLen, index);
}

void CodecComponentTypeServiceConstruct(struct OmxComponentManager *manager, struct CodecComponentType *instance)
{
    manager->CreateComponent = OmxManagerCreateComponent;
    manager->DestoryComponent = OmxManagerDestroyComponent;
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