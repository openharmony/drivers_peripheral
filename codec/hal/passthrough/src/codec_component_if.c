/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <hdf_dlist.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include "codec_adapter_if.h"

#define HDF_LOG_TAG codec_hdi_passthrough

static int32_t ComponentTypeGetComponentVersion(struct CodecComponentType *self, struct CompVerInfo *verInfo)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterGetComponentVersion(info->codecNode, verInfo);
}

static int32_t ComponentTypeSendCommand(
    struct CodecComponentType *self, enum OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterSendCommand(info->codecNode, cmd, param, cmdData, cmdDataLen);
}

static int32_t ComponentTypeGetParameter(
    struct CodecComponentType *self, uint32_t paramIndex, int8_t *paramStruct, uint32_t paramStructLen)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterGetParameter(info->codecNode, paramIndex, paramStruct, paramStructLen);
}

static int32_t ComponentTypeSetParameter(
    struct CodecComponentType *self, uint32_t index, int8_t *paramStruct, uint32_t paramStructLen)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterSetParameter(info->codecNode, index, paramStruct, paramStructLen);
}

static int32_t ComponentTypeGetConfig(
    struct CodecComponentType *self, uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterGetConfig(info->codecNode, index, cfgStruct, cfgStructLen);
}

static int32_t ComponentTypeSetConfig(
    struct CodecComponentType *self, uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterSetConfig(info->codecNode, index, cfgStruct, cfgStructLen);
}

static int32_t ComponentTypeGetExtensionIndex(
    struct CodecComponentType *self, const char *paramName, uint32_t *indexType)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterGetExtensionIndex(info->codecNode, paramName, indexType);
}

static int32_t ComponentTypeGetState(struct CodecComponentType *self, enum OMX_STATETYPE *state)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterGetState(info->codecNode, state);
}

static int32_t ComponentTypeComponentTunnelRequest(struct CodecComponentType *self, uint32_t port, int32_t tunneledComp,
    uint32_t tunneledPort, struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterComponentTunnelRequest(info->codecNode, port, tunneledComp, tunneledPort, tunnelSetup);
}

static int32_t ComponentTypeUseBuffer(
    struct CodecComponentType *self, uint32_t portIndex, struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterUseBuffer(info->codecNode, portIndex, buffer);
}

static int32_t ComponentTypeAllocateBuffer(
    struct CodecComponentType *self, uint32_t portIndex, struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterAllocateBuffer(info->codecNode, portIndex, buffer);
}

static int32_t ComponentTypeFreeBuffer(
    struct CodecComponentType *self, uint32_t portIndex, const struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterFreeBuffer(info->codecNode, portIndex, buffer);
}

static int32_t ComponentTypeEmptyThisBuffer(struct CodecComponentType *self, const struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterEmptyThisBuffer(info->codecNode, buffer);
}

static int32_t ComponentTypeFillThisBuffer(struct CodecComponentType *self, const struct OmxCodecBuffer *buffer)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterFillThisBuffer(info->codecNode, buffer);
}

static int32_t ComponentTypeSetCallbacks(
    struct CodecComponentType *self, struct CodecCallbackType *callback, int64_t appData)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterSetCallbacks(info->codecNode, callback, appData);
}

static int32_t ComponentTypeComponentDeInit(struct CodecComponentType *self)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterComponentDeInit(info->codecNode);
}

static int32_t ComponentTypeUseEglImage(struct CodecComponentType *self, struct OmxCodecBuffer *buffer,
    uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterUseEglImage(info->codecNode, buffer, portIndex, eglImage, eglImageLen);
}

static int32_t ComponentTypeComponentRoleEnum(
    struct CodecComponentType *self, uint8_t *role, uint32_t roleLen, uint32_t index)
{
    struct CodecComponentTypeInfo *info = CONTAINER_OF(self, struct CodecComponentTypeInfo, instance);
    if (info == NULL) {
        HDF_LOGE("%{public}s: info is null", __func__);
        return HDF_FAILURE;
    }
    return CodecAdapterComponentRoleEnum(info->codecNode, role, roleLen, index);
}

static void ComponentTypeConstruct(struct CodecComponentType *instance)
{
    instance->GetComponentVersion = ComponentTypeGetComponentVersion;
    instance->SendCommand = ComponentTypeSendCommand;
    instance->GetParameter = ComponentTypeGetParameter;
    instance->SetParameter = ComponentTypeSetParameter;
    instance->GetConfig = ComponentTypeGetConfig;
    instance->SetConfig = ComponentTypeSetConfig;
    instance->GetExtensionIndex = ComponentTypeGetExtensionIndex;
    instance->GetState = ComponentTypeGetState;
    instance->ComponentTunnelRequest = ComponentTypeComponentTunnelRequest;
    instance->UseBuffer = ComponentTypeUseBuffer;
    instance->AllocateBuffer = ComponentTypeAllocateBuffer;
    instance->FreeBuffer = ComponentTypeFreeBuffer;
    instance->EmptyThisBuffer = ComponentTypeEmptyThisBuffer;
    instance->FillThisBuffer = ComponentTypeFillThisBuffer;
    instance->SetCallbacks = ComponentTypeSetCallbacks;
    instance->ComponentDeInit = ComponentTypeComponentDeInit;
    instance->UseEglImage = ComponentTypeUseEglImage;
    instance->ComponentRoleEnum = ComponentTypeComponentRoleEnum;
}

struct CodecComponentType *CodecComponentTypeGet(struct HdfRemoteService *remote)
{
    struct CodecComponentTypeInfo *info =
        (struct CodecComponentTypeInfo *)OsalMemAlloc(sizeof(struct CodecComponentTypeInfo));
    if (info == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return NULL;
    }

    ComponentTypeConstruct(&info->instance);
    return &info->instance;
}

void CodecComponentTypeRelease(struct CodecComponentType *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: instanceis null", __func__);
        return;
    }
    struct CodecComponentTypeInfo *info = CONTAINER_OF(instance, struct CodecComponentTypeInfo, instance);
    if (info != NULL) {
        HDF_LOGI("%{public}s: OsalMemFree info ", __func__);
        OsalMemFree(info);
        info = NULL;
    }
}
