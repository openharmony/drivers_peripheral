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

#ifndef CODEC_COMPONENT_H
#define CODEC_COMPONENT_H

#include <stdint.h>
#include "codec_types.h"
#include "codec_callback_type.h"
#include "codec_component_type.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CODEC_HDI_OMX_SERVICE_NAME  "codec_hdi_omx_service"

enum {
    CMD_CODEC_GET_COMPONENT_NUM,
    CMD_CODEC_GET_COMPONENT_CAPABILITY_LIST,
    CMD_CREATE_COMPONENT,
    CMD_DESTROY_COMPONENT,
    CMD_GET_COMPONENT_VERSION,
    CMD_SEND_COMMAND,
    CMD_GET_PARAMETER,
    CMD_SET_PARAMETER,
    CMD_GET_CONFIG,
    CMD_SET_CONFIG,
    CMD_GET_EXTENSION_INDEX,
    CMD_GET_STATE,
    CMD_COMPONENT_TUNNEL_REQUEST,
    CMD_USE_BUFFER,
    CMD_ALLOCATE_BUFFER,
    CMD_FREE_BUFFER,
    CMD_EMPTY_THIS_BUFFER,
    CMD_FILL_THIS_BUFFER,
    CMD_SET_CALLBACKS,
    CMD_COMPONENT_DE_INIT,
    CMD_USE_EGL_IMAGE,
    CMD_COMPONENT_ROLE_ENUM,
};

struct CodecComponentType {
    int32_t (*GetComponentVersion)(struct CodecComponentType *self, char *compName,
        union OMX_VERSIONTYPE *compVersion, union OMX_VERSIONTYPE *specVersion,
        uint8_t *compUUID, uint32_t compUUIDLen);

    int32_t (*SendCommand)(struct CodecComponentType *self, enum OMX_COMMANDTYPE cmd, uint32_t param1,
        int8_t *cmdData, uint32_t cmdDataLen);

    int32_t (*GetParameter)(struct CodecComponentType *self, uint32_t paramIndex, int8_t *paramStruct,
        uint32_t paramStructLen);

    int32_t (*SetParameter)(struct CodecComponentType *self, uint32_t index, int8_t *paramStruct,
        uint32_t paramStructLen);

    int32_t (*GetConfig)(struct CodecComponentType *self, uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen);

    int32_t (*SetConfig)(struct CodecComponentType *self, uint32_t index, int8_t *cfgStruct, uint32_t cfgStructLen);

    int32_t (*GetExtensionIndex)(struct CodecComponentType *self, const char *paramName, uint32_t *indexType);

    int32_t (*GetState)(struct CodecComponentType *self, enum OMX_STATETYPE *state);

    int32_t (*ComponentTunnelRequest)(struct CodecComponentType *self, uint32_t port,
        int32_t tunneledComp, uint32_t tunneledPort, struct OMX_TUNNELSETUPTYPE *tunnelSetup);

    int32_t (*UseBuffer)(struct CodecComponentType *self, uint32_t portIndex, struct OmxCodecBuffer *buffer);

    int32_t (*AllocateBuffer)(struct CodecComponentType *self, struct OmxCodecBuffer *buffer, uint32_t portIndex);

    int32_t (*FreeBuffer)(struct CodecComponentType *self, uint32_t portIndex, const struct OmxCodecBuffer *buffer);

    int32_t (*EmptyThisBuffer)(struct CodecComponentType *self, const struct OmxCodecBuffer *buffer);

    int32_t (*FillThisBuffer)(struct CodecComponentType *self, const struct OmxCodecBuffer *buffer);

    int32_t (*SetCallbacks)(struct CodecComponentType *self, struct CodecCallbackType *callback,
        int8_t *appData, uint32_t appDataLen);

    int32_t (*ComponentDeInit)(struct CodecComponentType *self);

    int32_t (*UseEglImage)(struct CodecComponentType *self, struct OmxCodecBuffer *buffer, uint32_t portIndex,
        int8_t *eglImage, uint32_t eglImageLen);

    int32_t (*ComponentRoleEnum)(struct CodecComponentType *self, uint8_t *role, uint32_t roleLen, uint32_t index);
};

struct CodecComponentType *CodecComponentTypeGet(struct HdfRemoteService *remote);

void CodecComponentTypeRelease(struct CodecComponentType *instance);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // CODEC_COMPONENT_H