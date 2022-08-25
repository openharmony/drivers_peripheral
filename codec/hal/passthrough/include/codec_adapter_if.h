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

#ifndef CODEC_ADAPTER_IF_H
#define CODEC_ADAPTER_IF_H
#include <hdf_dlist.h>
#include <pthread.h>
#include "codec_callback_if.h"
#include "codec_component_if.h"
#include "codec_component_type.h"
#include "codec_type.h"
#ifdef __cplusplus
extern "C" {
#endif

struct CodecComponentNode;

struct CodecComponentTypeInfo {
    struct CodecComponentType instance;
    struct CodecComponentNode *codecNode;
};

struct ComponentIdElement {
    uint32_t componentId;
    struct CodecComponentType **comp;
    struct CodecComponentTypeInfo *info;
    struct DListHead node;
};

struct ComponentManagerList {
    pthread_mutex_t listMute;
    struct DListHead head;
};

int32_t CodecAdapterCodecInit();
int32_t CodecAdapterCodecDeinit();
int32_t CodecAdapterCreateComponent(struct CodecComponentNode **codecNode, const char *compName, int64_t appData,
    const struct CodecCallbackType *callbacks);
int32_t CodecAdapterDestroyComponent(struct CodecComponentNode *codecNode);
int32_t CodecAdapterGetComponentVersion(const struct CodecComponentNode *codecNode, struct CompVerInfo *verInfo);
int32_t CodecAdapterSendCommand(const struct CodecComponentNode *codecNode, OMX_COMMANDTYPE cmd, uint32_t param,
    int8_t *cmdData, uint32_t cmdDataLen);
int32_t CodecAdapterGetParameter(
    const struct CodecComponentNode *codecNode, OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen);
int32_t CodecAdapterSetParameter(
    const struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, const int8_t *param, uint32_t paramLen);
int32_t CodecAdapterGetConfig(
    const struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, int8_t *config, uint32_t configLen);
int32_t CodecAdapterSetConfig(
    const struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, const int8_t *config, uint32_t configLen);
int32_t CodecAdapterGetExtensionIndex(
    const struct CodecComponentNode *codecNode, const char *parameterName, OMX_INDEXTYPE *indexType);
int32_t CodecAdapterGetState(const struct CodecComponentNode *codecNode, OMX_STATETYPE *state);
int32_t CodecAdapterComponentTunnelRequest(const struct CodecComponentNode *codecNode, uint32_t port,
    int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort, struct OMX_TUNNELSETUPTYPE *tunnelSetup);
int32_t CodecAdapterUseBuffer(
    const struct CodecComponentNode *codecNode, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer);
int32_t CodecAdapterAllocateBuffer(
    const struct CodecComponentNode *codecNode, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer);
int32_t CodecAdapterFreeBuffer(
    const struct CodecComponentNode *codecNode, uint32_t portIndex, const struct OmxCodecBuffer *omxBuffer);
int32_t CodecAdapterEmptyThisBuffer(const struct CodecComponentNode *codecNode, const struct OmxCodecBuffer *omxBuffer);
int32_t CodecAdapterFillThisBuffer(const struct CodecComponentNode *codecNode, const struct OmxCodecBuffer *omxBuffer);
int32_t CodecAdapterSetCallbacks(
    const struct CodecComponentNode *codecNode, struct CodecCallbackType *omxCallback, int64_t appData);
int32_t CodecAdapterComponentDeInit(const struct CodecComponentNode *codecNode);
int32_t CodecAdapterUseEglImage(const struct CodecComponentNode *codecNode, struct OmxCodecBuffer *buffer,
    uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen);
int32_t CodecAdapterComponentRoleEnum(
    const struct CodecComponentNode *codecNode, uint8_t *role, uint32_t roleLen, uint32_t index);
bool CheckParamStructLen(int32_t paramIndex, uint32_t paramLen);

#ifdef __cplusplus
};
#endif

#endif  // CODEC_ADAPTER_IF_H
