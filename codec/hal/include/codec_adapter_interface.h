/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_OMX_ADAPTER_INTERFACE_H
#define CODEC_OMX_ADAPTER_INTERFACE_H
#include "codec_callback_if.h"
#include "codec_types.h"
#ifdef __cplusplus
extern "C" {
#endif

struct CodecComponentNode;
/**
 * @brief Create a component by name.
 */
int32_t OMXAdapterCreateComponent(struct CodecComponentNode **codecNode, char *compName, int64_t appData,
                                  struct CodecCallbackType *callbacks);
/**
 * @brief Release the component by handle.
 */
int32_t OmxAdapterDestroyComponent(struct CodecComponentNode *codecNode);
/**
 * @brief Get the version of the component.
 */
int32_t OmxAdapterComponentVersion(struct CodecComponentNode *codecNode, struct CompVerInfo *verInfo);
/**
 * @brief Send command to the component.
 */
int32_t OmxAdapterSendCommand(struct CodecComponentNode *codecNode, OMX_COMMANDTYPE cmd, uint32_t param,
                              int8_t *cmdData, uint32_t cmdDataLen);
/**
 * @brief Get the parameter by index.
 */
int32_t OmxAdapterGetParameter(struct CodecComponentNode *codecNode, OMX_INDEXTYPE paramIndex, int8_t *param,
                               uint32_t paramLen);
/**
 * @brief Set the parameter by index.
 */
int32_t OmxAdapterSetParameter(struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, int8_t *param,
                               uint32_t paramLen);
/**
 * @brief Get the config by index.
 *
 * This func can be invoked when the component is in any state except the OMX_StateInvalid state.
 */
int32_t OmxAdapterGetConfig(struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, int8_t *config,
                            uint32_t configLen);
int32_t OmxAdapterSetConfig(struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, int8_t *config,
                            uint32_t configLen);
int32_t OmxAdapterGetExtensionIndex(struct CodecComponentNode *codecNode, const char *parameterName,
                                    OMX_INDEXTYPE *indexType);
int32_t OmxAdapterGetState(struct CodecComponentNode *codecNode, OMX_STATETYPE *state);
/**
 * @brief Set up tunneled communication between an output port and an input port.
 */
int32_t OmxAdapterComponentTunnelRequest(struct CodecComponentNode *codecNode, uint32_t port,
                                         int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                         struct OMX_TUNNELSETUPTYPE *tunnelSetup);
/**
 * @brief The component uses a buffer already allocated by the IL client.
 */
int32_t OmxAdapterUseBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex,
                            struct OmxCodecBuffer *omxBuffer);
/**
 * @brief The component allocate a buffer.
 */
int32_t OmxAdapterAllocateBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex,
                                 struct OmxCodecBuffer *omxBuffer);
/**
 * @brief The component free the buffer.
 */
int32_t OmxAdapterFreeBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex,
                             struct OmxCodecBuffer *omxBuffer);
/**
 * @brief Send a filled buffer to the input port of the component.
 */
int32_t OmxAdapterEmptyThisBuffer(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *omxBuffer);
/**
 * @brief Send a empty buffer to the output port of the component.
 */
int32_t OmxAdapterFillThisBuffer(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *omxBuffer);
/**
 * @brief Set the callback.
 */
int32_t OmxAdapterSetCallbacks(struct CodecComponentNode *codecNode, struct CodecCallbackType *omxCallback,
                               int64_t appData);
/**
 * @brief DeInit the component.
 */
int32_t OmxAdapterDeInit(struct CodecComponentNode *codecNode);
/**
 * @brief The component use the buffer allocated in EGL.
 */
int32_t OmxAdapterUseEglImage(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *buffer,
                              uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen);
/**
 * @brief Get the role of the component.
 */
int32_t OmxAdapterComponentRoleEnum(struct CodecComponentNode *codecNode, uint8_t *role, uint32_t roleLen,
                                    uint32_t index);
/**
 * @brief Set the role for the component.
 */
int32_t OmxAdapterSetComponentRole(struct CodecComponentNode *codecNode, char *compName);
/**
 * @brief build hidumper reply.
 */
int32_t OmxAdapterWriteDumperData(char *info, uint32_t size, uint32_t compId, struct CodecComponentNode *codecNode);
#ifdef __cplusplus
};
#endif

#endif  // CODEC_OMX_ADAPTER_INTERFACE_H