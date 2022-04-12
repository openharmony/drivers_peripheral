/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd.
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

/**
 * @brief Create a component by name.
 */
extern int32_t OMXAdapterCreateComponent(OMX_HANDLETYPE *compHandle, char *compName, int8_t *appData,
                                         int32_t appDataSize, struct CodecCallbackType *callbacks);
/**
 * @brief Release the componet by handle.
 */
extern int32_t OmxAdapterDestoryComponent(OMX_HANDLETYPE compHandle);
/**
 * @brief Get the version of the component.
 */
extern int32_t OmxAdapterComponentVersion(OMX_HANDLETYPE compHandle, struct CompVerInfo *verInfo);
/**
 * @brief Send command to the component.
 */
extern int32_t OmxAdapterSendCommand(OMX_HANDLETYPE compHandle, enum OMX_COMMANDTYPE cmd, uint32_t param,
                                     int8_t *cmdData, uint32_t cmdDataLen);
/**
 * @brief Get the parameter by index.
 */
extern int32_t OmxAdapterGetParameter(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE paramIndex, int8_t *param,
                                      uint32_t paramLen);
/**
 * @brief Set the parameter by index.
 */
extern int32_t OmxAdapterSetParameter(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *param,
                                      uint32_t paramLen);
/**
 * @brief Get the config by index.
 *
 * This func can be invoked when the component is in any state except the OMX_StateInvalid state.
 */
extern int32_t OmxAdapterGetConfig(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *config,
                                   uint32_t configLen);
extern int32_t OmxAdapterSetConfig(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *config,
                                   uint32_t configLen);
extern int32_t OmxAdapterGetExtensionIndex(OMX_HANDLETYPE compHandle, const char *parameterName,
                                           enum OMX_INDEXTYPE *indexType);
extern int32_t OmxAdapterGetState(OMX_HANDLETYPE compHandle, enum OMX_STATETYPE *state);
/**
 * @brief Set up tunneled communication between an output port and an input port.
 */
extern int32_t OmxAdapterComponentTunnelRequest(OMX_HANDLETYPE compHandle, uint32_t port,
                                                int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                                struct OMX_TUNNELSETUPTYPE *tunnelSetup);
/**
 * @brief The component uses a buffer already allocated by the IL client.
 */
extern int32_t OmxAdapterUseBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer);
/**
 * @brief The component allocate a buffer.
 */
extern int32_t OmxAdapterAllocateBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex,
                                        struct OmxCodecBuffer *omxBuffer);
/**
 * @brief The component free the buffer.
 */
extern int32_t OmxAdapterFreeBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer);
/**
 * @brief Send a filled buffer to the input port of the component.
 */
extern int32_t OmxAdapterEmptyThisBuffer(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer *omxBuffer);
/**
 * @brief Send a empty buffer to the output port of the component.
 */
extern int32_t OmxAdapterFillThisBuffer(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer *omxBuffer);
/**
 * @brief Set the callback.
 */
extern int32_t OmxAdapterSetCallbacks(OMX_HANDLETYPE compHandle, struct CodecCallbackType *omxCallback, int8_t *appData,
                                      uint32_t appDataLen);
/**
 * @brief DeInit the component.
 */
extern int32_t OmxAdapterDeInit(OMX_HANDLETYPE compHandle);
/**
 * @brief The component use the buffer allocated in EGL.
 */
extern int32_t OmxAdapterUseEglImage(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer *buffer, uint32_t portIndex,
                                     int8_t *eglImage, uint32_t eglImageLen);
/**
 * @brief Get the role of the component.
 */
extern int32_t OmxAdapterComponentRoleEnum(OMX_HANDLETYPE compHandle, uint8_t *role, uint32_t roleLen, uint32_t index);

#ifdef __cplusplus
};
#endif

#endif  // CODEC_OMX_ADAPTER_INTERFACE_H