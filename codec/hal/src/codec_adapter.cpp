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

#include "codec_adapter_interface.h"
#include "component_node_mgr.h"
using namespace OHOS::Codec::Omx;

static ComponentNodeMgr g_mgr;
#ifdef __cplusplus
extern "C" {
#endif

int32_t OMXAdapterCreateComponent(OMX_HANDLETYPE *compHandle, char *compName, int8_t *appData, int32_t appDataSize,
                                  struct CodecCallbackType *callbacks)
{
    return g_mgr.CreateComponent(compHandle, compName, appData, appDataSize, callbacks);
}

int32_t OmxAdapterDestoryComponent(OMX_HANDLETYPE compHandle)
{
    return g_mgr.DestoryComponent(compHandle);
}

int32_t OmxAdapterComponentVersion(OMX_HANDLETYPE compHandle, struct CompVerInfo *verInfo)
{
    return g_mgr.GetComponentVersion(compHandle, *verInfo);
}

int32_t OmxAdapterSendCommand(OMX_HANDLETYPE compHandle, enum OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData,
                              uint32_t cmdDataLen)
{
    return g_mgr.SendCommand(compHandle, cmd, param, cmdData, cmdDataLen);
}

int32_t OmxAdapterGetParameter(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE paramIndex, int8_t *param,
                               uint32_t paramLen)
{
    return g_mgr.GetParameter(compHandle, paramIndex, param, paramLen);
}

int32_t OmxAdapterSetParameter(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *param, uint32_t paramLen)
{
    return g_mgr.SetParameter(compHandle, index, param, paramLen);
}

int32_t OmxAdapterGetConfig(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    return g_mgr.GetConfig(compHandle, index, config, configLen);
}

int32_t OmxAdapterSetConfig(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    return g_mgr.SetConfig(compHandle, index, config, configLen);
}

int32_t OmxAdapterGetExtensionIndex(OMX_HANDLETYPE compHandle, const char *parameterName, enum OMX_INDEXTYPE *indexType)
{
    return g_mgr.GetExtensionIndex(compHandle, parameterName, indexType);
}

int32_t OmxAdapterGetState(OMX_HANDLETYPE compHandle, enum OMX_STATETYPE *state)
{
    return g_mgr.GetState(compHandle, state);
}

int32_t OmxAdapterComponentTunnelRequest(OMX_HANDLETYPE compHandle, uint32_t port, int32_t omxHandleTypeTunneledComp,
                                         uint32_t tunneledPort, struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    return g_mgr.ComponentTunnelRequest(compHandle, port, omxHandleTypeTunneledComp, tunneledPort, tunnelSetup);
}

int32_t OmxAdapterUseBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    return g_mgr.UseBuffer(compHandle, portIndex, *omxBuffer);
}

int32_t OmxAdapterAllocateBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    return g_mgr.AllocateBuffer(compHandle, portIndex, *omxBuffer);
}

int32_t OmxAdapterFreeBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    return g_mgr.FreeBuffer(compHandle, portIndex, *omxBuffer);
}

int32_t OmxAdapterEmptyThisBuffer(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer *omxBuffer)
{
    return g_mgr.EmptyThisBuffer(compHandle, *omxBuffer);
}

int32_t OmxAdapterFillThisBuffer(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer *omxBuffer)
{
    return g_mgr.FillThisBuffer(compHandle, *omxBuffer);
}

int32_t OmxAdapterSetCallbacks(OMX_HANDLETYPE compHandle, struct CodecCallbackType *omxCallback, int8_t *appData,
                               uint32_t appDataLen)
{
    return g_mgr.SetCallbacks(compHandle, omxCallback, appData, appDataLen);
}

int32_t OmxAdapterDeInit(OMX_HANDLETYPE compHandle)
{
    return g_mgr.DeInit(compHandle);
}

int32_t OmxAdapterUseEglImage(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer *buffer, uint32_t portIndex,
                              int8_t *eglImage, uint32_t eglImageLen)
{
    return g_mgr.UseEglImage(compHandle, *buffer, portIndex, eglImage, eglImageLen);
}

int32_t OmxAdapterComponentRoleEnum(OMX_HANDLETYPE compHandle, uint8_t *role, uint32_t roleLen, uint32_t index)
{
    return g_mgr.ComponentRoleEnum(compHandle, role, roleLen, index);
}
#ifdef __cplusplus
};
#endif
