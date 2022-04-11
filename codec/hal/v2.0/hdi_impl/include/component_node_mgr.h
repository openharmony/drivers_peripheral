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
#ifndef COMPONENT_NODE_MGR_H
#define COMPONENT_NODE_MGR_H
#include <OMX_Core.h>
#include <map>
#include <nocopyable.h>

#include "codec_callback_if.h"
#include "codec_types.h"
#include "component_mgr.h"
#include "component_node.h"
namespace OHOS {
namespace Codec {
namespace Omx {
class ComponentNodeMgr : NoCopyable {
public:
    ComponentNodeMgr();
    ~ComponentNodeMgr();

    int32_t CreateComponent(OMX_HANDLETYPE *compHandle, char *compName, int8_t *appData, int32_t appDataSize,
                            struct CodecCallbackType *callbacks);

    int32_t DestoryComponent(OMX_HANDLETYPE compHandle);

    int32_t GetComponentVersion(OMX_HANDLETYPE compHandle, struct CompVerInfo &verInfo);

    int32_t SendCommand(OMX_HANDLETYPE compHandle, enum OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData,
                        uint32_t cmdDataLen);

    int32_t GetParameter(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen);

    int32_t SetParameter(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen);

    int32_t GetConfig(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *config, uint32_t configLen);

    int32_t SetConfig(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *config, uint32_t configLen);

    int32_t GetExtensionIndex(OMX_HANDLETYPE compHandle, const char *parameterName, enum OMX_INDEXTYPE *indexType);

    int32_t GetState(OMX_HANDLETYPE compHandle, enum OMX_STATETYPE *state);

    int32_t ComponentTunnelRequest(OMX_HANDLETYPE compHandle, uint32_t port, int32_t omxHandleTypeTunneledComp,
                                   uint32_t tunneledPort, struct OMX_TUNNELSETUPTYPE *tunnelSetup);

    int32_t UseBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t AllocateBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t FreeBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t EmptyThisBuffer(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer &buffer);

    int32_t FillThisBuffer(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer &buffer);

    int32_t SetCallbacks(OMX_HANDLETYPE compHandle, struct CodecCallbackType *omxCallback, int8_t *appData,
                         uint32_t appDataLen);

    int32_t DeInit(OMX_HANDLETYPE compHandle);

    int32_t UseEglImage(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer &buffer, uint32_t portIndex, int8_t *eglImage,
                        uint32_t eglImageLen);

    int32_t ComponentRoleEnum(OMX_HANDLETYPE compHandle, uint8_t *role, uint32_t roleLen, uint32_t index);

private:
    std::shared_ptr<ComponentMgr> compMgr_;
    std::map<OMX_HANDLETYPE, std::shared_ptr<ComponentNode>> nodeMaps_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif /* COMPONENT_NODE_MGR_H */