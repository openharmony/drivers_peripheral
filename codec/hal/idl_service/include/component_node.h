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
#ifndef COMPONENT_NODE_H
#define COMPONENT_NODE_H
#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_Types.h>
#include <map>
#include <memory>
#include <nocopyable.h>
#include <osal_mem.h>
#include <vector>
#include "icodec_buffer.h"
#include "v1_0/icodec_callback.h"
#include "v1_0/icodec_component.h"
#include "component_mgr.h"
using OHOS::HDI::Codec::V1_0::CompVerInfo;
using OHOS::HDI::Codec::V1_0::ICodecCallback;
using OHOS::HDI::Codec::V1_0::OmxCodecBuffer;
namespace OHOS {
namespace Codec {
namespace Omx {
class ComponentNode : NoCopyable {
public:
    ComponentNode(const sptr<ICodecCallback> &callbacks, int64_t appData, std::shared_ptr<ComponentMgr>& mgr);
    ~ComponentNode();
    int32_t OpenHandle(const std::string& name);
    int32_t GetComponentVersion(CompVerInfo &verInfo);
    int32_t SendCommand(OHOS::HDI::Codec::V1_0::OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData);
    int32_t GetParameter(OMX_INDEXTYPE paramIndex, int8_t *param);
    int32_t SetParameter(OMX_INDEXTYPE paramIndex, const int8_t *param);
    int32_t GetConfig(OMX_INDEXTYPE index, int8_t *config);
    int32_t SetConfig(OMX_INDEXTYPE index, const int8_t *config);
    int32_t GetExtensionIndex(const char *parameterName, uint32_t& index);
    int32_t GetState(OHOS::HDI::Codec::V1_0::OMX_STATETYPE &state);
    int32_t ComponentTunnelRequest(uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                   OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE &tunnelSetup);
    int32_t UseBuffer(uint32_t portIndex, OmxCodecBuffer &buffer);
    int32_t AllocateBuffer(uint32_t portIndex, OmxCodecBuffer &buffer);
    int32_t FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer);
    int32_t EmptyThisBuffer(OmxCodecBuffer &buffer);
    int32_t FillThisBuffer(OmxCodecBuffer &buffer);
    int32_t SetCallbacks(const sptr<ICodecCallback> &callbacks, int64_t appData);
    int32_t UseEglImage(struct OmxCodecBuffer &buffer, uint32_t portIndex, const int8_t *eglImage);
    int32_t ComponentRoleEnum(std::vector<uint8_t> &role, uint32_t index);
    int32_t ComponentDeInit();
    OMX_ERRORTYPE static OnEvent(OMX_HANDLETYPE component, void *appData, OMX_EVENTTYPE event, uint32_t data1,
                                 uint32_t data2, void *eventData);
    OMX_ERRORTYPE static OnEmptyBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer);
    OMX_ERRORTYPE static OnFillBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer);

public:
    static OMX_CALLBACKTYPE callbacks_;  // callbacks

private:
    int32_t OnEvent(OMX_EVENTTYPE event, uint32_t data1, uint32_t data2, void *eventData);
    int32_t OnEmptyBufferDone(OMX_BUFFERHEADERTYPE *buffer);
    int32_t OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer);
    uint32_t GenerateBufferId();
    sptr<ICodecBuffer> GetBufferInfoByHeader(OMX_BUFFERHEADERTYPE *buffer);
    bool GetBufferById(uint32_t bufferId, sptr<ICodecBuffer> &codecBuffer, OMX_BUFFERHEADERTYPE *&bufferHdrType);
    void ReleaseCodecBuffer(struct OmxCodecBuffer &buffer);
private:
    OMX_HANDLETYPE comp_;  // Compnent handle
    sptr<ICodecCallback> omxCallback_;
    int64_t appData_;
    std::map<uint32_t, sptr<ICodecBuffer>> codecBufferMap_;       // Key is buffferID
    std::map<OMX_BUFFERHEADERTYPE *, uint32_t> bufferHeaderMap_;  // Key is omx buffer header type
    uint32_t bufferIdCount_;
    std::shared_ptr<ComponentMgr> mgr_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif /* COMPONENT_NODE_H */