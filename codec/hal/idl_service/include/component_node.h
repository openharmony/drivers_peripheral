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
#ifndef COMPONENT_NODE_H
#define COMPONENT_NODE_H
#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_Types.h>
#include <map>
#include <memory>
#include <shared_mutex>
#include <nocopyable.h>
#include <osal_mem.h>
#include <vector>
#include "icodec_buffer.h"
#include "v3_0/icodec_callback.h"
#include "v3_0/icodec_component.h"
#include "component_mgr.h"
using OHOS::HDI::Codec::V3_0::CompVerInfo;
using OHOS::HDI::Codec::V3_0::ICodecCallback;
using OHOS::HDI::Codec::V3_0::CodecStateType;
namespace OHOS {
namespace Codec {
namespace Omx {
class ComponentNode : NoCopyable {
public:
    ComponentNode(const sptr<ICodecCallback> &callbacks, int64_t appData, std::shared_ptr<ComponentMgr>& mgr);
    ~ComponentNode();
    int32_t OpenHandle(const std::string& name);
    int32_t CloseHandle();
    int32_t GetComponentVersion(CompVerInfo &verInfo);
    int32_t SendCommand(HDI::Codec::V3_0::CodecCommandType cmd, uint32_t param, int8_t *cmdData);
    int32_t GetParameter(OMX_INDEXTYPE paramIndex, int8_t *param);
    int32_t SetParameter(OMX_INDEXTYPE paramIndex, const int8_t *param);
    int32_t SetParameterWithBuffer(int32_t index, const std::vector<int8_t>& paramStruct,
            const OmxCodecBuffer& inBuffer);
    int32_t GetConfig(OMX_INDEXTYPE index, int8_t *config);
    int32_t SetConfig(OMX_INDEXTYPE index, const int8_t *config);
    int32_t GetExtensionIndex(const char *parameterName, uint32_t& index);
    int32_t GetState(HDI::Codec::V3_0::CodecStateType &state);
    int32_t ComponentTunnelRequest(uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                   OHOS::HDI::Codec::V3_0::CodecTunnelSetupType &tunnelSetup);
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
    void ReleaseOMXResource();
    void GetBuffCount(uint32_t &inputBuffCount, uint32_t &outputBuffCount);

public:
    static OMX_CALLBACKTYPE callbacks_;  // callbacks

private:
    int32_t OnEvent(HDI::Codec::V3_0::CodecEventType event, uint32_t data1, uint32_t data2, void *eventData);
    int32_t OnEmptyBufferDone(OMX_BUFFERHEADERTYPE *buffer);
    int32_t OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer);
    int32_t UseBufferByType(uint32_t portIndex, OmxCodecBuffer &buffer,
        sptr<ICodecBuffer> codecBuffer, OMX_BUFFERHEADERTYPE *&bufferHdrType);
    uint32_t GenerateBufferId();
    sptr<ICodecBuffer> GetBufferInfoByHeader(OMX_BUFFERHEADERTYPE *buffer);
    bool GetBufferById(uint32_t bufferId, sptr<ICodecBuffer> &codecBuffer, OMX_BUFFERHEADERTYPE *&bufferHdrType);
    void ReleaseCodecBuffer(struct OmxCodecBuffer &buffer);
    void WaitStateChange(CodecStateType objState, CodecStateType &status);
    int32_t ReleaseAllBuffer();
private:
    OMX_HANDLETYPE comp_;  // Compnent handle
    sptr<ICodecCallback> omxCallback_;
    int64_t appData_;
    std::map<uint32_t, sptr<ICodecBuffer>> codecBufferMap_;       // Key is buffferID
    std::map<OMX_BUFFERHEADERTYPE *, uint32_t> portIndexMap_;
    std::map<OMX_BUFFERHEADERTYPE *, uint32_t> bufferHeaderMap_;  // Key is omx buffer header type
    std::map<OMX_BUFFERHEADERTYPE *, uint32_t> bufferHeaderPortMap_;
    std::vector<std::pair<void *, uint32_t>> audioBuffer_;
    uint32_t bufferIdCount_;
    std::shared_ptr<ComponentMgr> mgr_;
    uint32_t maxStateWaitTime = 10000;
    uint32_t maxStateWaitCount = 100;
    std::shared_mutex mapMutex_;
    std::string compName_;
    bool isIPCMode_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif /* COMPONENT_NODE_H */