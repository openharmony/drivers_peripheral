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
#include <string>

#include "icodec_buffer.h"
#include "codec_callback_if.h"
#include "codec_component_type.h"

namespace OHOS {
namespace Codec {
namespace Omx {
class ComponentNode : NoCopyable {
public:
    ComponentNode(struct CodecCallbackType *callback, int64_t appData, const std::string &compName);

    ~ComponentNode() override;

    int32_t GetComponentVersion(struct CompVerInfo &verInfo);

    int32_t SendCommand(OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen);

    int32_t GetParameter(OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen);

    int32_t SetParameter(OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen);

    int32_t GetConfig(OMX_INDEXTYPE index, int8_t *config, uint32_t configLen);

    int32_t SetConfig(OMX_INDEXTYPE index, int8_t *config, uint32_t configLen);

    int32_t GetExtensionIndex(const char *parameterName, OMX_INDEXTYPE *indexType);

    int32_t GetState(OMX_STATETYPE *state);

    int32_t ComponentTunnelRequest(uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                   struct OMX_TUNNELSETUPTYPE *tunnelSetup);

    int32_t UseBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t AllocateBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t FreeBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t EmptyThisBuffer(struct OmxCodecBuffer &buffer);

    int32_t FillThisBuffer(struct OmxCodecBuffer &buffer);

    int32_t SetCallbacks(struct CodecCallbackType *omxCallback, int64_t appData);

    int32_t UseEglImage(struct OmxCodecBuffer &buffer, uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen);

    int32_t ComponentRoleEnum(uint8_t *role, uint32_t roleLen, uint32_t index);

    int32_t DeInit();

    static OMX_ERRORTYPE OnEvent(OMX_HANDLETYPE component, void *appData, OMX_EVENTTYPE event, uint32_t data1,
                                 uint32_t data2, void *eventData);

    static OMX_ERRORTYPE OnEmptyBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer);

    static OMX_ERRORTYPE OnFillBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer);

    void SetHandle(OMX_HANDLETYPE comp)
    {
        this->comp_ = comp;
    }

    OMX_HANDLETYPE GetHandle()
    {
        return comp_;
    }

    uint32_t GetBufferCount()
    {
        return codecBufferMap_.size();
    }

    std::string GetCompName()
    {
        return name_;
    }

    void WaitStateChange(uint32_t objState, OMX_STATETYPE *status);

    void ReleaseOMXResource();

    int32_t ReleaseAllBuffer();

public:
    static OMX_CALLBACKTYPE callbacks_;  // callbacks

private:
    int32_t OnEvent(OMX_EVENTTYPE event, uint32_t data1, uint32_t data2, void *eventData);

    int32_t OnEmptyBufferDone(OMX_BUFFERHEADERTYPE *buffer);

    int32_t OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer);

    uint32_t GenerateBufferId();
    sptr<ICodecBuffer> GetBufferInfoByHeader(OMX_BUFFERHEADERTYPE *buffer);
    bool GetBufferById(uint32_t bufferId, sptr<ICodecBuffer> &codecBuffer, OMX_BUFFERHEADERTYPE *&bufferHdrType);

private:
    OMX_HANDLETYPE comp_;                                         // Component handle
    struct CodecCallbackType *omxCallback_;                       // Callbacks in HDI
    int64_t appData_;                                             // Use data, default is 0
    std::map<uint32_t, sptr<ICodecBuffer>> codecBufferMap_;       // Key is buffferID
    std::map<OMX_BUFFERHEADERTYPE *, uint32_t> bufferHeaderMap_;  // Key is omx buffer header type
    uint32_t bufferIdCount_;
    std::string name_;
    std::map<OMX_BUFFERHEADERTYPE *, uint32_t> bufferHeaderPortMap_;
    uint32_t maxStateWaitTime = 10000;
    uint32_t maxStateWaitCount = 100;
    std::shared_mutex mapMutex_;
    std::shared_mutex callbackMutex_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif /* COMPONENT_NODE_H */