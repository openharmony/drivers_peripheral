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
#include <ashmem.h>
#include <map>
#include <memory>
#include <nocopyable.h>
#include <osal_mem.h>

#include "codec_callback_if.h"
#include "codec_component_type.h"

struct BufferInfo {
    struct OmxCodecBuffer omxCodecBuffer;
    std::shared_ptr<OHOS::Ashmem> sharedMem;  // sharedMem

    BufferInfo()
    {
        omxCodecBuffer = {0};
        sharedMem = nullptr;
    }
    ~BufferInfo()
    {
        if (sharedMem) {
            sharedMem->UnmapAshmem();
            sharedMem->CloseAshmem();
            sharedMem = nullptr;
        }
    }
};
using BufferInfo = struct BufferInfo;
using BufferInfoSPtr = std::shared_ptr<BufferInfo>;
using BufferInfoWPtr = std::weak_ptr<BufferInfo>;
namespace OHOS {
namespace Codec {
namespace Omx {
class ComponentNode : NoCopyable {
public:
    ComponentNode(struct CodecCallbackType *callback, int8_t *appData, int32_t appDataLen);

    ~ComponentNode();

    int32_t GetComponentVersion(struct CompVerInfo &verInfo);

    int32_t SendCommand(enum OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen);

    int32_t GetParameter(enum OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen);

    int32_t SetParameter(enum OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen);

    int32_t GetConfig(enum OMX_INDEXTYPE index, int8_t *config, uint32_t configLen);

    int32_t SetConfig(enum OMX_INDEXTYPE index, int8_t *config, uint32_t configLen);

    int32_t GetExtensionIndex(const char *parameterName, enum OMX_INDEXTYPE *indexType);

    int32_t GetState(enum OMX_STATETYPE *state);

    int32_t ComponentTunnelRequest(uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                   struct OMX_TUNNELSETUPTYPE *tunnelSetup);

    int32_t UseBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t AllocateBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t FreeBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer);

    int32_t EmptyThisBuffer(struct OmxCodecBuffer &buffer);

    int32_t FillThisBuffer(struct OmxCodecBuffer &buffer);

    int32_t SetCallbacks(struct CodecCallbackType *omxCallback, int8_t *appData, uint32_t appDataLen);

    int32_t UseEglImage(struct OmxCodecBuffer &buffer, uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen);

    int32_t ComponentRoleEnum(uint8_t *role, uint32_t roleLen, uint32_t index);

    int32_t DeInit();

    OMX_ERRORTYPE static OnEvent(OMX_HANDLETYPE component, void *appData, OMX_EVENTTYPE event, uint32_t data1,
                                 uint32_t data2, void *eventData);

    OMX_ERRORTYPE static OnEmptyBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer);

    OMX_ERRORTYPE static OnFillBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer);

    void SetHandle(OMX_HANDLETYPE comp)
    {
        this->comp_ = comp;
    }

public:
    static OMX_CALLBACKTYPE callbacks_;  // callbacks

private:
    int32_t OnEvent(OMX_EVENTTYPE event, uint32_t data1, uint32_t data2, void *eventData);

    int32_t OnEmptyBufferDone(OMX_BUFFERHEADERTYPE *buffer);

    int32_t OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer);

    uint32_t GenerateBufferId();

    void inline CheckBuffer(struct OmxCodecBuffer &buffer);

    BufferInfoSPtr GetBufferInfoByHeader(OMX_BUFFERHEADERTYPE *buffer);

    bool GetBufferById(uint32_t bufferId, BufferInfoSPtr &bufferInfo, OMX_BUFFERHEADERTYPE *&bufferHdrType);

    void ReleaseBufferById(uint32_t bufferId);

    int32_t UseSharedBuffer(struct OmxCodecBuffer &omxCodecBuffer, uint32_t portIndex);

    int32_t UseHandleBuffer(struct OmxCodecBuffer &omxCodecBuffer, uint32_t portIndex);

    int32_t UseDynaHandleBuffer(struct OmxCodecBuffer &omxCodecBuffer, uint32_t portIndex);

    int32_t EmptySharedBuffer(struct OmxCodecBuffer &buffer, BufferInfoSPtr bufferInfo,
                              OMX_BUFFERHEADERTYPE *bufferHdrType);

    void SaveBufferInfo(struct OmxCodecBuffer &omxCodecBuffer, OMX_BUFFERHEADERTYPE *bufferHdrType,
                        std::shared_ptr<Ashmem> sharedMem);

private:
    OMX_HANDLETYPE comp_;                                         // Compnent handle
    struct CodecCallbackType *omxCallback_;                       // Callbacks in HDI
    int8_t *appData_;                                             // Use data, default is nullptr
    int32_t appDataSize_;                                         // User data length, default is 0
    std::map<uint32_t, BufferInfoSPtr> bufferInfoMap_;            // Key is buffferID
    std::map<OMX_BUFFERHEADERTYPE *, uint32_t> bufferHeaderMap_;  // Key is omx buffer header type

    uint32_t bufferIdCount_;

#ifdef NODE_DEBUG
    FILE *fp_in;
    FILE *fp_out;
#endif
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif /* COMPONENT_NODE_H */