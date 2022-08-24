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
#ifndef COMPONENT_NODE_H
#define COMPONENT_NODE_H
#include <nocopyable.h>
#include <OMX_Component.h>
#include "codec_callback_if.h"
#include "codec_capability_parser.h"
#include "codec_component_type.h"
#include "codec_type.h"

namespace OHOS {
namespace Codec {
namespace CodecAdapter {
class ComponentNode : public NoCopyable {
public:
    explicit ComponentNode(CODEC_HANDLETYPE handle, CodecExInfo info);
    ~ComponentNode() {}
    int32_t GetComponentVersion(CompVerInfo &verInfo);
    int32_t SendCommand(OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen);
    int32_t GetParameter(OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen);
    int32_t SetParameter(OMX_INDEXTYPE paramIndex, const int8_t *param, uint32_t paramLen);
    int32_t GetConfig(OMX_INDEXTYPE index, int8_t *config, uint32_t configLen);
    int32_t SetConfig(OMX_INDEXTYPE index, const int8_t *config, uint32_t configLen);
    int32_t GetExtensionIndex(const char *parameterName, OMX_INDEXTYPE *indexType);
    int32_t GetState(OMX_STATETYPE *state);
    int32_t ComponentTunnelRequest(
        uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort, OMX_TUNNELSETUPTYPE *tunnelSetup);
    int32_t UseBuffer(uint32_t portIndex, OmxCodecBuffer &buffer);
    int32_t AllocateBuffer(uint32_t portIndex, OmxCodecBuffer &buffer);
    int32_t FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer);
    int32_t EmptyThisBuffer(const OmxCodecBuffer &buffer);
    int32_t FillThisBuffer(const OmxCodecBuffer &buffer);
    int32_t SetCallbacks(const CodecCallbackType *omxCallback, int64_t appData);
    int32_t UseEglImage(OmxCodecBuffer &buffer, uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen);
    int32_t ComponentRoleEnum(uint8_t *role, uint32_t roleLen, uint32_t index);
    int32_t ComponentDeInit();
    int32_t static OnEvent(UINTPTR userData, EventType event, uint32_t length, int32_t eventData[]);
    int32_t static InputBufferAvailable(UINTPTR userData, CodecBuffer *inBuf, int32_t *acquireFd);
    int32_t static OutputBufferAvailable(UINTPTR userData, CodecBuffer *outBuf, int32_t *acquireFd);
    int32_t SetState(OMX_STATETYPE state);
    CODEC_HANDLETYPE GetHandle()
    {
        return comp_;
    }

public:
    static CodecCallback callbacks_;

private:
    int32_t SetPortMode(uint32_t portIndex, OmxCodecBuffer &buffer, AllocateBufferMode mode);
    int32_t ChangeComponentState(uint32_t param);
    int32_t FlushComponent(uint32_t param);
    int32_t OnEvent(EventType event, uint32_t length, int32_t eventData[]);
    int32_t OnEmptyBufferDone(CodecBuffer *inBuf, int32_t *acquireFd);
    int32_t OnFillBufferDone(CodecBuffer *outBuf, int32_t *acquireFd);

private:
    CODEC_HANDLETYPE comp_;          // Compnent handle
    CodecCallbackType *omxCallback_; // Callbacks in HDI
    CodecExInfo exInfo_;
    int64_t appData_;
    uint32_t bufferId_;
    bool setCallbackComplete_;
    OMX_STATETYPE state_;
    CodecType codecType_;
    AllocateBufferMode inputMode_;
    AllocateBufferMode outputMode_;
};
}  // namespace CodecAdapter
}  // namespace Codec
}  // namespace OHOS
#endif /* COMPONENT_NODE_H */
