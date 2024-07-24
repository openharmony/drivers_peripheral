/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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

#ifndef OHOS_HDI_CODEC_V3_0_CODECCOMPONENTSERVICE_H
#define OHOS_HDI_CODEC_V3_0_CODECCOMPONENTSERVICE_H

#include "component_node.h"
#include "v3_0/icodec_component.h"
#include "v1_0/imapper.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V3_0 {
class CodecComponentService : public ICodecComponent {
public:
    CodecComponentService(const std::shared_ptr<OHOS::Codec::Omx::ComponentNode> &node,
                          const std::shared_ptr<OHOS::Codec::Omx::ComponentMgr> mgr, const std::string name);
    virtual ~CodecComponentService();
    int32_t GetComponentVersion(CompVerInfo &verInfo) override;
    int32_t SendCommand(CodecCommandType cmd, uint32_t param, const std::vector<int8_t> &cmdData) override;
    int32_t GetParameter(uint32_t index, const std::vector<int8_t> &inParamStruct,
                         std::vector<int8_t> &outParamStruct) override;
    int32_t SetParameter(uint32_t index, const std::vector<int8_t> &paramStruct) override;
    int32_t GetConfig(uint32_t index, const std::vector<int8_t> &inCfgStruct,
                      std::vector<int8_t> &outCfgStruct) override;
    int32_t SetConfig(uint32_t index, const std::vector<int8_t> &cfgStruct) override;
    int32_t GetExtensionIndex(const std::string &paramName, uint32_t &indexType) override;
    int32_t GetState(CodecStateType &state) override;
    int32_t ComponentTunnelRequest(uint32_t port, int32_t tunneledComp, uint32_t tunneledPort,
                                   const CodecTunnelSetupType &inTunnelSetup,
                                   CodecTunnelSetupType &outTunnelSetup) override;
    int32_t UseBuffer(uint32_t portIndex, const OmxCodecBuffer &inBuffer, OmxCodecBuffer &outBuffer) override;
    int32_t AllocateBuffer(uint32_t portIndex, const OmxCodecBuffer &inBuffer, OmxCodecBuffer &outBuffer) override;
    int32_t FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer) override;
    int32_t EmptyThisBuffer(const OmxCodecBuffer &buffer) override;
    int32_t FillThisBuffer(const OmxCodecBuffer &buffer) override;
    int32_t SetCallbacks(const sptr<ICodecCallback> &callbacks, int64_t appData) override;
    int32_t ComponentDeInit() override;
    int32_t UseEglImage(uint32_t portIndex, const OmxCodecBuffer &inBuffer, OmxCodecBuffer &outBuffer,
                        const std::vector<int8_t> &eglImage) override;
    int32_t ComponentRoleEnum(std::vector<uint8_t> &role, uint32_t index) override;
    int32_t SetParameterWithBuffer(uint32_t index, const std::vector<int8_t>& paramStruct,
                                   const OmxCodecBuffer& inBuffer) override;

    const std::string &GetComponentCompName() const;
    void GetComponentNode(std::shared_ptr<OHOS::Codec::Omx::ComponentNode> &dumpNode_);
private:
    void SetComponentRole();
    void ReleaseCache();
    bool isIPCMode_;
    std::string name_;
    std::shared_ptr<OHOS::Codec::Omx::ComponentNode> node_;
    std::shared_ptr<OHOS::Codec::Omx::ComponentMgr> mgr_;
};

sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> GetMapperService();

}  // namespace V3_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS

#endif  // OHOS_HDI_CODEC_V3_0_CODECCOMPONENTSERVICE_H