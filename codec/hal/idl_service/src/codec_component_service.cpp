/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd.
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

#include "codec_component_service.h"
#include <hdf_base.h>
#include "codec_log_wrapper.h"
namespace OHOS {
namespace HDI {
namespace Codec {
namespace V1_0 {
int32_t CodecComponentService::GetComponentVersion(CompVerInfo &verInfo)
{
    return node_->GetComponentVersion(verInfo);
}

int32_t CodecComponentService::SendCommand(OMX_COMMANDTYPE cmd, uint32_t param, const std::vector<int8_t> &cmdData)
{
    CODEC_LOGD("cmd [%{public}d]", cmd);
    return node_->SendCommand(cmd, param, const_cast<int8_t *>(cmdData.data()));
}

int32_t CodecComponentService::GetParameter(uint32_t index, const std::vector<int8_t> &inParamStruct,
                                            std::vector<int8_t> &outParamStruct)
{
    CODEC_LOGD("index [%{public}d]", index);
    outParamStruct = inParamStruct;
    return node_->GetParameter(static_cast<enum OMX_INDEXTYPE>(index), outParamStruct.data());
}

int32_t CodecComponentService::SetParameter(uint32_t index, const std::vector<int8_t> &paramStruct)
{
    CODEC_LOGD("index [%{public}d]", index);
    return node_->SetParameter(static_cast<enum OMX_INDEXTYPE>(index), paramStruct.data());
}

int32_t CodecComponentService::GetConfig(uint32_t index, const std::vector<int8_t> &inCfgStruct,
                                         std::vector<int8_t> &outCfgStruct)
{
    CODEC_LOGD("index [%{public}d]", index);
    outCfgStruct = inCfgStruct;
    return node_->GetConfig(static_cast<enum OMX_INDEXTYPE>(index), outCfgStruct.data());
}

int32_t CodecComponentService::SetConfig(uint32_t index, const std::vector<int8_t> &cfgStruct)
{
    CODEC_LOGD("index [%{public}d]", index);
    return node_->SetConfig(static_cast<enum OMX_INDEXTYPE>(index), cfgStruct.data());
}

int32_t CodecComponentService::GetExtensionIndex(const std::string &paramName, uint32_t &indexType)
{
    CODEC_LOGD("paramName [%{public}s]", paramName.c_str());
    return node_->GetExtensionIndex(paramName.c_str(), indexType);
}

int32_t CodecComponentService::GetState(OMX_STATETYPE &state)
{
    return node_->GetState(state);
}

int32_t CodecComponentService::ComponentTunnelRequest(uint32_t port, int32_t tunneledComp, uint32_t tunneledPort,
                                                      const OMX_TUNNELSETUPTYPE &inTunnelSetup,
                                                      OMX_TUNNELSETUPTYPE &outTunnelSetup)
{
    CODEC_LOGD("port [%{public}d]", port);
    outTunnelSetup = inTunnelSetup;
    return node_->ComponentTunnelRequest(port, tunneledComp, tunneledPort, outTunnelSetup);
}

int32_t CodecComponentService::UseBuffer(uint32_t portIndex, const OmxCodecBuffer &inBuffer, OmxCodecBuffer &outBuffer)
{
    CODEC_LOGD("portIndex [%{public}d]", portIndex);
    outBuffer = inBuffer;
    return node_->UseBuffer(portIndex, outBuffer);
}

int32_t CodecComponentService::AllocateBuffer(uint32_t portIndex, const OmxCodecBuffer &inBuffer,
                                              OmxCodecBuffer &outBuffer)
{
    CODEC_LOGD("portIndex [%{public}d]", portIndex);
    outBuffer = inBuffer;
    return node_->AllocateBuffer(portIndex, outBuffer);
}

int32_t CodecComponentService::FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer)
{
    CODEC_LOGD("portIndex [%{public}d]", portIndex);
    return node_->FreeBuffer(portIndex, buffer);
}

int32_t CodecComponentService::EmptyThisBuffer(const OmxCodecBuffer &buffer)
{
    return node_->EmptyThisBuffer(const_cast<OmxCodecBuffer &>(buffer));
}

int32_t CodecComponentService::FillThisBuffer(const OmxCodecBuffer &buffer)
{
    return node_->FillThisBuffer(const_cast<OmxCodecBuffer &>(buffer));
}

int32_t CodecComponentService::SetCallbacks(const sptr<ICodecCallback> &callbacks, int64_t appData)
{
    return node_->SetCallbacks(callbacks, appData);
}

int32_t CodecComponentService::ComponentDeInit()
{
    return node_->ComponentDeInit();
}

int32_t CodecComponentService::UseEglImage(uint32_t portIndex, const OmxCodecBuffer &inBuffer,
                                           OmxCodecBuffer &outBuffer, const std::vector<int8_t> &eglImage)
{
    CODEC_LOGD("portIndex [%{public}d]", portIndex);
    outBuffer = inBuffer;
    return node_->UseEglImage(outBuffer, portIndex, eglImage.data());
}

int32_t CodecComponentService::ComponentRoleEnum(std::vector<uint8_t> &role, uint32_t index)
{
    CODEC_LOGD("index [%{public}d]", index);
    return node_->ComponentRoleEnum(role, index);
}
}  // namespace V1_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS
