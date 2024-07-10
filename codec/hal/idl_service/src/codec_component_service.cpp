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

#include "codec_component_service.h"
#include <hdf_base.h>
#include <hdf_remote_service.h>
#include <securec.h>
#include <malloc.h>
#include <unistd.h>
#include <hitrace_meter.h>
#include "codec_log_wrapper.h"

#define AUDIO_CODEC_NAME "OMX.audio"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V3_0 {
CodecComponentService::CodecComponentService(const std::shared_ptr<OHOS::Codec::Omx::ComponentNode> &node,
    const std::shared_ptr<OHOS::Codec::Omx::ComponentMgr> mgr, const std::string name)
{
    name_ = name;
    node_ = node;
    mgr_  = mgr;
    isIPCMode_ = (HdfRemoteGetCallingPid() == getpid() ? false : true);
#ifdef SUPPORT_ROLE
    SetComponentRole();
#endif
}
CodecComponentService::~CodecComponentService()
{
    if (node_ != nullptr) {
        node_->ReleaseOMXResource();
        int32_t ret = node_->CloseHandle();
        if (ret != HDF_SUCCESS) {
            CODEC_LOGE("CloseHandle failed, err[%{public}d]", ret);
        }
        node_ = nullptr;
        ReleaseCache();
    }
    name_ = "";
    mgr_ = nullptr;
}

void CodecComponentService::ReleaseCache()
{
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    mallopt(M_FLUSH_THREAD_CACHE, 0);
#endif
}

int32_t CodecComponentService::GetComponentVersion(CompVerInfo &verInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecGetComponentVersion");
    return node_->GetComponentVersion(verInfo);
}

int32_t CodecComponentService::SendCommand(CodecCommandType cmd, uint32_t param, const std::vector<int8_t> &cmdData)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecSendCommand");
    CODEC_LOGI("commandType: [%{public}d], command [%{public}d]", cmd, param);
    return node_->SendCommand(cmd, param, const_cast<int8_t *>(cmdData.data()));
}

int32_t CodecComponentService::GetParameter(uint32_t index, const std::vector<int8_t> &inParamStruct,
                                            std::vector<int8_t> &outParamStruct)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecGetParameter");
    CODEC_LOGD("index [%{public}x]", index);
    outParamStruct = inParamStruct;
    return node_->GetParameter(static_cast<enum OMX_INDEXTYPE>(index), outParamStruct.data());
}

int32_t CodecComponentService::SetParameter(uint32_t index, const std::vector<int8_t> &paramStruct)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecSetParameter");
    CODEC_LOGD("index [%{public}x]", index);
    return node_->SetParameter(static_cast<enum OMX_INDEXTYPE>(index), paramStruct.data());
}

int32_t CodecComponentService::GetConfig(uint32_t index, const std::vector<int8_t> &inCfgStruct,
                                         std::vector<int8_t> &outCfgStruct)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecGetConfig");
    CODEC_LOGD("index [%{public}x]", index);
    outCfgStruct = inCfgStruct;
    return node_->GetConfig(static_cast<enum OMX_INDEXTYPE>(index), outCfgStruct.data());
}

int32_t CodecComponentService::SetConfig(uint32_t index, const std::vector<int8_t> &cfgStruct)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecSetConfig");
    CODEC_LOGD("index [%{public}x]", index);
    return node_->SetConfig(static_cast<enum OMX_INDEXTYPE>(index), cfgStruct.data());
}

int32_t CodecComponentService::GetExtensionIndex(const std::string &paramName, uint32_t &indexType)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecGetExtensionIndex");
    CODEC_LOGI("paramName [%{public}s]", paramName.c_str());
    return node_->GetExtensionIndex(paramName.c_str(), indexType);
}

int32_t CodecComponentService::GetState(CodecStateType &state)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecGetState");
    return node_->GetState(state);
}

int32_t CodecComponentService::ComponentTunnelRequest(uint32_t port, int32_t tunneledComp, uint32_t tunneledPort,
                                                      const CodecTunnelSetupType &inTunnelSetup,
                                                      CodecTunnelSetupType &outTunnelSetup)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecComponentTunnelRequest");
    CODEC_LOGI("port [%{public}d]", port);
    outTunnelSetup = inTunnelSetup;
    return node_->ComponentTunnelRequest(port, tunneledComp, tunneledPort, outTunnelSetup);
}

int32_t CodecComponentService::UseBuffer(uint32_t portIndex, const OmxCodecBuffer &inBuffer, OmxCodecBuffer &outBuffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecUseBuffer");
    CODEC_LOGD("portIndex: [%{public}d]", portIndex);
    outBuffer = const_cast<OmxCodecBuffer &>(inBuffer);

    if (outBuffer.fd >= 0 && isIPCMode_ && outBuffer.bufferType != CODEC_BUFFER_TYPE_AVSHARE_MEM_FD &&
        outBuffer.bufferType != CODEC_BUFFER_TYPE_DMA_MEM_FD &&
        name_.find(AUDIO_CODEC_NAME) == std::string::npos) {
        close(outBuffer.fd);
        outBuffer.fd = -1;
    }
    if (outBuffer.fenceFd >= 0) {
        close(outBuffer.fenceFd);
        outBuffer.fenceFd = -1;
    }

    return node_->UseBuffer(portIndex, outBuffer);
}

int32_t CodecComponentService::AllocateBuffer(uint32_t portIndex, const OmxCodecBuffer &inBuffer,
                                              OmxCodecBuffer &outBuffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecAllocateBuffer");
    CODEC_LOGD("portIndex: [%{public}d]", portIndex);
    outBuffer = inBuffer;
    return node_->AllocateBuffer(portIndex, outBuffer);
}

int32_t CodecComponentService::FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecFreeBuffer");
    OmxCodecBuffer &bufferTemp = const_cast<OmxCodecBuffer &>(buffer);
    CODEC_LOGD("portIndex: [%{public}d], bufferId: [%{public}d]", portIndex, buffer.bufferId);
    int32_t ret = node_->FreeBuffer(portIndex, buffer);
    ReleaseCache();
    if (isIPCMode_ && bufferTemp.fd >= 0) {
        close(bufferTemp.fd);
        bufferTemp.fd = -1;
    }

    return ret;
}

int32_t CodecComponentService::EmptyThisBuffer(const OmxCodecBuffer &buffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecEmptyThisBuffer");
    OmxCodecBuffer &bufferTemp = const_cast<OmxCodecBuffer &>(buffer);
    int32_t ret = node_->EmptyThisBuffer(bufferTemp);
    if (isIPCMode_ && bufferTemp.fd >= 0) {
        close(bufferTemp.fd);
        bufferTemp.fd = -1;
    }

    return ret;
}

int32_t CodecComponentService::FillThisBuffer(const OmxCodecBuffer &buffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecFillThisBuffer");
    OmxCodecBuffer &bufferTemp = const_cast<OmxCodecBuffer &>(buffer);
    int32_t ret = node_->FillThisBuffer(bufferTemp);
    if (isIPCMode_ && bufferTemp.fd >= 0) {
        close(bufferTemp.fd);
        bufferTemp.fd = -1;
    }

    return ret;
}

int32_t CodecComponentService::SetCallbacks(const sptr<ICodecCallback> &callbacks, int64_t appData)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecSetCallbacks");
    CODEC_LOGI("service impl!");
    CHECK_AND_RETURN_RET_LOG(callbacks != nullptr, HDF_ERR_INVALID_PARAM, "callbacks is null");
    return node_->SetCallbacks(callbacks, appData);
}

int32_t CodecComponentService::ComponentDeInit()
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecComponentDeInit");
    CODEC_LOGI("service impl!");
    return node_->ComponentDeInit();
}

int32_t CodecComponentService::UseEglImage(uint32_t portIndex, const OmxCodecBuffer &inBuffer,
                                           OmxCodecBuffer &outBuffer, const std::vector<int8_t> &eglImage)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecUseEglImage");
    CODEC_LOGI("portIndex [%{public}d]", portIndex);
    outBuffer = inBuffer;
    return node_->UseEglImage(outBuffer, portIndex, eglImage.data());
}

int32_t CodecComponentService::ComponentRoleEnum(std::vector<uint8_t> &role, uint32_t index)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecComponentRoleEnum");
    CODEC_LOGI("index [%{public}d]", index);
    return node_->ComponentRoleEnum(role, index);
}

void CodecComponentService::SetComponentRole()
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecSetComponentRole");
    if (name_ == "") {
        CODEC_LOGE("compName is null");
        return;
    }
    OHOS::Codec::Omx::CodecOMXCore *core;
    auto err = mgr_->GetCoreOfComponent(core, name_);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("core is null");
        return;
    }

    std::vector<std::string> roles;
    int32_t ret = core->GetRolesOfComponent(name_, roles);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("GetRoleOfComponent return err [%{public}d]", ret);
        return;
    }
    uint32_t roleIndex = 0;
    CODEC_LOGI("RoleName = [%{public}s]", roles[roleIndex].c_str());

    OMX_PARAM_COMPONENTROLETYPE role;
    errno_t res = strncpy_s(reinterpret_cast<char *>(role.cRole), OMX_MAX_STRINGNAME_SIZE,
                            roles[roleIndex].c_str(), roles[roleIndex].length());
    if (res != EOK) {
        CODEC_LOGE("strncpy_s return err [%{public}d]", err);
        return;
    }
    role.nSize = sizeof(role);
    ret = node_->SetParameter(OMX_IndexParamStandardComponentRole, reinterpret_cast<int8_t *>(&role));
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("OMX_IndexParamStandardComponentRole err [%{public}d]", ret);
    }
}

int32_t CodecComponentService::SetParameterWithBuffer(uint32_t index, const std::vector<int8_t>& paramStruct,
                                                      const OmxCodecBuffer& inBuffer)
{
    return OMX_ErrorNotImplemented;
}

const std::string &CodecComponentService::GetComponentCompName() const
{
    return name_;
}

void CodecComponentService::GetComponentNode(std::shared_ptr<OHOS::Codec::Omx::ComponentNode> &dumpNode_)
{
    dumpNode_ = node_;
}

}  // namespace V3_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS
