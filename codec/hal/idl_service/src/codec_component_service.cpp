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
#include "codec_log_wrapper.h"
namespace OHOS {
namespace HDI {
namespace Codec {
namespace V1_0 {
CodecComponentService::CodecComponentService(const std::shared_ptr<OHOS::Codec::Omx::ComponentNode> &node,
    const std::shared_ptr<OHOS::Codec::Omx::ComponentMgr> mgr, const std::string name)
{
    name_ = name;
    node_ = node;
    mgr_  = mgr;
    pid_t remotePid = HdfRemoteGetCallingPid();
    isIPCMode_ = remotePid != getpid();
#ifdef SUPPORT_ROLE
    SetComponentRole();
#endif
}
CodecComponentService::~CodecComponentService()
{
    if (node_ != nullptr) {
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
    auto err = mallopt(M_FLUSH_THREAD_CACHE, 0);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("release cache error, m_purge = %{public}d", err);
    }
#endif
}

int32_t CodecComponentService::GetComponentVersion(CompVerInfo &verInfo)
{
    return node_->GetComponentVersion(verInfo);
}

int32_t CodecComponentService::SendCommand(CodecCommandType cmd, uint32_t param, const std::vector<int8_t> &cmdData)
{
    CODEC_LOGI("commandType: [%{public}d], command [%{public}d]", cmd, param);
    return node_->SendCommand(cmd, param, const_cast<int8_t *>(cmdData.data()));
}

int32_t CodecComponentService::GetParameter(uint32_t index, const std::vector<int8_t> &inParamStruct,
                                            std::vector<int8_t> &outParamStruct)
{
    CODEC_LOGI("index [%{public}x]", index);
    outParamStruct = inParamStruct;
    return node_->GetParameter(static_cast<enum OMX_INDEXTYPE>(index), outParamStruct.data());
}

int32_t CodecComponentService::SetParameter(uint32_t index, const std::vector<int8_t> &paramStruct)
{
    CODEC_LOGI("index [%{public}x]", index);
    return node_->SetParameter(static_cast<enum OMX_INDEXTYPE>(index), paramStruct.data());
}

int32_t CodecComponentService::GetConfig(uint32_t index, const std::vector<int8_t> &inCfgStruct,
                                         std::vector<int8_t> &outCfgStruct)
{
    CODEC_LOGI("index [%{public}x]", index);
    outCfgStruct = inCfgStruct;
    return node_->GetConfig(static_cast<enum OMX_INDEXTYPE>(index), outCfgStruct.data());
}

int32_t CodecComponentService::SetConfig(uint32_t index, const std::vector<int8_t> &cfgStruct)
{
    CODEC_LOGI("index [%{public}x]", index);
    return node_->SetConfig(static_cast<enum OMX_INDEXTYPE>(index), cfgStruct.data());
}

int32_t CodecComponentService::GetExtensionIndex(const std::string &paramName, uint32_t &indexType)
{
    CODEC_LOGI("paramName [%{public}s]", paramName.c_str());
    return node_->GetExtensionIndex(paramName.c_str(), indexType);
}

int32_t CodecComponentService::GetState(CodecStateType &state)
{
    return node_->GetState(state);
}

int32_t CodecComponentService::ComponentTunnelRequest(uint32_t port, int32_t tunneledComp, uint32_t tunneledPort,
                                                      const CodecTunnelSetupType &inTunnelSetup,
                                                      CodecTunnelSetupType &outTunnelSetup)
{
    CODEC_LOGI("port [%{public}d]", port);
    outTunnelSetup = inTunnelSetup;
    return node_->ComponentTunnelRequest(port, tunneledComp, tunneledPort, outTunnelSetup);
}

int32_t CodecComponentService::UseBuffer(uint32_t portIndex, const OmxCodecBuffer &inBuffer, OmxCodecBuffer &outBuffer)
{
    CODEC_LOGI("portIndex: [%{public}d]", portIndex);
    int32_t ret;
    outBuffer = inBuffer;
    if (!isIPCMode_ && codecBuffer.bufferType) {
        outBuffer.fd = dup(inBuffer.fd);
    }

    ret = node_->UseBuffer(portIndex, outBuffer);
    if (isIPCMode_ && inBuffer.fd >= 0) {
        close(inBuffer.fd);
    }

    return ret;
}

int32_t CodecComponentService::AllocateBuffer(uint32_t portIndex, const OmxCodecBuffer &inBuffer,
                                              OmxCodecBuffer &outBuffer)
{
    CODEC_LOGI("portIndex: [%{public}d]", portIndex);
    outBuffer = inBuffer;
    return node_->AllocateBuffer(portIndex, outBuffer);
}

int32_t CodecComponentService::FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer)
{
    CODEC_LOGI("portIndex: [%{public}d], bufferId: [%{public}d]", portIndex, buffer.bufferId);
    int32_t ret = node_->FreeBuffer(portIndex, buffer);
    ReleaseCache();
    if (isIPCMode_ && buffer.fd >= 0) {
        close(buffer.fd);
    }

    return ret;
}

int32_t CodecComponentService::EmptyThisBuffer(const OmxCodecBuffer &buffer)
{
    int32_t ret = node_->EmptyThisBuffer(const_cast<OmxCodecBuffer &>(buffer));
    if (isIPCMode_ && buffer.fd >= 0) {
        close(buffer.fd);
    }

    return ret;
}

int32_t CodecComponentService::FillThisBuffer(const OmxCodecBuffer &buffer)
{
    int32_t ret = node_->FillThisBuffer(const_cast<OmxCodecBuffer &>(buffer));
    if (isIPCMode_ && buffer.fd >= 0) {
        close(buffer.fd);
    }

    return ret;
}

int32_t CodecComponentService::SetCallbacks(const sptr<ICodecCallback> &callbacks, int64_t appData)
{
    CODEC_LOGI("service impl!");
    CHECK_AND_RETURN_RET_LOG(callbacks != nullptr, HDF_ERR_INVALID_PARAM, "callbacks is null");
    return node_->SetCallbacks(callbacks, appData);
}

int32_t CodecComponentService::ComponentDeInit()
{
    CODEC_LOGI("service impl!");
    return node_->ComponentDeInit();
}

int32_t CodecComponentService::UseEglImage(uint32_t portIndex, const OmxCodecBuffer &inBuffer,
                                           OmxCodecBuffer &outBuffer, const std::vector<int8_t> &eglImage)
{
    CODEC_LOGI("portIndex [%{public}d]", portIndex);
    outBuffer = inBuffer;
    return node_->UseEglImage(outBuffer, portIndex, eglImage.data());
}

int32_t CodecComponentService::ComponentRoleEnum(std::vector<uint8_t> &role, uint32_t index)
{
    CODEC_LOGI("index [%{public}d]", index);
    return node_->ComponentRoleEnum(role, index);
}

void CodecComponentService::SetComponentRole()
{
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

std::string &CodecComponentService::GetComponentCompName()
{
    return name_;
}

void CodecComponentService::GetComponentNode(std::shared_ptr<OHOS::Codec::Omx::ComponentNode> &dumpNode_)
{
    dumpNode_ = node_;
}

}  // namespace V1_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS
