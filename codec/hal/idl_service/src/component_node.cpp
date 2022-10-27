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

#include "component_node.h"
#include <ashmem.h>
#include <securec.h>
#include <unistd.h>
#include "codec_log_wrapper.h"
#include "component_mgr.h"
#include "icodec_buffer.h"

using OHOS::HDI::Codec::V1_0::EventInfo;
#define FD_SIZE sizeof(int)

namespace {
    constexpr int NAME_LENGTH = 32;
    constexpr int ROLE_MAX_LEN = 256;
}

namespace OHOS {
namespace Codec {
namespace Omx {
OMX_ERRORTYPE ComponentNode::OnEvent(OMX_HANDLETYPE component, void *appData, OMX_EVENTTYPE event, uint32_t data1,
                                     uint32_t data2, void *eventData)
{
    ComponentNode *node = static_cast<ComponentNode *>(appData);
    (void)component;
    if (node != nullptr) {
        node->OnEvent(event, data1, data2, eventData);
    }
    return OMX_ErrorNone;
}

OMX_ERRORTYPE ComponentNode::OnEmptyBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer)
{
    ComponentNode *node = static_cast<ComponentNode *>(appData);
    (void)component;
    if (node != nullptr) {
        node->OnEmptyBufferDone(buffer);
    }
    return OMX_ErrorNone;
}

OMX_ERRORTYPE ComponentNode::OnFillBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer)
{
    ComponentNode *node = static_cast<ComponentNode *>(appData);
    (void)component;
    if (node != nullptr) {
        node->OnFillBufferDone(buffer);
    }
    return OMX_ErrorNone;
}

OMX_CALLBACKTYPE ComponentNode::callbacks_ = {&ComponentNode::OnEvent, &ComponentNode::OnEmptyBufferDone,
                                              &ComponentNode::OnFillBufferDone};

ComponentNode::ComponentNode(const sptr<ICodecCallback> &callbacks, int64_t appData, std::shared_ptr<ComponentMgr> &mgr)
{
    omxCallback_ = callbacks;
    appData_ = appData;
    comp_ = nullptr;
    codecBufferMap_.clear();
    bufferHeaderMap_.clear();
    bufferIdCount_ = 0;
    mgr_ = mgr;
}

ComponentNode::~ComponentNode()
{
    omxCallback_ = nullptr;

    codecBufferMap_.clear();
    bufferHeaderMap_.clear();
    bufferIdCount_ = 0;
    if (comp_ != nullptr) {
        mgr_->DeleteComponentInstance(static_cast<OMX_COMPONENTTYPE *>(comp_));
        comp_ = nullptr;
    }
}

int32_t ComponentNode::OpenHandle(const std::string &name)
{
    if (comp_ != nullptr) {
        return HDF_SUCCESS;
    }

    OMX_COMPONENTTYPE *comp = nullptr;
    auto err = mgr_->CreateComponentInstance(name.c_str(), &callbacks_, this, &comp);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("CreateComponentInstance err = %{public}x ", err);
        return err;
    }
    this->comp_ = (OMX_HANDLETYPE)comp;
    return HDF_SUCCESS;
}

int32_t ComponentNode::GetComponentVersion(CompVerInfo &verInfo)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    char name[NAME_LENGTH] = {0};
    OMX_UUIDTYPE uuid = {0};
    OMX_VERSIONTYPE compVersion = {.nVersion = 0};
    OMX_VERSIONTYPE sepcVersion = {.nVersion = 0};
    int32_t err = OMX_GetComponentVersion(comp_, name, &compVersion, &sepcVersion, &uuid);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_GetComponentVersion err = %{public}x ", err);
        return err;
    }

    verInfo.compName = name;
    verInfo.compUUID.insert(verInfo.compUUID.end(), uuid, uuid + sizeof(OMX_UUIDTYPE));
    (void)memcpy_s(&verInfo.compVersion, sizeof(verInfo.compVersion), &compVersion, sizeof(sepcVersion));
    (void)memcpy_s(&verInfo.specVersion, sizeof(verInfo.specVersion), &sepcVersion, sizeof(sepcVersion));

    return err;
}

int32_t ComponentNode::SendCommand(OHOS::HDI::Codec::V1_0::OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_COMMANDTYPE omxCmd = static_cast<OMX_COMMANDTYPE>(cmd);
    auto err = OMX_SendCommand(comp_, omxCmd, param, cmdData);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_SendCommand err = %{public}x ", err);
    }
    return err;
}

int32_t ComponentNode::GetParameter(OMX_INDEXTYPE paramIndex, int8_t *param)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    auto err = OMX_GetParameter(comp_, paramIndex, param);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_GetParameter err = %{public}x ", err);
    }
    return err;
}

int32_t ComponentNode::SetParameter(OMX_INDEXTYPE paramIndex, const int8_t *param)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    auto err = OMX_SetParameter(comp_, paramIndex, const_cast<int8_t *>(param));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_SetParameter err = %{public}x ", err);
    }
    return err;
}

int32_t ComponentNode::GetConfig(OMX_INDEXTYPE index, int8_t *config)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    auto err = OMX_GetConfig(comp_, index, config);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_GetConfig err = %{public}x ", err);
    }
    return err;
}

int32_t ComponentNode::SetConfig(OMX_INDEXTYPE index, const int8_t *config)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    auto err = OMX_SetConfig(comp_, index, const_cast<int8_t *>(config));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_SetConfig err = %{public}x ", err);
    }
    return err;
}

int32_t ComponentNode::GetExtensionIndex(const char *parameterName, uint32_t &index)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_INDEXTYPE indexType = OMX_IndexComponentStartUnused;
    auto err = OMX_GetExtensionIndex(comp_, const_cast<char *>(parameterName), &indexType);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_GetExtensionIndex ret value[%{public}x]", err);
        return err;
    }
    index = indexType;
    return err;
}

int32_t ComponentNode::GetState(OHOS::HDI::Codec::V1_0::OMX_STATETYPE &state)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_STATETYPE status = OMX_StateInvalid;
    auto err = OMX_GetState(comp_, &status);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_GetState ret value[%{public}x]", err);
        return err;
    }
    state = static_cast<OHOS::HDI::Codec::V1_0::OMX_STATETYPE>(status);
    return err;
}

int32_t ComponentNode::ComponentTunnelRequest(uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                              OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE &tunnelSetup)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    unsigned long tunneledComp = (unsigned long)omxHandleTypeTunneledComp;
    auto err = comType->ComponentTunnelRequest(comp_, port, (OMX_HANDLETYPE)tunneledComp, tunneledPort,
                                               reinterpret_cast<OMX_TUNNELSETUPTYPE *>(&tunnelSetup));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("ComponentTunnelRequest err = %{public}x ", err);
    }
    return err;
}

int32_t ComponentNode::SetCallbacks(const sptr<ICodecCallback> &callbacks, int64_t appData)
{
    this->omxCallback_ = callbacks;
    appData_ = appData;
    return OMX_ErrorNone;
}

int32_t ComponentNode::UseEglImage(struct OmxCodecBuffer &buffer, uint32_t portIndex, const int8_t *eglImage)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_BUFFERHEADERTYPE *pBufferHdrType = nullptr;
    auto err = OMX_UseEGLImage(comp_, &pBufferHdrType, portIndex, 0, const_cast<int8_t *>(eglImage));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_UseEGLImage error[0x%{public}x]", err);
        return err;
    }
    (void)buffer;
    return OMX_ErrorNotImplemented;
}

int32_t ComponentNode::ComponentRoleEnum(std::vector<uint8_t> &role, uint32_t index)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    uint8_t omxRole[ROLE_MAX_LEN] = {0};
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    int32_t err = comType->ComponentRoleEnum(comp_, omxRole, index);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("ComponentRoleEnum ret err [0x%{public}x] ", err);
        return err;
    }
    role.insert(role.end(), omxRole, omxRole + strlen((const char *)omxRole));
    return OMX_ErrorNone;
}

int32_t ComponentNode::ComponentDeInit()
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    auto err = comType->ComponentDeInit(comp_);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("ComponentDeInit err = %{public}x ", err);
    }
    return err;
}

int32_t ComponentNode::OnEvent(OMX_EVENTTYPE event, uint32_t data1, uint32_t data2, void *eventData)
{
    if (omxCallback_ == nullptr) {
        CODEC_LOGE("omxCallback_ is null");
        return OMX_ErrorNone;
    }
    (void)eventData;
    EventInfo info = {.appData = appData_, .data1 = data1, .data2 = data2};
    (void)omxCallback_->EventHandler(static_cast<OHOS::HDI::Codec::V1_0::OMX_EVENTTYPE>(event), info);

    return OMX_ErrorNone;
}

int32_t ComponentNode::OnEmptyBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        CODEC_LOGE("omxCallback_ or buffer is null");
        return OMX_ErrorNone;
    }
    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    if (codecBuffer == nullptr || codecBuffer->EmptyOmxBufferDone(*buffer) != HDF_SUCCESS) {
        CODEC_LOGE("codecBuffer is null or EmptyOmxBufferDone error");
        return OMX_ErrorNone;
    }
    OmxCodecBuffer &codecOmxBuffer = codecBuffer->GetCodecBuffer();
    (void)omxCallback_->EmptyBufferDone(appData_, codecOmxBuffer);
    return OMX_ErrorNone;
}

int32_t ComponentNode::OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        CODEC_LOGE("omxCallback_ or buffer is null");
        return OMX_ErrorNone;
    }

    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    if (codecBuffer == nullptr || codecBuffer->FillOmxBufferDone(*buffer) != HDF_SUCCESS) {
        CODEC_LOGE("codecBuffer is null or EmptyOmxBufferDone error");
        return OMX_ErrorNone;
    }

    struct OmxCodecBuffer &codecOmxBuffer = codecBuffer->GetCodecBuffer();
    (void)omxCallback_->FillBufferDone(appData_, codecOmxBuffer);
    return OMX_ErrorNone;
}

int32_t ComponentNode::UseBuffer(uint32_t portIndex, OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    if (buffer.fenceFd >= 0) {
        close(buffer.fenceFd);
        buffer.fenceFd = -1;
    }

    int32_t err = OMX_ErrorBadParameter;
    sptr<ICodecBuffer> codecBuffer = ICodecBuffer::CreateCodeBuffer(buffer);
    if (codecBuffer == nullptr) {
        CODEC_LOGE("codecBuffer is null");
        return OMX_ErrorInvalidComponent;
    }
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    if (buffer.bufferType == CODEC_BUFFER_TYPE_AVSHARE_MEM_FD) {
        err = OMX_AllocateBuffer((OMX_HANDLETYPE)comp_, &bufferHdrType, portIndex, 0, buffer.allocLen);
    } else {
        err = OMX_UseBuffer((OMX_HANDLETYPE)comp_, &bufferHdrType, portIndex, 0, buffer.allocLen,
                            codecBuffer->GetBuffer());
    }

    if (err != OMX_ErrorNone) {
        CODEC_LOGE("type [%{public}d] OMX_AllocateBuffer or OMX_UseBuffer ret err[%{public}x]", buffer.bufferType, err);
        codecBuffer = nullptr;
        return err;
    }
    // for test
    buffer.fenceFd = 0;

    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    codecBuffer->SetBufferId(bufferId);
    codecBufferMap_.emplace(std::make_pair(bufferId, codecBuffer));
    bufferHeaderMap_.emplace(std::make_pair(bufferHdrType, bufferId));

    return err;
}

int32_t ComponentNode::AllocateBuffer(uint32_t portIndex, OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_BUFFERHEADERTYPE *bufferHdrType = 0;
    int32_t err = OMX_AllocateBuffer((OMX_HANDLETYPE)comp_, &bufferHdrType, portIndex, 0, buffer.allocLen);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_AllocateBuffer error, err = %{public}x", err);
        return err;
    }

    buffer.allocLen = bufferHdrType->nAllocLen;
    sptr<ICodecBuffer> codecBuffer = ICodecBuffer::AllocateCodecBuffer(buffer);
    if (codecBuffer == nullptr) {
        CODEC_LOGE("codecBuffer is null");
        (void)OMX_FreeBuffer((OMX_HANDLETYPE)comp_, portIndex, bufferHdrType);
        return OMX_ErrorInvalidComponent;
    }

    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    codecBufferMap_.emplace(std::make_pair(bufferId, codecBuffer));
    bufferHeaderMap_.emplace(std::make_pair(bufferHdrType, bufferId));
    return OMX_ErrorNone;
}

int32_t ComponentNode::FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    int32_t err = OMX_ErrorBadParameter;
    sptr<ICodecBuffer> codecBufer = nullptr;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBufer, bufferHdrType)) {
        CODEC_LOGE(" GetBufferById return false");
        return err;
    }

    err = OMX_FreeBuffer((OMX_HANDLETYPE)comp_, portIndex, bufferHdrType);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_FreeBuffer err [%{public}x]", err);
        return err;
    }

    auto iterOmxBuffer = bufferHeaderMap_.begin();
    while (iterOmxBuffer != bufferHeaderMap_.end()) {
        if (iterOmxBuffer->first == bufferHdrType) {
            bufferHeaderMap_.erase(iterOmxBuffer);
            break;
        }
        iterOmxBuffer++;
    }

    auto iter = codecBufferMap_.find(buffer.bufferId);
    if (iter != codecBufferMap_.end()) {
        codecBufferMap_.erase(iter);
    }
    (void)codecBufer->FreeBuffer(const_cast<OmxCodecBuffer &>(buffer));

    return err;
}

int32_t ComponentNode::EmptyThisBuffer(OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    int32_t err = OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    sptr<ICodecBuffer> codecBuffer = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBuffer, bufferHdrType)) {
        CODEC_LOGE(" GetBufferById return false");
        return err;
    }
    err = codecBuffer->EmptyOmxBuffer(buffer, *bufferHdrType);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("EmptyOmxBuffer err [%{public}d]", err);
        return err;
    }

    err = OMX_EmptyThisBuffer((OMX_HANDLETYPE)comp_, bufferHdrType);
    return err;
}

int32_t ComponentNode::FillThisBuffer(OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    int32_t err = OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    sptr<ICodecBuffer> codecBuffer = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBuffer, bufferHdrType)) {
        CODEC_LOGE("GetBufferById return false");
        return err;
    }

    err = codecBuffer->FillOmxBuffer(buffer, *bufferHdrType);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("FillOmxBuffer err [%{public}d]", err);
        return err;
    }

    err = OMX_FillThisBuffer((OMX_HANDLETYPE)comp_, bufferHdrType);
    return err;
}

uint32_t ComponentNode::GenerateBufferId()
{
    uint32_t bufferId = 0;
    do {
        if (++bufferIdCount_ == 0) {
            ++bufferIdCount_;
        }
        bufferId = bufferIdCount_;
    } while (codecBufferMap_.find(bufferId) != codecBufferMap_.end());
    return bufferId;
}

sptr<ICodecBuffer> ComponentNode::GetBufferInfoByHeader(OMX_BUFFERHEADERTYPE *buffer)
{
    if (buffer == nullptr) {
        CODEC_LOGE("Buffer is null");
        return nullptr;
    }

    auto iterHead = bufferHeaderMap_.find(buffer);
    if (iterHead == bufferHeaderMap_.end()) {
        CODEC_LOGE("Can not find bufferID by pHeaderType = 0x%{public}p", buffer);
        return nullptr;
    }

    uint32_t bufferId = iterHead->second;
    auto iter = codecBufferMap_.find(bufferId);
    if (iter == codecBufferMap_.end()) {
        CODEC_LOGE("Can not find bufferInfo by bufferId = %{public}d", bufferId);
        return nullptr;
    }
    return iter->second;
}

bool ComponentNode::GetBufferById(uint32_t bufferId, sptr<ICodecBuffer> &codecBuffer,
                                  OMX_BUFFERHEADERTYPE *&bufferHdrType)
{
    auto iter = codecBufferMap_.find(bufferId);
    if ((iter == codecBufferMap_.end()) || (iter->second == nullptr)) {
        CODEC_LOGE("Can not find bufferIndo by bufferID [%{public}d]", bufferId);
        return false;
    }

    auto iterHead = bufferHeaderMap_.begin();
    for (; iterHead != bufferHeaderMap_.end(); iterHead++) {
        if (iterHead->second == bufferId) {
            break;
        }
    }
    if ((iterHead == bufferHeaderMap_.end()) || (iterHead->first == nullptr)) {
        CODEC_LOGE("Can not find bufferHeaderType by bufferID [%{public}d] or iterHead->first is null", bufferId);
        return false;
    }
    bufferHdrType = iterHead->first;
    codecBuffer = iter->second;
    return true;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS