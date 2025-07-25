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

#include "component_node.h"
#include <ashmem.h>
#include <securec.h>
#include <unistd.h>
#include <sys/stat.h>
#include <hdf_remote_service.h>
#include <hitrace_meter.h>
#include "codec_log_wrapper.h"
#include "component_mgr.h"
#include "icodec_buffer.h"
#include "sys/mman.h"
#include "v4_0/codec_ext_types.h"
#include "codec_component_service.h"

#define AUDIO_CODEC_NAME "OMX.audio"

using OHOS::HDI::Codec::V4_0::EventInfo;
using OHOS::HDI::Codec::V4_0::CodecEventType;
using OHOS::HDI::Codec::V4_0::CodecStateType;
using OHOS::HDI::Codec::V4_0::CodecCommandType;
using OHOS::HDI::Codec::V4_0::CODEC_STATE_INVALID;
using OHOS::HDI::Codec::V4_0::CODEC_STATE_LOADED;
using OHOS::HDI::Codec::V4_0::CODEC_STATE_IDLE;
using OHOS::HDI::Codec::V4_0::CODEC_STATE_EXECUTING;
using OHOS::HDI::Codec::V4_0::CODEC_COMMAND_STATE_SET;
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
        node->OnEvent(static_cast<CodecEventType>(event), data1, data2, eventData);
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
    : comp_(nullptr),
      omxCallback_(callbacks),
      appData_(appData),
      bufferIdCount_(0),
      mgr_(mgr)
{
    isIPCMode_ = (HdfRemoteGetCallingPid() == getpid() ? false : true);
}

ComponentNode::~ComponentNode()
{
    std::unique_lock<std::shared_mutex> lk(poolMutex_);
    omxCallback_ = nullptr;
    bufferPool_.clear();
    bufferIdCount_ = 0;
    comp_ = nullptr;
    mgr_ = nullptr;
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
    compName_ = name;
    return HDF_SUCCESS;
}

int32_t ComponentNode::CloseHandle()
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return HDF_FAILURE;
    }

    auto err = mgr_->DeleteComponentInstance(reinterpret_cast<OMX_COMPONENTTYPE *>(comp_));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("DeleteComponentInstance err = %{public}x ", err);
        return err;
    }
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
    err = memcpy_s(&verInfo.compVersion, sizeof(verInfo.compVersion), &compVersion, sizeof(sepcVersion));
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("memset_s return err [%{public}d].", err);
        return err;
    }

    err = memcpy_s(&verInfo.specVersion, sizeof(verInfo.specVersion), &sepcVersion, sizeof(sepcVersion));
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("memset_s return err [%{public}d].", err);
        return err;
    }
    return err;
}

int32_t ComponentNode::SendCommand(CodecCommandType cmd, uint32_t param, int8_t *cmdData)
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

int32_t ComponentNode::SetParameterWithBuffer(int32_t index, const std::vector<int8_t>& paramStruct,
    const OmxCodecBuffer& inBuffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    if (index != HDI::Codec::V4_0::Codec_IndexParamOverlayBuffer) {
        return OMX_ErrorNotImplemented;
    }
    if (paramStruct.size() != sizeof(HDI::Codec::V4_0::CodecParamOverlay)) {
        return OMX_ErrorBadParameter;
    }
    if (inBuffer.bufferhandle == nullptr) {
        CODEC_LOGE("null bufferhandle");
        return OMX_ErrorBadParameter;
    }
    BufferHandle* handle = inBuffer.bufferhandle->GetBufferHandle();
    if (handle == nullptr) {
        CODEC_LOGE("null bufferhandle");
        return OMX_ErrorBadParameter;
    }
    int ret = Mmap(inBuffer.bufferhandle);
    if (ret != 0) {
        CODEC_LOGE("mmap failed");
        return ret;
    }
    auto paramSrc = reinterpret_cast<const HDI::Codec::V4_0::CodecParamOverlay *>(paramStruct.data());
    CodecParamOverlayBuffer paramDst {
        .size = sizeof(CodecParamOverlayBuffer),
        .enable = paramSrc->enable,
        .dstX = paramSrc->dstX,
        .dstY = paramSrc->dstY,
        .dstW = paramSrc->dstW,
        .dstH = paramSrc->dstH,
        .bufferHandle = handle,
    };
    auto err = OMX_SetParameter(comp_, static_cast<OMX_INDEXTYPE>(OMX_IndexParamOverlayBuffer),
        reinterpret_cast<int8_t *>(&paramDst));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_SetParameter err = %{public}x ", err);
    }
    (void)Unmap(inBuffer.bufferhandle);
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

int32_t ComponentNode::GetState(CodecStateType &state)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_STATETYPE status = OMX_StateInvalid;
    auto err = OMX_GetState(comp_, &status);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_GetState ret value[%{public}x]", err);
        return err;
    }
    state = static_cast<CodecStateType>(status);
    return err;
}

int32_t ComponentNode::ComponentTunnelRequest(uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                              OHOS::HDI::Codec::V4_0::CodecTunnelSetupType &tunnelSetup)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    unsigned long tunneledComp = static_cast<unsigned long>(omxHandleTypeTunneledComp);
    if (comType->ComponentTunnelRequest == nullptr) {
        CODEC_LOGE("The requested function is not implemented.");
        return OMX_ErrorNotImplemented;
    }
    auto err = comType->ComponentTunnelRequest(comp_, port, reinterpret_cast<OMX_HANDLETYPE>(tunneledComp),
        tunneledPort, reinterpret_cast<OMX_TUNNELSETUPTYPE *>(&tunnelSetup));
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
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    if (comType->UseEGLImage == nullptr) {
        CODEC_LOGE("The requested function is not implemented.");
        return OMX_ErrorNotImplemented;
    }
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
    CHECK_AND_RETURN_RET_LOG(index < ROLE_MAX_LEN, HDF_ERR_INVALID_PARAM, "index is too large");
    uint8_t omxRole[ROLE_MAX_LEN] = {0};
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    if (comType->ComponentRoleEnum == nullptr) {
        CODEC_LOGE("The requested function is not implemented.");
        return OMX_ErrorNotImplemented;
    }
    int32_t err = comType->ComponentRoleEnum(comp_, omxRole, index);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("ComponentRoleEnum ret err [0x%{public}x] ", err);
        return err;
    }
    role.insert(role.end(), omxRole, omxRole + strlen(reinterpret_cast<const char *>(omxRole)));
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

int32_t ComponentNode::OnEvent(CodecEventType event, uint32_t data1, uint32_t data2, void *eventData)
{
    CODEC_LOGD("eventType: [%{public}d], data1: [%{public}x], data2: [%{public}x]", event, data1, data2);
    if (omxCallback_ == nullptr) {
        CODEC_LOGE("omxCallback_ is null");
        return OMX_ErrorNone;
    }
    (void)eventData;
    EventInfo info = {.appData = appData_, .data1 = data1, .data2 = data2};
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecOnEvent");
    (void)omxCallback_->EventHandler(event, info);

    return OMX_ErrorNone;
}

int32_t ComponentNode::OnEmptyBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        CODEC_LOGE("omxCallback_ or buffer is null");
        return OMX_ErrorBadParameter;
    }
    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    CHECK_AND_RETURN_RET_LOG(codecBuffer != nullptr, OMX_ErrorBadParameter, "buffer not exist");

    OmxCodecBuffer codecOmxBuffer;
    int32_t ret = codecBuffer->EmptyBufferDone(*buffer, codecOmxBuffer);
    CHECK_AND_RETURN_RET_LOG(ret == 0, ret, "EmptyBufferDone failed");

    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecOnEmptyBufferDone");
    (void)omxCallback_->EmptyBufferDone(appData_, OHOS::Codec::Omx::Convert(codecOmxBuffer, isIPCMode_));
    return OMX_ErrorNone;
}

int32_t ComponentNode::OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        CODEC_LOGE("omxCallback_ or buffer is null");
        return OMX_ErrorBadParameter;
    }

    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    CHECK_AND_RETURN_RET_LOG(codecBuffer != nullptr, OMX_ErrorBadParameter, "buffer not exist");

    OmxCodecBuffer codecOmxBuffer;
    int32_t ret = codecBuffer->FillBufferDone(*buffer, codecOmxBuffer);
    CHECK_AND_RETURN_RET_LOG(ret == 0, ret, "FillBufferDone failed");

    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecOnFillBufferDone");
    (void)omxCallback_->FillBufferDone(appData_, OHOS::Codec::Omx::Convert(codecOmxBuffer, isIPCMode_));
    return OMX_ErrorNone;
}

int32_t ComponentNode::UseBuffer(uint32_t portIndex, OmxCodecBuffer &buffer)
{
    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    bool doCopy = compName_.find(AUDIO_CODEC_NAME) == std::string::npos;
    OMX_BUFFERHEADERTYPE *omxHeader = nullptr;
    sptr<ICodecBuffer> codecBuffer = ICodecBuffer::UseBuffer(comp_, portIndex, buffer, omxHeader, doCopy);
    CHECK_AND_RETURN_RET_LOG(codecBuffer != nullptr, OMX_ErrorBadParameter, "codecBuffer is null");
    {
        std::unique_lock<std::shared_mutex> lk(poolMutex_);
        bufferPool_.push_back(BufferInfo{bufferId, portIndex, codecBuffer, omxHeader});
    }
    return OMX_ErrorNone;
}

int32_t ComponentNode::AllocateBuffer(uint32_t portIndex, OmxCodecBuffer &buffer)
{
    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    OMX_BUFFERHEADERTYPE *omxHeader = nullptr;
    sptr<ICodecBuffer> codecBuffer = ICodecBuffer::AllocateBuffer(comp_, portIndex, buffer, omxHeader);
    CHECK_AND_RETURN_RET_LOG(codecBuffer != nullptr, OMX_ErrorBadParameter, "codecBuffer is null");
    {
        std::unique_lock<std::shared_mutex> lk(poolMutex_);
        bufferPool_.push_back(BufferInfo{bufferId, portIndex, codecBuffer, omxHeader});
    }
    return OMX_ErrorNone;
}

int32_t ComponentNode::FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer)
{
    std::unique_lock<std::shared_mutex> poolLock(poolMutex_);
    uint32_t bufferId = buffer.bufferId;
    auto iter = std::find_if(bufferPool_.begin(), bufferPool_.end(), [bufferId, portIndex](const BufferInfo& info) {
        return info.bufferId == bufferId && info.portIndex == portIndex;
    });
    if (iter == bufferPool_.end()) {
        CODEC_LOGE("Can not find buffer");
        return OMX_ErrorBadParameter;
    }
    sptr<ICodecBuffer> codecBuffer = iter->icodecBuf;
    CHECK_AND_RETURN_RET_LOG(codecBuffer != nullptr, OMX_ErrorBadParameter, "codecBuffer is null");
    codecBuffer->FreeBuffer();
    bufferPool_.erase(iter);
    return 0;
}

int32_t ComponentNode::EmptyThisBuffer(OmxCodecBuffer &buffer)
{
    sptr<ICodecBuffer> codecBuffer = GetBufferById(buffer.bufferId);
    CHECK_AND_RETURN_RET_LOG(codecBuffer != nullptr, OMX_ErrorBadParameter, "buffer not exist");
    return codecBuffer->EmptyThisBuffer(buffer);
}

int32_t ComponentNode::FillThisBuffer(OmxCodecBuffer &buffer)
{
    sptr<ICodecBuffer> codecBuffer = GetBufferById(buffer.bufferId);
    CHECK_AND_RETURN_RET_LOG(codecBuffer != nullptr, OMX_ErrorBadParameter, "buffer not exist");
    return codecBuffer->FillThisBuffer(buffer);
}

uint32_t ComponentNode::GenerateBufferId()
{
    std::shared_lock<std::shared_mutex> lk(poolMutex_);
    uint32_t bufferId = 0;
    do {
        if (++bufferIdCount_ == 0) {
            ++bufferIdCount_;
        }
        bufferId = bufferIdCount_;
    } while (std::any_of(bufferPool_.begin(), bufferPool_.end(), [bufferId](const BufferInfo& info) {
        return info.bufferId == bufferId;
    }));
    CODEC_LOGD("bufferId=%{public}u", bufferId);
    return bufferId;
}

sptr<ICodecBuffer> ComponentNode::GetBufferInfoByHeader(OMX_BUFFERHEADERTYPE *buffer)
{
    std::shared_lock<std::shared_mutex> lk(poolMutex_);
    auto iter = std::find_if(bufferPool_.begin(), bufferPool_.end(), [buffer](const BufferInfo& info) {
        return info.omxHeader == buffer;
    });
    if (iter == bufferPool_.end()) {
        CODEC_LOGE("Can not find buffer");
        return nullptr;
    }
    return iter->icodecBuf;
}

sptr<ICodecBuffer> ComponentNode::GetBufferById(uint32_t bufferId)
{
    std::shared_lock<std::shared_mutex> lk(poolMutex_);
    auto iter = std::find_if(bufferPool_.begin(), bufferPool_.end(), [bufferId](const BufferInfo& info) {
        return info.bufferId == bufferId;
    });
    if (iter == bufferPool_.end()) {
        CODEC_LOGE("Can not find bufferID [%{public}d]", bufferId);
        return nullptr;
    }
    return iter->icodecBuf;
}

void ComponentNode::WaitStateChange(CodecStateType objState, CodecStateType &status)
{
    int32_t ret;
    uint32_t count = 0;
    while (status != objState && count < maxStateWaitCount) {
        usleep(maxStateWaitTime);
        ret = GetState(status);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: GetState error [%{public}x]", __func__, ret);
            return;
        }
        count++;
    }
}

void ComponentNode::GetBuffCount(uint32_t &inputBuffCount, uint32_t &outputBuffCount)
{
    std::shared_lock<std::shared_mutex> lk(poolMutex_);
    for (const BufferInfo& info : bufferPool_) {
        if (info.portIndex == 0) {
            inputBuffCount++;
        } else {
            outputBuffCount++;
        }
    }
}

void ComponentNode::ReleaseOMXResource()
{
    std::unique_lock<std::shared_mutex> lk(poolMutex_);
    if (bufferPool_.empty()) {
        return;
    }
    CodecStateType status = CODEC_STATE_INVALID;
    int32_t ret = GetState(status);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("ReleaseOMXResource GetState error [%{public}x]", ret);
        return;
    }
    if (status == CODEC_STATE_EXECUTING) {
        SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_IDLE, NULL);
        WaitStateChange(CODEC_STATE_IDLE, status);
    }
    if (status == CODEC_STATE_IDLE) {
        SendCommand(CODEC_COMMAND_STATE_SET, CODEC_STATE_LOADED, NULL);
        bufferPool_.clear();
        WaitStateChange(CODEC_STATE_LOADED, status);
    }
    HDF_LOGI("%{public}s: Release OMX Resource success!", __func__);
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
