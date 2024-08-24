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
#include <hitrace_meter.h>
#include "codec_log_wrapper.h"
#include "component_mgr.h"
#include "icodec_buffer.h"
#include "sys/mman.h"
#include "v3_0/codec_ext_types.h"
#include "codec_component_service.h"

#define AUDIO_CODEC_NAME "OMX.audio"

using OHOS::HDI::Codec::V3_0::EventInfo;
using OHOS::HDI::Codec::V3_0::CodecEventType;
using OHOS::HDI::Codec::V3_0::CodecStateType;
using OHOS::HDI::Codec::V3_0::CodecCommandType;
using OHOS::HDI::Codec::V3_0::CodecStateType;
using OHOS::HDI::Codec::V3_0::CODEC_STATE_INVALID;
using OHOS::HDI::Codec::V3_0::CODEC_STATE_LOADED;
using OHOS::HDI::Codec::V3_0::CODEC_STATE_IDLE;
using OHOS::HDI::Codec::V3_0::CODEC_STATE_EXECUTING;
using OHOS::HDI::Codec::V3_0::CODEC_COMMAND_STATE_SET;
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
}

ComponentNode::~ComponentNode()
{
    std::unique_lock<std::shared_mutex> lk(mapMutex_);
    omxCallback_ = nullptr;
    bufferHeaderPortMap_.clear();
    codecBufferMap_.clear();
    bufferHeaderMap_.clear();
    portIndexMap_.clear();
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
    if (index != HDI::Codec::V3_0::Codec_IndexParamOverlayBuffer) {
        return OMX_ErrorNotImplemented;
    }
    if (paramStruct.size() != sizeof(HDI::Codec::V3_0::CodecParamOverlay)) {
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
    sptr<OHOS::HDI::Display::Buffer::V1_0::IMapper> mapper = HDI::Codec::V3_0::GetMapperService();
    if (mapper != nullptr) {
        mapper->Mmap(inBuffer.bufferhandle);
    }
    auto paramSrc = reinterpret_cast<const HDI::Codec::V3_0::CodecParamOverlay *>(paramStruct.data());
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
    if (mapper != nullptr) {
        mapper->Unmap(inBuffer.bufferhandle);
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
                                              OHOS::HDI::Codec::V3_0::CodecTunnelSetupType &tunnelSetup)
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
        return OMX_ErrorNone;
    }
    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    if (codecBuffer == nullptr || codecBuffer->EmptyOmxBufferDone(*buffer) != HDF_SUCCESS) {
        CODEC_LOGE("codecBuffer is null or EmptyOmxBufferDone error");
        return OMX_ErrorNone;
    }
    OmxCodecBuffer &codecOmxBuffer = codecBuffer->GetCodecBuffer();
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecOnEmptyBufferDone");
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
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecOnFillBufferDone");
    auto appPrivate = static_cast<OMXBufferAppPrivateData *>(buffer->pAppPrivate);
    if (appPrivate != nullptr && appPrivate->param != nullptr &&
        appPrivate->sizeOfParam < 1024) { // 1024: to protect from taint data
        codecOmxBuffer.alongParam.resize(appPrivate->sizeOfParam);
        std::copy(static_cast<uint8_t*>(appPrivate->param),
                  static_cast<uint8_t*>(appPrivate->param) + appPrivate->sizeOfParam,
                  codecOmxBuffer.alongParam.begin());
    }
    (void)omxCallback_->FillBufferDone(appData_, codecOmxBuffer);
    return OMX_ErrorNone;
}

int32_t ComponentNode::UseBuffer(uint32_t portIndex, OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");

    int32_t err = OMX_ErrorBadParameter;
    sptr<ICodecBuffer> codecBuffer = sptr<ICodecBuffer>();
    if (compName_.find(AUDIO_CODEC_NAME) != std::string::npos) {
        codecBuffer = sptr<ICodecBuffer>(new ICodecBuffer(buffer));
    } else {
        codecBuffer = ICodecBuffer::CreateCodeBuffer(buffer);
    }
    CHECK_AND_RETURN_RET_LOG(codecBuffer != nullptr, OMX_ErrorInvalidComponent, "codecBuffer is null");

    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    err = UseBufferByType(portIndex, buffer, codecBuffer, bufferHdrType);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("type [%{public}d] OMX_AllocateBuffer or OMX_UseBuffer ret = [%{public}x]", buffer.bufferType, err);
        codecBuffer = nullptr;
        return err;
    }

    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    codecBuffer->SetBufferId(bufferId);
    {
        std::unique_lock<std::shared_mutex> lk(mapMutex_);
        codecBufferMap_.emplace(std::make_pair(bufferId, codecBuffer));
        bufferHeaderMap_.emplace(std::make_pair(bufferHdrType, bufferId));
        bufferHeaderPortMap_.emplace(std::make_pair(bufferHdrType, portIndex));
        portIndexMap_.emplace(std::make_pair(bufferHdrType, portIndex));
    }
    return err;
}

int32_t ComponentNode::AllocateBuffer(uint32_t portIndex, OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    OMX_BUFFERHEADERTYPE *bufferHdrType = 0;
    OMXBufferAppPrivateData priv{};
    int32_t err = OMX_AllocateBuffer(static_cast<OMX_HANDLETYPE>(comp_),
                                     &bufferHdrType, portIndex, &priv, buffer.allocLen);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_AllocateBuffer error, err = %{public}x", err);
        return err;
    }

    buffer.allocLen = bufferHdrType->nAllocLen;
    sptr<ICodecBuffer> codecBuffer = ICodecBuffer::AllocateCodecBuffer(buffer, *bufferHdrType);
    if (codecBuffer == nullptr) {
        CODEC_LOGE("codecBuffer is null");
        (void)OMX_FreeBuffer(static_cast<OMX_HANDLETYPE>(comp_), portIndex, bufferHdrType);
        return OMX_ErrorInvalidComponent;
    }
    bufferHdrType->pAppPrivate = nullptr;
    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    codecBuffer->SetBufferId(bufferId);
    {
        std::unique_lock<std::shared_mutex> lk(mapMutex_);
        codecBufferMap_.emplace(std::make_pair(bufferId, codecBuffer));
        bufferHeaderMap_.emplace(std::make_pair(bufferHdrType, bufferId));
        bufferHeaderPortMap_.emplace(std::make_pair(bufferHdrType, portIndex));
        portIndexMap_.emplace(std::make_pair(bufferHdrType, portIndex));
    }
    return OMX_ErrorNone;
}

int32_t ComponentNode::FreeBuffer(uint32_t portIndex, const OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    int32_t err = OMX_ErrorBadParameter;
    sptr<ICodecBuffer> codecBufer = sptr<ICodecBuffer>();
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBufer, bufferHdrType)) {
        CODEC_LOGE(" GetBufferById return false");
        return err;
    }

    err = OMX_FreeBuffer(static_cast<OMX_HANDLETYPE>(comp_), portIndex, bufferHdrType);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_FreeBuffer err [%{public}x]", err);
        return err;
    }

    {
        std::unique_lock<std::shared_mutex> lk(mapMutex_);
        auto iterOmxBuffer = bufferHeaderMap_.begin();
        while (iterOmxBuffer != bufferHeaderMap_.end()) {
            if (iterOmxBuffer->first == bufferHdrType) {
                bufferHeaderMap_.erase(iterOmxBuffer);
                break;
            }
            iterOmxBuffer++;
        }

        iterOmxBuffer = bufferHeaderPortMap_.begin();
        while (iterOmxBuffer != bufferHeaderPortMap_.end()) {
            if (iterOmxBuffer->first == bufferHdrType) {
                bufferHeaderPortMap_.erase(iterOmxBuffer);
                break;
            }
            iterOmxBuffer++;
        }

        auto iter = codecBufferMap_.find(buffer.bufferId);
        if (iter != codecBufferMap_.end()) {
            codecBufferMap_.erase(iter);
        }
    }

    (void)codecBufer->FreeBuffer(const_cast<OmxCodecBuffer &>(buffer));

    return err;
}

int32_t ComponentNode::EmptyThisBuffer(OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    int32_t err = OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    sptr<ICodecBuffer> codecBuffer = sptr<ICodecBuffer>();
    if (!GetBufferById(buffer.bufferId, codecBuffer, bufferHdrType)) {
        CODEC_LOGE(" GetBufferById return false");
        return err;
    }
    err = codecBuffer->EmptyOmxBuffer(buffer, *bufferHdrType);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("EmptyOmxBuffer err [%{public}d]", err);
        return err;
    }
    bufferHdrType->pAppPrivate = nullptr;
    OMXBufferAppPrivateData privateData{};
    if (buffer.bufferType == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE && (!buffer.alongParam.empty())) {
        privateData.sizeOfParam = static_cast<uint32_t>(buffer.alongParam.size());
        privateData.param = static_cast<void *>(buffer.alongParam.data());
        bufferHdrType->pAppPrivate = static_cast<void *>(&privateData);
    }

    err = OMX_EmptyThisBuffer(static_cast<OMX_HANDLETYPE>(comp_), bufferHdrType);
    bufferHdrType->pAppPrivate = nullptr;
    return err;
}

int32_t ComponentNode::FillThisBuffer(OmxCodecBuffer &buffer)
{
    CHECK_AND_RETURN_RET_LOG(comp_ != nullptr, OMX_ErrorInvalidComponent, "comp_ is null");
    int32_t err = OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    sptr<ICodecBuffer> codecBuffer = sptr<ICodecBuffer>();
    if (!GetBufferById(buffer.bufferId, codecBuffer, bufferHdrType)) {
        CODEC_LOGE("GetBufferById return false");
        return err;
    }

    err = codecBuffer->FillOmxBuffer(buffer, *bufferHdrType);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("FillOmxBuffer err [%{public}d]", err);
        return err;
    }

    err = OMX_FillThisBuffer(static_cast<OMX_HANDLETYPE>(comp_), bufferHdrType);
    return err;
}

int32_t ComponentNode::UseBufferByType(uint32_t portIndex, OmxCodecBuffer &buffer,
    sptr<ICodecBuffer> codecBuffer, OMX_BUFFERHEADERTYPE *&bufferHdrType)
{
    int32_t err = OMX_ErrorUndefined;
    switch (buffer.bufferType) {
        case CODEC_BUFFER_TYPE_AVSHARE_MEM_FD: {
            if (compName_.find(AUDIO_CODEC_NAME) != std::string::npos) {
                void *addr = ::mmap(nullptr, static_cast<size_t>(buffer.allocLen),
                    static_cast<int>(PROT_READ | PROT_WRITE), MAP_SHARED, buffer.fd, 0);
                CHECK_AND_RETURN_RET_LOG(addr != nullptr, OMX_ErrorBadParameter, "addr is null");
                err = OMX_UseBuffer(static_cast<OMX_HANDLETYPE>(comp_), &bufferHdrType, portIndex, 0, buffer.allocLen,
                    reinterpret_cast<uint8_t *>(addr));
                break;
            }
            err = OMX_AllocateBuffer(static_cast<OMX_HANDLETYPE>(comp_), &bufferHdrType, portIndex, 0,
                buffer.allocLen);
            break;
        }
        case CODEC_BUFFER_TYPE_HANDLE:
        case CODEC_BUFFER_TYPE_DYNAMIC_HANDLE:
            err = OMX_UseBuffer(static_cast<OMX_HANDLETYPE>(comp_), &bufferHdrType, portIndex, 0, buffer.allocLen,
                codecBuffer->GetBuffer());
            break;
        case CODEC_BUFFER_TYPE_DMA_MEM_FD: {
            err = OMX_UseBuffer(static_cast<OMX_HANDLETYPE>(comp_), &bufferHdrType, portIndex, 0, 0,
                reinterpret_cast<uint8_t *>(&buffer.fd));
            break;
        }
        default:
            break;
    }
    return err;
}

uint32_t ComponentNode::GenerateBufferId()
{
    std::unique_lock<std::shared_mutex> lk(mapMutex_);
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
        return sptr<ICodecBuffer>();
    }
    std::shared_lock<std::shared_mutex> lk(mapMutex_);
    auto iterHead = bufferHeaderMap_.find(buffer);
    if (iterHead == bufferHeaderMap_.end()) {
        CODEC_LOGE("Can not find bufferID");
        return sptr<ICodecBuffer>();
    }

    uint32_t bufferId = iterHead->second;
    auto iter = codecBufferMap_.find(bufferId);
    if (iter == codecBufferMap_.end()) {
        CODEC_LOGE("Can not find bufferInfo by bufferId = %{public}d", bufferId);
        return sptr<ICodecBuffer>();
    }
    return iter->second;
}

bool ComponentNode::GetBufferById(uint32_t bufferId, sptr<ICodecBuffer> &codecBuffer,
                                  OMX_BUFFERHEADERTYPE *&bufferHdrType)
{
    std::shared_lock<std::shared_mutex> lk(mapMutex_);
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
    std::unique_lock<std::shared_mutex> lk(mapMutex_);
    auto iter = portIndexMap_.begin();
    while (iter != portIndexMap_.end()) {
        if (iter->second == 0) {
            inputBuffCount++;
        } else {
            outputBuffCount++;
        }
        iter++;
    }
}

void ComponentNode::ReleaseOMXResource()
{
    std::shared_lock<std::shared_mutex> lk(mapMutex_);
    if (codecBufferMap_.size() == 0) {
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
        ret = ReleaseAllBuffer();
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("ReleaseAllBuffer err [%{public}x]", ret);
            return;
        }
        WaitStateChange(CODEC_STATE_LOADED, status);
    }
    HDF_LOGI("%{public}s: Release OMX Resource success!", __func__);
}

int32_t ComponentNode::ReleaseAllBuffer()
{
    auto iter = bufferHeaderMap_.begin();
    for (; iter != bufferHeaderMap_.end(); iter++) {
        OMX_BUFFERHEADERTYPE *bufferHdrType = iter->first;
        uint32_t protIndex = bufferHeaderPortMap_.find(bufferHdrType)->second;
        auto ret = OMX_FreeBuffer((OMX_HANDLETYPE)comp_, protIndex, bufferHdrType);
        if (ret != OMX_ErrorNone) {
            HDF_LOGE("OMX_FreeBuffer err [%{public}x]", ret);
            return ret;
        }
    }
    HDF_LOGI("Release OMXBuffer and CodecBuffer success!");
    return HDF_SUCCESS;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
