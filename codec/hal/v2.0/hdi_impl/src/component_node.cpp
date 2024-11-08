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
#include "icodec_buffer.h"
#include "codec_log_wrapper.h"

#define FD_SIZE     sizeof(int)
namespace {
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

ComponentNode::ComponentNode(struct CodecCallbackType *callback, int64_t appData, const std::string &compName)
    : comp_(nullptr),
      omxCallback_(callback),
      appData_(appData),
      bufferIdCount_(0),
      name_(compName)
{
}

ComponentNode::~ComponentNode()
{
    if (omxCallback_ != nullptr) {
        std::unique_lock<std::shared_mutex> lk(callbackMutex_);
        CodecCallbackTypeRelease(omxCallback_);
        omxCallback_ = nullptr;
    }
    std::unique_lock<std::shared_mutex> lk(mapMutex_);
    if (codecBufferMap_.size() != 0) {
        ReleaseOMXResource();
    }
    codecBufferMap_.clear();
    bufferHeaderMap_.clear();
    bufferHeaderPortMap_.clear();
    bufferIdCount_ = 0;
    name_ = "";
}

int32_t ComponentNode::GetComponentVersion(struct CompVerInfo &verInfo)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
    int32_t err =
        OMX_GetComponentVersion(comp_, verInfo.compName, &verInfo.compVersion, &verInfo.specVersion, &verInfo.compUUID);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_GetComponentVersion err = %{public}d", err);
        return err;
    }
    return err;
}

int32_t ComponentNode::SendCommand(OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
    (void)cmdDataLen;
    return OMX_SendCommand(comp_, cmd, param, cmdData);
}

int32_t ComponentNode::GetParameter(OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
    (void)paramLen;
    return OMX_GetParameter(comp_, paramIndex, param);
}

int32_t ComponentNode::SetParameter(OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen)
{
    if (comp_ == nullptr || param == nullptr) {
        CODEC_LOGE("comp_ is null or param is null");
        return OMX_ErrorInvalidComponent;
    }
    (void)paramLen;
    return OMX_SetParameter(comp_, paramIndex, param);
}

int32_t ComponentNode::GetConfig(OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
    (void)configLen;
    return OMX_GetConfig(comp_, index, config);
}

int32_t ComponentNode::SetConfig(OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
    (void)configLen;
    return OMX_SetConfig(comp_, index, config);
}

int32_t ComponentNode::GetExtensionIndex(const char *parameterName, OMX_INDEXTYPE *indexType)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
    // change name
    return OMX_GetExtensionIndex(comp_, const_cast<char *>(parameterName), indexType);
}

int32_t ComponentNode::GetState(OMX_STATETYPE *state)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }

    return OMX_GetState(comp_, state);
}

int32_t ComponentNode::ComponentTunnelRequest(uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                              struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    if (comType->ComponentTunnelRequest == nullptr) {
        CODEC_LOGE("The requested function is not implemented.");
        return OMX_ErrorNotImplemented;
    }
    unsigned long tunneledComp = static_cast<unsigned long>(omxHandleTypeTunneledComp);
    return comType->ComponentTunnelRequest(comp_, port, reinterpret_cast<OMX_HANDLETYPE>(tunneledComp),
        tunneledPort, tunnelSetup);
}

int32_t ComponentNode::SetCallbacks(struct CodecCallbackType *omxCallback, int64_t appData)
{
    // release this->omxCallback_
    if (this->omxCallback_ != nullptr) {
        CodecCallbackTypeRelease(this->omxCallback_);
        this->omxCallback_ = nullptr;
    }
    this->omxCallback_ = omxCallback;
    this->appData_ = appData;
    return OMX_ErrorNone;
}

int32_t ComponentNode::UseEglImage(struct OmxCodecBuffer &buffer, uint32_t portIndex, int8_t *eglImage,
                                   uint32_t eglImageLen)
{
    OMX_BUFFERHEADERTYPE *pBufferHdrType = nullptr;

    auto err = OMX_UseEGLImage(comp_, &pBufferHdrType, portIndex, nullptr, eglImage);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_UseEGLImage error[0x%{public}x]", err);
        return err;
    }
    (void)buffer;
    (void)eglImageLen;
    return OMX_ErrorNotImplemented;
}

int32_t ComponentNode::ComponentRoleEnum(uint8_t *role, uint32_t roleLen, uint32_t index)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null ");
        return OMX_ErrorInvalidComponent;
    }
    uint8_t omxRole[ROLE_MAX_LEN] = {0};
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    if (comType->ComponentRoleEnum == nullptr) {
        CODEC_LOGE("The requested function is not implemented.");
        return OMX_ErrorNotImplemented;
    }
    int32_t err = comType->ComponentRoleEnum(comp_, omxRole, index);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("ComponentRoleEnum ret err [0x%{public}x]", err);
        return err;
    }

    size_t omxRoleLen = strlen(reinterpret_cast<const char *>(omxRole));
    if (omxRoleLen == 0) {
        CODEC_LOGW("omxRoleLen is 0");
    } else {
        int32_t ret = memcpy_s(role, roleLen, omxRole, omxRoleLen);
        if (ret != EOK) {
            CODEC_LOGE("memcpy_s ret [%{public}d]", ret);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    return OMX_ErrorNone;
}

int32_t ComponentNode::DeInit()
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null ");
        return OMX_ErrorInvalidComponent;
    }
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    return comType->ComponentDeInit(comp_);
}

int32_t ComponentNode::OnEvent(OMX_EVENTTYPE event, uint32_t data1, uint32_t data2, void *eventData)
{
    std::shared_lock<std::shared_mutex> lk(callbackMutex_);
    if (omxCallback_ == nullptr) {
        CODEC_LOGE("omxCallback_ is null");
        return OMX_ErrorNone;
    }
    CODEC_LOGD("event [%d], data1 [%d],data2 [%d]", event, data1, data2);
    struct EventInfo info = {.appData = appData_,
                             .data1 = data1,
                             .data2 = data2,
                             .eventData = static_cast<int8_t *>(eventData),
                             .eventDataLen = 0};
    (void)omxCallback_->EventHandler(omxCallback_, event, &info);

    return OMX_ErrorNone;
}

int32_t ComponentNode::OnEmptyBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    std::shared_lock<std::shared_mutex> lk(callbackMutex_);
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        CODEC_LOGE("omxCallback_ or buffer is null");
        return OMX_ErrorNone;
    }
    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    if (codecBuffer == nullptr || codecBuffer->EmptyOmxBufferDone(*buffer) != HDF_SUCCESS) {
        CODEC_LOGE("codecBuffer is null or EmptyOmxBufferDone error");
        return OMX_ErrorNone;
    }
    struct OmxCodecBuffer &codecOmxBuffer = codecBuffer->GetCodecBuffer();
    (void)omxCallback_->EmptyBufferDone(omxCallback_, appData_, &codecOmxBuffer);
    return OMX_ErrorNone;
}

int32_t ComponentNode::OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    std::shared_lock<std::shared_mutex> lk(callbackMutex_);
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        CODEC_LOGE("omxCallback_ or buffer is null");
        return OMX_ErrorNone;
    }

    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    if (codecBuffer == nullptr || codecBuffer->FillOmxBufferDone(*buffer) != HDF_SUCCESS) {
        CODEC_LOGE("codecBuffer is null or FillOmxBufferDone error");
        return OMX_ErrorNone;
    }

    struct OmxCodecBuffer &codecOmxBuffer = codecBuffer->GetCodecBuffer();
    (void)omxCallback_->FillBufferDone(omxCallback_, appData_, &codecOmxBuffer);
    return OMX_ErrorNone;
}

int32_t ComponentNode::UseBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
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
        err = OMX_AllocateBuffer(static_cast<OMX_HANDLETYPE>(comp_), &bufferHdrType, portIndex, 0, buffer.allocLen);
    } else {
        err = OMX_UseBuffer(static_cast<OMX_HANDLETYPE>(comp_), &bufferHdrType, portIndex, 0, buffer.allocLen,
                            codecBuffer->GetBuffer());
    }

    if (err != OMX_ErrorNone) {
        CODEC_LOGE("type [%{public}d] OMX_AllocateBuffer or OMX_UseBuffer ret err[%{public}x]",
            buffer.bufferType, err);
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
    }
    return err;
}

int32_t ComponentNode::AllocateBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is null");
        return OMX_ErrorInvalidComponent;
    }
    OMX_BUFFERHEADERTYPE *bufferHdrType = 0;
    int32_t err = OMX_AllocateBuffer(static_cast<OMX_HANDLETYPE>(comp_), &bufferHdrType, portIndex, 0, buffer.allocLen);
    if (err != OMX_ErrorNone || bufferHdrType == nullptr) {
        CODEC_LOGE("OMX_AllocateBuffer error, err = %{public}x", err);
        return err;
    }

    buffer.allocLen = bufferHdrType->nAllocLen;
    sptr<ICodecBuffer> codecBuffer = ICodecBuffer::AllocateCodecBuffer(buffer);
    if (codecBuffer == nullptr) {
        CODEC_LOGE("codecBuffer is null");
        (void)OMX_FreeBuffer(static_cast<OMX_HANDLETYPE>(comp_), portIndex, bufferHdrType);
        return OMX_ErrorInvalidComponent;
    }

    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    {
        std::unique_lock<std::shared_mutex> lk(mapMutex_);
        codecBufferMap_.emplace(std::make_pair(bufferId, codecBuffer));
        bufferHeaderMap_.emplace(std::make_pair(bufferHdrType, bufferId));
        bufferHeaderPortMap_.emplace(std::make_pair(bufferHdrType, portIndex));
    }
    return OMX_ErrorNone;
}

int32_t ComponentNode::FreeBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is nullptr");
        return OMX_ErrorInvalidComponent;
    }

    int32_t err = OMX_ErrorBadParameter;
    sptr<ICodecBuffer> codecBufer = nullptr;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBufer, bufferHdrType)) {
        CODEC_LOGE("GetBufferById return false");
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

    (void)codecBufer->FreeBuffer(buffer);

    return err;
}

int32_t ComponentNode::EmptyThisBuffer(struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is nullptr");
        return OMX_ErrorInvalidComponent;
    }
    int32_t err = OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    sptr<ICodecBuffer> codecBuffer = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBuffer, bufferHdrType) || codecBuffer == nullptr) {
        CODEC_LOGE("GetBufferById return false");
        return err;
    }
    err = codecBuffer->EmptyOmxBuffer(buffer, *bufferHdrType);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("EmptyOmxBuffer err [%{public}d]", err);
        return err;
    }

    err = OMX_EmptyThisBuffer(static_cast<OMX_HANDLETYPE>(comp_), bufferHdrType);
    return err;
}

int32_t ComponentNode::FillThisBuffer(struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        CODEC_LOGE("comp_ is nullptr");
        return OMX_ErrorInvalidComponent;
    }
    int32_t err = OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    sptr<ICodecBuffer> codecBuffer = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBuffer, bufferHdrType)) {
        CODEC_LOGE("GetBufferById return false");
        return err;
    }
    if (codecBuffer == nullptr) {
        CODEC_LOGE("fail to get codecBuffer");
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
        CODEC_LOGE("buffer is null");
        return sptr<ICodecBuffer>();
    }
    std::shared_lock<std::shared_mutex> lk(mapMutex_);
    auto iterHead = bufferHeaderMap_.find(buffer);
    if (iterHead == bufferHeaderMap_.end()) {
        CODEC_LOGE("can not find bufferID");
        return sptr<ICodecBuffer>();
    }

    uint32_t nBufferID = iterHead->second;
    auto iter = codecBufferMap_.find(nBufferID);
    if (iter == codecBufferMap_.end()) {
        CODEC_LOGE("can not find bufferInfo by nBufferID = %{public}d", nBufferID);
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
        CODEC_LOGE("can not find bufferIndo by bufferID [%{public}d]", bufferId);
        return false;
    }

    auto iterHead = bufferHeaderMap_.begin();
    for (; iterHead != bufferHeaderMap_.end(); iterHead++) {
        if (iterHead->second == bufferId) {
            break;
        }
    }
    if ((iterHead == bufferHeaderMap_.end()) || (iterHead->first == nullptr)) {
        CODEC_LOGE("can not find bufferHeaderType by bufferID [%{public}d] or iterHead->first is null", bufferId);
        return false;
    }
    bufferHdrType = iterHead->first;
    codecBuffer = iter->second;
    return true;
}

void ComponentNode::WaitStateChange(uint32_t objState, OMX_STATETYPE *status)
{
    int32_t ret = GetState(status);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("GetState error [%{public}x]", ret);
        return;
    }
    uint32_t count = 0;
    while (*status != objState && count++ < maxStateWaitCount) {
        usleep(maxStateWaitTime);
        ret = GetState(status);
        if (ret != HDF_SUCCESS) {
            CODEC_LOGE("GetState error [%{public}x]", ret);
            return;
        }
    }
}

void ComponentNode::ReleaseOMXResource()
{
    OMX_STATETYPE status = OMX_StateInvalid;
    int32_t ret = GetState(&status);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("ReleaseOMXResource GetState error [%{public}x]", ret);
        return;
    }
    if (status == OMX_StateExecuting) {
        SendCommand(OMX_CommandStateSet, OMX_StateIdle, NULL, 0);
        WaitStateChange(OMX_StateIdle, &status);
    }
    if (status == OMX_StateIdle) {
        SendCommand(OMX_CommandStateSet, OMX_StateLoaded, NULL, 0);
        auto err = ReleaseAllBuffer();
        if (err != HDF_SUCCESS) {
            CODEC_LOGE("ReleaseAllBuffer err [%{public}x]", err);
            return;
        }
        WaitStateChange(OMX_StateLoaded, &status);
    }
    CODEC_LOGI("Release OMX Resource success!");
}

int32_t ComponentNode::ReleaseAllBuffer()
{
    auto iter = bufferHeaderMap_.begin();
    for (; iter != bufferHeaderMap_.end(); iter++) {
        OMX_BUFFERHEADERTYPE *bufferHdrType = iter->first;
        uint32_t protIndex = bufferHeaderPortMap_.find(bufferHdrType)->second;
        auto ret = OMX_FreeBuffer((OMX_HANDLETYPE)comp_, protIndex, bufferHdrType);
        if (ret != OMX_ErrorNone) {
            CODEC_LOGE("OMX_FreeBuffer err [%{public}x]", ret);
            return ret;
        }
    }
    CODEC_LOGI("Release OMXBuffer and CodecBuffer success!");
    return HDF_SUCCESS;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
