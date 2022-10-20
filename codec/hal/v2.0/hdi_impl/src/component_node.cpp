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
#include <hdf_log.h>
#include <securec.h>
#include <unistd.h>
#include "icodec_buffer.h"

#define HDF_LOG_TAG codec_hdi_server
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

ComponentNode::ComponentNode(struct CodecCallbackType *callback, int64_t appData)
{
    appData_ = appData;
    comp_ = nullptr;
    codecBufferMap_.clear();
    bufferHeaderMap_.clear();
    omxCallback_ = callback;
    bufferIdCount_ = 0;
}

ComponentNode::~ComponentNode()
{
    if (omxCallback_ != nullptr) {
        CodecCallbackTypeRelease(omxCallback_);
        omxCallback_ = nullptr;
    }
    codecBufferMap_.clear();
    bufferHeaderMap_.clear();
    bufferIdCount_ = 0;
}

int32_t ComponentNode::GetComponentVersion(struct CompVerInfo &verInfo)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null or verInfo is null", __func__);
        return OMX_ErrorInvalidComponent;
    }
    int32_t err =
        OMX_GetComponentVersion(comp_, verInfo.compName, &verInfo.compVersion, &verInfo.specVersion, &verInfo.compUUID);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s error, OMX_GetComponentVersion err = %{public}d ", __func__, err);
        return err;
    }
    return err;
}

int32_t ComponentNode::SendCommand(OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)cmdDataLen;
    return OMX_SendCommand(comp_, cmd, param, cmdData);
}

int32_t ComponentNode::GetParameter(OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)paramLen;
    return OMX_GetParameter(comp_, paramIndex, param);
}

int32_t ComponentNode::SetParameter(OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen)
{
    if (comp_ == nullptr || param == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null or param is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)paramLen;
    return OMX_SetParameter(comp_, paramIndex, param);
}

int32_t ComponentNode::GetConfig(OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)configLen;
    return OMX_GetConfig(comp_, index, config);
}

int32_t ComponentNode::SetConfig(OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)configLen;
    return OMX_SetConfig(comp_, index, config);
}

int32_t ComponentNode::GetExtensionIndex(const char *parameterName, OMX_INDEXTYPE *indexType)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    // change name
    return OMX_GetExtensionIndex(comp_, const_cast<char *>(parameterName), indexType);
}

int32_t ComponentNode::GetState(OMX_STATETYPE *state)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }

    return OMX_GetState(comp_, state);
}

int32_t ComponentNode::ComponentTunnelRequest(uint32_t port, int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                              struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    unsigned long tunneledComp = (unsigned long)omxHandleTypeTunneledComp;
    return comType->ComponentTunnelRequest(comp_, port, (OMX_HANDLETYPE)tunneledComp, tunneledPort, tunnelSetup);
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

    auto err = OMX_UseEGLImage(comp_, &pBufferHdrType, portIndex, 0, eglImage);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s OMX_UseEGLImage error[0x%{public}x]", __func__, err);
        return err;
    }
    (void)buffer;
    (void)eglImageLen;
    return OMX_ErrorNotImplemented;
}

int32_t ComponentNode::ComponentRoleEnum(uint8_t *role, uint32_t roleLen, uint32_t index)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    uint8_t omxRole[ROLE_MAX_LEN] = {0};
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    int32_t err = comType->ComponentRoleEnum(comp_, omxRole, index);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s error, ComponentRoleEnum ret err [0x%{public}x] ", __func__, err);
        return err;
    }

    size_t omxRoleLen = strlen(reinterpret_cast<const char *>(omxRole));
    if (omxRoleLen == 0) {
        HDF_LOGW("%{public}s error, omxRoleLen is 0 [%{public}zu] ", __func__, omxRoleLen);
    } else {
        int32_t ret = memcpy_s(role, roleLen, omxRole, omxRoleLen);
        if (ret != EOK) {
            HDF_LOGE("%{public}s error, memcpy_s ret [%{public}d]", __func__, ret);
            return HDF_ERR_INVALID_PARAM;
        }
    }

    return OMX_ErrorNone;
}

int32_t ComponentNode::DeInit()
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    OMX_COMPONENTTYPE *comType = static_cast<OMX_COMPONENTTYPE *>(comp_);
    return comType->ComponentDeInit(comp_);
}

int32_t ComponentNode::OnEvent(OMX_EVENTTYPE event, uint32_t data1, uint32_t data2, void *eventData)
{
    if (omxCallback_ == nullptr) {
        HDF_LOGE("%{public}s omxCallback_ is null", __func__);
        return OMX_ErrorNone;
    }
    HDF_LOGD("%{public}s, event [%d], data1 [%d],data2 [%d]", __func__, event, data1, data2);
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
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        HDF_LOGE("%{public}s error, omxCallback_ or buffer is null", __func__);
        return OMX_ErrorNone;
    }
    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    if (codecBuffer == nullptr || codecBuffer->EmptyOmxBufferDone(*buffer) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s codecBuffer is null or EmptyOmxBufferDone error", __func__);
        return OMX_ErrorNone;
    }
    struct OmxCodecBuffer &codecOmxBuffer = codecBuffer->GetCodecBuffer();
    (void)omxCallback_->EmptyBufferDone(omxCallback_, appData_, &codecOmxBuffer);
    return OMX_ErrorNone;
}

int32_t ComponentNode::OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        HDF_LOGE("%{public}s error, omxCallback_ or buffer is null", __func__);
        return OMX_ErrorNone;
    }

    sptr<ICodecBuffer> codecBuffer = GetBufferInfoByHeader(buffer);
    if (codecBuffer == nullptr || codecBuffer->FillOmxBufferDone(*buffer) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s codecBuffer is null or EmptyOmxBufferDone error", __func__);
        return OMX_ErrorNone;
    }

    struct OmxCodecBuffer &codecOmxBuffer = codecBuffer->GetCodecBuffer();
    (void)omxCallback_->FillBufferDone(omxCallback_, appData_, &codecOmxBuffer);
    return OMX_ErrorNone;
}

int32_t ComponentNode::UseBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null", __func__);
        return OMX_ErrorInvalidComponent;
    }
    if (buffer.fenceFd >= 0) {
        close(buffer.fenceFd);
        buffer.fenceFd = -1;
    }

    int32_t err = OMX_ErrorBadParameter;
    sptr<ICodecBuffer> codecBuffer = ICodecBuffer::CreateCodeBuffer(buffer);
    if (codecBuffer == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null", __func__);
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
        HDF_LOGE("%{public}s : type [%{public}d] OMX_AllocateBuffer or OMX_UseBuffer ret err[%{public}x]", __func__,
                 buffer.bufferType, err);
        codecBuffer = nullptr;
        return err;
    }
    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    codecBuffer->SetBufferId(bufferId);
    codecBufferMap_.emplace(std::make_pair(bufferId, codecBuffer));
    bufferHeaderMap_.emplace(std::make_pair(bufferHdrType, bufferId));

    return err;
}

int32_t ComponentNode::AllocateBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null", __func__);
        return OMX_ErrorInvalidComponent;
    }
    OMX_BUFFERHEADERTYPE *bufferHdrType = 0;
    int32_t err = OMX_AllocateBuffer(static_cast<OMX_HANDLETYPE>(comp_), &bufferHdrType, portIndex, 0, buffer.allocLen);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s ,OMX_AllocateBuffer error, err = %{public}x", __func__, err);
        return err;
    }

    buffer.allocLen = bufferHdrType->nAllocLen;
    sptr<ICodecBuffer> codecBuffer = ICodecBuffer::AllocateCodecBuffer(buffer);
    if (codecBuffer == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null", __func__);
        (void)OMX_FreeBuffer(static_cast<OMX_HANDLETYPE>(comp_), portIndex, bufferHdrType);
        return OMX_ErrorInvalidComponent;
    }

    uint32_t bufferId = GenerateBufferId();
    buffer.bufferId = bufferId;
    codecBufferMap_.emplace(std::make_pair(bufferId, codecBuffer));
    bufferHeaderMap_.emplace(std::make_pair(bufferHdrType, bufferId));
    return OMX_ErrorNone;
}

int32_t ComponentNode::FreeBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ = %{public}p", __func__, comp_);
        return OMX_ErrorInvalidComponent;
    }

    int32_t err = OMX_ErrorBadParameter;
    sptr<ICodecBuffer> codecBufer = nullptr;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBufer, bufferHdrType)) {
        HDF_LOGE("%{public}s error, GetBufferById return false", __func__);
        return err;
    }

    err = OMX_FreeBuffer(static_cast<OMX_HANDLETYPE>(comp_), portIndex, bufferHdrType);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s error, OMX_FreeBuffer err [%{public}x]", __func__, err);
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
    (void)codecBufer->FreeBuffer(buffer);

    return err;
}

int32_t ComponentNode::EmptyThisBuffer(struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ = %{public}p", __func__, comp_);
        return OMX_ErrorInvalidComponent;
    }
    int32_t err = OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    sptr<ICodecBuffer> codecBuffer = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBuffer, bufferHdrType)) {
        HDF_LOGE("%{public}s error, GetBufferById return false", __func__);
        return err;
    }
    err = codecBuffer->EmptyOmxBuffer(buffer, *bufferHdrType);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s EmptyOmxBuffer err [%{public}d]", __func__, err);
        return err;
    }

    err = OMX_EmptyThisBuffer(static_cast<OMX_HANDLETYPE>(comp_), bufferHdrType);
    return err;
}

int32_t ComponentNode::FillThisBuffer(struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ = %{public}p", __func__, comp_);
        return OMX_ErrorInvalidComponent;
    }
    int32_t err = OMX_ErrorBadParameter;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    sptr<ICodecBuffer> codecBuffer = nullptr;
    if (!GetBufferById(buffer.bufferId, codecBuffer, bufferHdrType)) {
        HDF_LOGE("%{public}s error, GetBufferById return false", __func__);
        return err;
    }

    err = codecBuffer->FillOmxBuffer(buffer, *bufferHdrType);
    if (err != HDF_SUCCESS) {
        HDF_LOGE("%{public}s FillOmxBuffer err [%{public}d]", __func__, err);
        return err;
    }

    err = OMX_FillThisBuffer(static_cast<OMX_HANDLETYPE>(comp_), bufferHdrType);
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
        HDF_LOGE("%{public}s buffer is null", __func__);
        return nullptr;
    }

    auto iterHead = bufferHeaderMap_.find(buffer);
    if (iterHead == bufferHeaderMap_.end()) {
        HDF_LOGE("%{public}s can not find bufferID by pHeaderType = 0x%{public}p", __func__, buffer);
        return nullptr;
    }

    uint32_t nBufferID = iterHead->second;
    auto iter = codecBufferMap_.find(nBufferID);
    if (iter == codecBufferMap_.end()) {
        HDF_LOGE("%{public}s can not find bufferInfo by nBufferID = %{public}d", __func__, nBufferID);
        return nullptr;
    }
    return iter->second;
}

bool ComponentNode::GetBufferById(uint32_t bufferId, sptr<ICodecBuffer> &codecBuffer,
                                  OMX_BUFFERHEADERTYPE *&bufferHdrType)
{
    auto iter = codecBufferMap_.find(bufferId);
    if ((iter == codecBufferMap_.end()) || (iter->second == nullptr)) {
        HDF_LOGE("%{public}s error, can not find bufferIndo by bufferID [%{public}d]", __func__, bufferId);
        return false;
    }

    auto iterHead = bufferHeaderMap_.begin();
    for (; iterHead != bufferHeaderMap_.end(); iterHead++) {
        if (iterHead->second == bufferId) {
            break;
        }
    }
    if ((iterHead == bufferHeaderMap_.end()) || (iterHead->first == nullptr)) {
        HDF_LOGE("%{public}s error, can not find bufferHeaderType by bufferID [%{public}d] or iterHead->first is null",
                 __func__, bufferId);
        return false;
    }
    bufferHdrType = iterHead->first;
    codecBuffer = iter->second;
    return true;
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS