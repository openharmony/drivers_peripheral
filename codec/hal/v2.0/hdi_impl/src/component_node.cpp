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

#include <ashmem.h>
#include <buffer_handle.h>
#include <cstring>
#include <hdf_log.h>
#include <memory.h>
#include <securec.h>
#include <sys/mman.h>
#include <unistd.h>

#include "component_node.h"

#define HDF_LOG_TAG codec_hdi_server
#define FD_SIZE     sizeof(int)
constexpr int ROLE_MAX_LEN = 256;
namespace OHOS {
namespace Codec {
namespace Omx {
OMX_ERRORTYPE ComponentNode::OnEvent(OMX_HANDLETYPE component, void *appData, OMX_EVENTTYPE event, uint32_t data1,
                                     uint32_t data2, void *eventData)
{
    ComponentNode *node = (ComponentNode *)appData;
    (void)component;
    if (node != nullptr) {
        node->OnEvent(event, data1, data2, eventData);
    }

    return OMX_ErrorNone;
}

OMX_ERRORTYPE ComponentNode::OnEmptyBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer)
{
    ComponentNode *node = (ComponentNode *)appData;
    (void)component;
    if (node != nullptr) {
        node->OnEmptyBufferDone(buffer);
    }
    return OMX_ErrorNone;
}

OMX_ERRORTYPE ComponentNode::OnFillBufferDone(OMX_HANDLETYPE component, void *appData, OMX_BUFFERHEADERTYPE *buffer)
{
    ComponentNode *node = (ComponentNode *)appData;
    (void)component;
    if (node != nullptr) {
        node->OnFillBufferDone(buffer);
    }
    return OMX_ErrorNone;
}

OMX_CALLBACKTYPE ComponentNode::callbacks_ = {&ComponentNode::OnEvent, &ComponentNode::OnEmptyBufferDone,
                                              &ComponentNode::OnFillBufferDone};

ComponentNode::ComponentNode(struct CodecCallbackType *callback, int8_t *appData, int32_t appDataLen)
{
    if (appData != nullptr && appDataLen != 0) {
        appData_ = (int8_t *)OsalMemCalloc(sizeof(int8_t) * appDataLen);
        (void)memcpy_s(appData_, appDataLen, appData, appDataLen);
        appDataSize_ = appDataLen;
    } else {
        appData_ = nullptr;
        appDataSize_ = 0;
    }
    comp_ = nullptr;
    bufferInfoMap_.clear();
    bufferHeaderMap_.clear();
    omxCallback_ = callback;
    bufferIdCount_ = 0;
#ifdef NODE_DEBUG
    char filename[256] = {0};
    (void)snprintf_s(filename, sizeof(filename), sizeof(filename) - 1, "/data/codec_in_%p.h264", this);
    fp_in = fopen(filename, "wb+");
    (void)snprintf_s(filename, sizeof(filename), sizeof(filename) - 1, "/data/codec_out_%p.yuv", this);
    fp_out = fopen(filename, "wb+");
#endif
}

ComponentNode::~ComponentNode()
{
#ifdef NODE_DEBUG
    if (fp_in != nullptr) {
        fclose(fp_in);
        fp_in = nullptr;
    }

    if (fp_out != nullptr) {
        fclose(fp_out);
        fp_out = nullptr;
    }
#endif

    if (appData_ != nullptr) {
        OsalMemFree(appData_);
        appData_ = nullptr;
        appDataSize_ = 0;
    }

    if (omxCallback_ != nullptr) {
        OsalMemFree(omxCallback_);
        omxCallback_ = nullptr;
    }

    HDF_LOGI("%{public}s bufferInfoMap_.size()=[%{public}d],bufferHeaderMap_.size()=[%{public}d]", __func__,
             bufferInfoMap_.size(), bufferHeaderMap_.size());
    bufferInfoMap_.clear();
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

int32_t ComponentNode::SendCommand(enum OMX_COMMANDTYPE cmd, uint32_t param, int8_t *cmdData, uint32_t cmdDataLen)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)cmdDataLen;
    return OMX_SendCommand(comp_, cmd, param, cmdData);
}

int32_t ComponentNode::GetParameter(enum OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)paramLen;
    return OMX_GetParameter(comp_, paramIndex, param);
}

int32_t ComponentNode::SetParameter(enum OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen)
{
    if (comp_ == nullptr || param == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null or param is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)paramLen;
    return OMX_SetParameter(comp_, paramIndex, param);
}

int32_t ComponentNode::GetConfig(enum OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)configLen;
    return OMX_GetConfig(comp_, index, config);
}

int32_t ComponentNode::SetConfig(enum OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    (void)configLen;
    return OMX_SetConfig(comp_, index, config);
}

int32_t ComponentNode::GetExtensionIndex(const char *parameterName, enum OMX_INDEXTYPE *indexType)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null ", __func__);
        return OMX_ErrorInvalidComponent;
    }
    // change name
    return OMX_GetExtensionIndex(comp_, const_cast<char *>(parameterName), indexType);
}

int32_t ComponentNode::GetState(enum OMX_STATETYPE *state)
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
    return comType->ComponentTunnelRequest(comp_, port, (OMX_HANDLETYPE)omxHandleTypeTunneledComp, tunneledPort,
                                           tunnelSetup);
}

int32_t ComponentNode::SetCallbacks(struct CodecCallbackType *omxCallback, int8_t *appData, uint32_t appDataLen)
{
    // release this->omxCallback_
    if (this->omxCallback_ != nullptr) {
        OsalMemFree(this->omxCallback_);
        this->omxCallback_ = nullptr;
    }

    this->omxCallback_ = omxCallback;

    if (this->appData_ != nullptr) {
        OsalMemFree(this->appData_);
        this->appData_ = nullptr;
    }
    if ((appData != nullptr) && appDataLen != 0) {
        this->appData_ = (int8_t *)OsalMemCalloc(sizeof(int8_t) * appDataLen);
        (void)memcpy_s(this->appData_, appDataLen, appData, appDataLen);
    }
    this->appDataSize_ = appDataLen;
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
    size_t omxRoleLen = strlen((const char *)omxRole);
    (void)memcpy_s(role, roleLen, omxRole, omxRoleLen);
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

    struct EventInfo info = {0};
    info.appData = appData_;
    info.appDataLen = appDataSize_;
    info.data1 = data1;
    info.data2 = data2;
    info.eventData = static_cast<int8_t *>(eventData);
    info.eventDataLen = 0;
    omxCallback_->EventHandler(omxCallback_, event, &info);

    return OMX_ErrorNone;
}

int32_t ComponentNode::OnEmptyBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        HDF_LOGE("%{public}s error, omxCallback_ or buffer is null", __func__);
        return OMX_ErrorNone;
    }
    BufferInfoSPtr bufferInfo = GetBufferInfoByHeader(buffer);
    if (bufferInfo == nullptr) {
        HDF_LOGE("%{public}s get bufferinfo by header[0x%{public}p] error", __func__, buffer);
        return OMX_ErrorNone;
    }

    struct OmxCodecBuffer &omxCodecBuffer = bufferInfo->omxCodecBuffer;
    switch (omxCodecBuffer.bufferType) {
        case BUFFER_TYPE_AVSHARE_MEM_FD: {
            omxCodecBuffer.offset = buffer->nOffset;
            omxCodecBuffer.filledLen = buffer->nFilledLen;
            break;
        }

        case BUFFER_TYPE_HANDLE: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle = %{public}d is not implement", __func__,
                     omxCodecBuffer.bufferType);
            break;
        }

        case BUFFER_TYPE_DYNAMIC_HANDLE: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle = %{public}d is not implement", __func__,
                     omxCodecBuffer.bufferType);
            break;
        }
        default: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle = %{public}d is not implement", __func__,
                     omxCodecBuffer.bufferType);
            break;
        }
    }

    omxCallback_->EmptyBufferDone(omxCallback_, appData_, appDataSize_, &omxCodecBuffer);
    return OMX_ErrorNone;
}

int32_t ComponentNode::OnFillBufferDone(OMX_BUFFERHEADERTYPE *buffer)
{
    if ((omxCallback_ == nullptr) || (buffer == nullptr)) {
        HDF_LOGE("%{public}s error, omxCallback_ or buffer is null", __func__);
        return OMX_ErrorNone;
    }

    BufferInfoSPtr bufferInfo = GetBufferInfoByHeader(buffer);
    if (bufferInfo == nullptr) {
        HDF_LOGE("%{public}s error, GetBufferInfoByHeader return null", __func__);
        return OMX_ErrorNone;
    }

    struct OmxCodecBuffer &omxCodecBuffer = bufferInfo->omxCodecBuffer;

    switch (omxCodecBuffer.bufferType) {
        case BUFFER_TYPE_AVSHARE_MEM_FD: {
            if (!bufferInfo->sharedMem->WriteToAshmem(buffer->pBuffer, buffer->nFilledLen, buffer->nOffset)) {
                HDF_LOGE("%{public}s write to ashmem fail", __func__);
                return OMX_ErrorNone;
            }
#ifdef NODE_DEBUG
            (void)fwrite(buffer->buffer + buffer->nOffset, 1, buffer->nFilledLen, fp_out);
            (void)fflush(fp_out);
#endif
            omxCodecBuffer.offset = buffer->nOffset;
            omxCodecBuffer.filledLen = buffer->nFilledLen;
            break;
        }

        case BUFFER_TYPE_HANDLE: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle = %{public}d is not implement", __func__,
                     omxCodecBuffer.bufferType);
            break;
        }

        case BUFFER_TYPE_DYNAMIC_HANDLE: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle = %{public}d is not implement", __func__,
                     omxCodecBuffer.bufferType);
            break;
        }
        default: {
            break;
        }
    }

    // save the flags
    omxCodecBuffer.flag = buffer->nFlags;
    omxCodecBuffer.pts = buffer->nTimeStamp;
    omxCallback_->FillBufferDone(omxCallback_, appData_, appDataSize_, &omxCodecBuffer);

    return OMX_ErrorNone;
}

int32_t ComponentNode::UseBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null", __func__);
        return OMX_ErrorInvalidComponent;
    }

    int32_t err = OMX_ErrorUndefined;

    switch (buffer.bufferType) {
        case BUFFER_TYPE_AVSHARE_MEM_FD:
            err = UseSharedBuffer(buffer, portIndex);
            break;
        case BUFFER_TYPE_HANDLE:
            err = UseHandleBuffer(buffer, portIndex);
            break;
        case BUFFER_TYPE_DYNAMIC_HANDLE:
            err = UseDynaHandleBuffer(buffer, portIndex);
            break;
        default:
            break;
    }

    return err;
}

int32_t ComponentNode::AllocateBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ is null", __func__);
        return OMX_ErrorInvalidComponent;
    }

    OMX_BUFFERHEADERTYPE *bufferHdrType = 0;
    int32_t err = OMX_AllocateBuffer((OMX_HANDLETYPE)comp_, &bufferHdrType, portIndex, 0, buffer.allocLen);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s ,OMX_AllocateBuffer error, err = %{public}x", __func__, err);
        return err;
    }

    // create shared memory
    int sharedFD = AshmemCreate(nullptr, bufferHdrType->nAllocLen);
    std::shared_ptr<Ashmem> sharedMemory = std::make_shared<Ashmem>(sharedFD, bufferHdrType->nAllocLen);
    SaveBufferInfo(buffer, bufferHdrType, sharedMemory);
    buffer.buffer = (uint8_t *)&sharedFD;
    buffer.bufferLen = FD_SIZE;
    return OMX_ErrorNone;
}

int32_t ComponentNode::FreeBuffer(uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ = %{public}p", __func__, comp_);
        return OMX_ErrorInvalidComponent;
    }
    CheckBuffer(buffer);
    int32_t err = OMX_ErrorUndefined;
    BufferInfoSPtr bufferInfo = nullptr;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    if (!GetBufferById(buffer.bufferId, bufferInfo, bufferHdrType)) {
        HDF_LOGE("%{public}s error, GetBufferById return false", __func__);
        return err;
    }
    switch (bufferInfo->omxCodecBuffer.bufferType) {
        case BUFFER_TYPE_AVSHARE_MEM_FD: {
            err = OMX_FreeBuffer((OMX_HANDLETYPE)comp_, portIndex, bufferHdrType);
            HDF_LOGI("%{public}s , OMX_FreeBuffer ret [0x%{public}x]", __func__, err);
            break;
        }

        case BUFFER_TYPE_HANDLE: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle is not implement", __func__);
            err = OMX_ErrorUndefined;
            break;
        }

        case BUFFER_TYPE_DYNAMIC_HANDLE: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle is not implement", __func__);
            err = OMX_ErrorUndefined;
            break;
        }
        default: {
            err = OMX_ErrorUndefined;
            break;
        }
    }
    if (err == OMX_ErrorNone) {
        ReleaseBufferById(buffer.bufferId);
        bufferInfo = nullptr;
    }
    return err;
}

int32_t ComponentNode::EmptyThisBuffer(struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ = %{public}p", __func__, comp_);
        return OMX_ErrorInvalidComponent;
    }
    CheckBuffer(buffer);
    int32_t err = OMX_ErrorUndefined;
    BufferInfoSPtr bufferInfo = nullptr;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    if (!GetBufferById(buffer.bufferId, bufferInfo, bufferHdrType)) {
        HDF_LOGE("%{public}s error, GetBufferById return false", __func__);
        return err;
    }
    switch (bufferInfo->omxCodecBuffer.bufferType) {
        case BUFFER_TYPE_AVSHARE_MEM_FD: {
            err = EmptySharedBuffer(buffer, bufferInfo, bufferHdrType);
            break;
        }
        // When empty buffer, this case is disabled
        case BUFFER_TYPE_HANDLE: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle is not implement", __func__);
            err = OMX_ErrorBadParameter;
            break;
        }

        case BUFFER_TYPE_DYNAMIC_HANDLE: {
            int eFence = buffer.fenceFd;
            if (eFence > 0) {
                ;  // sync_wait(eFence, 5);
            }
            err = OMX_ErrorNone;
            break;
        }
        default: {
            err = OMX_ErrorUndefined;
            break;
        }
    }

    if (err == OMX_ErrorNone) {
        bufferHdrType->nOffset = buffer.offset;
        bufferHdrType->nFilledLen = buffer.filledLen;
        bufferHdrType->nFlags = buffer.flag;
        err = OMX_EmptyThisBuffer((OMX_HANDLETYPE)comp_, bufferHdrType);
    }
    return err;
}

int32_t ComponentNode::FillThisBuffer(struct OmxCodecBuffer &buffer)
{
    if (comp_ == nullptr) {
        HDF_LOGE("%{public}s error, comp_ = %{public}p", __func__, comp_);
        return OMX_ErrorInvalidComponent;
    }

    CheckBuffer(buffer);

    int32_t err = OMX_ErrorUndefined;
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    BufferInfoSPtr bufferInfo = nullptr;
    if (!GetBufferById(buffer.bufferId, bufferInfo, bufferHdrType)) {
        HDF_LOGE("%{public}s error, GetBufferById return false", __func__);
        return err;
    }

    switch (bufferInfo->omxCodecBuffer.bufferType) {
        case BUFFER_TYPE_AVSHARE_MEM_FD: {
            if ((bufferInfo->sharedMem == nullptr) || (bufferInfo->omxCodecBuffer.type != READ_WRITE_TYPE)) {
                HDF_LOGE("%{public}s error, pBufferHdrType [0x%{public}p] omxCodecBuffer.type[%{public}d]", __func__,
                         bufferHdrType, bufferInfo->omxCodecBuffer.type);
            } else {
                err = OMX_ErrorNone;
            }

            break;
        }
        case BUFFER_TYPE_HANDLE: {
            int eFence = buffer.fenceFd;
            if (eFence > 0) {
                ;  // we may sync_wait here// sync_wait(eFence, 5);
            }
            err = OMX_ErrorUndefined;
            break;
        }
        default: {
            HDF_LOGE("%{public}s error, bufferTypeBufferHandle = %{public}d is not implement", __func__,
                     bufferInfo->omxCodecBuffer.bufferType);
            err = OMX_ErrorBadParameter;
            break;
        }
    }

    if (err == OMX_ErrorNone) {
        // check this
        bufferHdrType->nOffset = buffer.offset;
        bufferHdrType->nFilledLen = buffer.filledLen;
        err = OMX_FillThisBuffer((OMX_HANDLETYPE)comp_, bufferHdrType);
    }
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
    } while (bufferInfoMap_.find(bufferId) != bufferInfoMap_.end());
    return bufferId;
}

void ComponentNode::CheckBuffer(struct OmxCodecBuffer &buffer)
{
    if ((buffer.buffer != nullptr) && (buffer.bufferType == BUFFER_TYPE_AVSHARE_MEM_FD) &&
        (buffer.bufferLen == FD_SIZE)) {
        int fd = reinterpret_cast<int>(buffer.buffer);
        close(fd);
        buffer.buffer = 0;
        buffer.bufferLen = 0;
    }
}

BufferInfoSPtr ComponentNode::GetBufferInfoByHeader(OMX_BUFFERHEADERTYPE *buffer)
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
    HDF_LOGI("%{public}s buffer[%{public}p], nBufferID[%{public}d], ", __func__, buffer, nBufferID);

    auto iter = bufferInfoMap_.find(nBufferID);
    if (iter == bufferInfoMap_.end()) {
        HDF_LOGE("%{public}s can not find bufferInfo by nBufferID = %{public}d", __func__, nBufferID);
        return nullptr;
    }
    BufferInfoSPtr bufferInfo = iter->second;
    if (bufferInfo == nullptr) {
        HDF_LOGE("%{public}s pBufferInfo is null", __func__);
        return nullptr;
    }

    return bufferInfo;
}

bool ComponentNode::GetBufferById(uint32_t bufferId, BufferInfoSPtr &bufferInfo, OMX_BUFFERHEADERTYPE *&bufferHdrType)
{
    auto iter = bufferInfoMap_.find(bufferId);
    if ((iter == bufferInfoMap_.end()) || (iter->second == nullptr)) {
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
    bufferInfo = iter->second;
    return true;
}

void ComponentNode::ReleaseBufferById(uint32_t bufferId)
{
    auto iter = bufferInfoMap_.find(bufferId);
    if ((iter == bufferInfoMap_.end()) || (iter->second == nullptr)) {
        HDF_LOGE("%{public}s error, can not find bufferIndo by bufferID [%{public}d]", __func__, bufferId);
        return;
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
        return;
    }
    BufferInfoSPtr bufferInfo = iter->second;
    bufferInfoMap_.erase(iter);
    bufferHeaderMap_.erase(iterHead);
    bufferInfo = nullptr;
}

int32_t ComponentNode::UseSharedBuffer(struct OmxCodecBuffer &omxCodecBuffer, uint32_t portIndex)
{
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    int32_t err = OMX_ErrorUndefined;
    if (omxCodecBuffer.bufferLen != FD_SIZE) {
        HDF_LOGE("%{public}s error, omxCodecBuffer.bufferLen = %{public}d ", __func__, omxCodecBuffer.bufferLen);
        return err;
    }

    int shardFd = reinterpret_cast<int>(omxCodecBuffer.buffer);
    if (shardFd < 0) {
        HDF_LOGE("%{public}s error, shardFd < 0", __func__);
        return err;
    }

    int size = AshmemGetSize(shardFd);
    HDF_LOGI("%{public}s , shardFd = %{public}d, size = %{public}d", __func__, shardFd, size);
    std::shared_ptr<Ashmem> sharedMem = std::make_shared<Ashmem>(shardFd, size);
    // check READ/WRITE
    bool mapd = false;
    if (omxCodecBuffer.type == READ_WRITE_TYPE) {
        mapd = sharedMem->MapReadAndWriteAshmem();
    } else {
        mapd = sharedMem->MapReadOnlyAshmem();
    }

    if (!mapd) {
        HDF_LOGE("%{public}s error, MapReadAndWriteAshmem or MapReadOnlyAshmem return false", __func__);
        return err;
    }

    err = OMX_AllocateBuffer((OMX_HANDLETYPE)comp_, &bufferHdrType, portIndex, 0, omxCodecBuffer.allocLen);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s error, OMX_AllocateBuffer failed", __func__);
        sharedMem->UnmapAshmem();
        sharedMem->CloseAshmem();
        sharedMem = nullptr;
        return err;
    }
    SaveBufferInfo(omxCodecBuffer, bufferHdrType, sharedMem);

    return err;
}
int32_t ComponentNode::UseHandleBuffer(struct OmxCodecBuffer &omxCodecBuffer, uint32_t portIndex)
{
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    int32_t err = OMX_ErrorUndefined;

    if (sizeof(BufferHandle) != omxCodecBuffer.bufferLen) {
        HDF_LOGE("%{public}s error, BufferHandle size = %{public}d, omxBuffer.ptrSize = %{public}d ", __func__,
                 sizeof(BufferHandle), omxCodecBuffer.bufferLen);
        return err;
    }

    BufferHandle *bufferHandle = (BufferHandle *)omxCodecBuffer.buffer;
    (void)bufferHandle;
    // bufferHandle trans to native_handle_t, then use native_handle_t in omx
    err = OMX_UseBuffer((OMX_HANDLETYPE)comp_, &bufferHdrType, portIndex, 0, omxCodecBuffer.allocLen, nullptr);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s error, OMX_UseBuffer ret[%{public}d]", __func__, err);
    }
    HDF_LOGW("%{public}s error, bufferType BufferHandle is not implement", __func__);
    // bufferID
    SaveBufferInfo(omxCodecBuffer, bufferHdrType, nullptr);
    return err;
}

int32_t ComponentNode::UseDynaHandleBuffer(struct OmxCodecBuffer &omxCodecBuffer, uint32_t portIndex)
{
    OMX_BUFFERHEADERTYPE *bufferHdrType = nullptr;
    int32_t err = OMX_ErrorUndefined;
    // check: buffer need alloc 8 Bytes
    // type 4 Bytes，native_handle 4 Bytes
    err = OMX_UseBuffer((OMX_HANDLETYPE)comp_, &bufferHdrType, portIndex, 0, omxCodecBuffer.allocLen, nullptr);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s error, OMX_UseBuffer ret [%{public}d]", __func__, err);
    }
    HDF_LOGW("%{public}s error, bufferTypeBufferHandle is not implement", __func__);
    // bufferID
    SaveBufferInfo(omxCodecBuffer, bufferHdrType, nullptr);
    return err;
}

int32_t ComponentNode::EmptySharedBuffer(struct OmxCodecBuffer &buffer, BufferInfoSPtr bufferInfo,
                                         OMX_BUFFERHEADERTYPE *bufferHdrType)
{
    void *sharedPtr = const_cast<void *>(bufferInfo->sharedMem->ReadFromAshmem(buffer.filledLen, buffer.offset));
    if (!sharedPtr) {
        HDF_LOGE("%{public}s error, omxBuffer.length [%{public}d omxBuffer.offset[%{public}d]", __func__,
                 buffer.filledLen, buffer.offset);
        return OMX_ErrorUndefined;
    }
    auto ret = memcpy_s(bufferHdrType->pBuffer + buffer.offset, buffer.allocLen - buffer.offset, sharedPtr,
                        buffer.filledLen);
    if (ret != EOK) {
        HDF_LOGE("%{public}s error, memcpy_s ret [%{public}d", __func__, ret);
        return OMX_ErrorUndefined;
    }

#ifdef NODE_DEBUG
    (void)fwrite(sharedPtr, 1, buffer->filledLen, fp_in);
    (void)fflush(fp_in);
#endif

    return OMX_ErrorNone;
}

void ComponentNode::SaveBufferInfo(struct OmxCodecBuffer &omxCodecBuffer, OMX_BUFFERHEADERTYPE *bufferHdrType,
                                   std::shared_ptr<Ashmem> sharedMem)
{
    BufferInfoSPtr bufferInfo = std::make_shared<BufferInfo>();
    uint32_t bufferId = GenerateBufferId();
    // set bufferId
    omxCodecBuffer.bufferId = bufferId;
    omxCodecBuffer.version = bufferHdrType->nVersion;
    omxCodecBuffer.allocLen = bufferHdrType->nAllocLen;
    omxCodecBuffer.filledLen = bufferHdrType->nFilledLen;
    omxCodecBuffer.offset = bufferHdrType->nOffset;
    omxCodecBuffer.pts = bufferHdrType->nTimeStamp;
    omxCodecBuffer.flag = bufferHdrType->nFlags;

    bufferInfo->omxCodecBuffer = omxCodecBuffer;
    bufferInfo->omxCodecBuffer.buffer = 0;
    bufferInfo->omxCodecBuffer.bufferLen = 0;
    bufferInfo->sharedMem = sharedMem;
    uint32_t bufferIdTemp = bufferId;
    bufferInfoMap_.insert(std::make_pair<uint32_t, BufferInfoSPtr>(std::move(bufferId), std::move(bufferInfo)));
    bufferHeaderMap_.insert(
        std::make_pair<OMX_BUFFERHEADERTYPE *, uint32_t>(std::move(bufferHdrType), std::move(bufferIdTemp)));
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS