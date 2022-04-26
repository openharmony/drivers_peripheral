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

#include <hdf_log.h>

#include "component_node_mgr.h"

#define HDF_LOG_TAG codec_hdi_server

namespace OHOS {
namespace Codec {
namespace Omx {
ComponentNodeMgr::ComponentNodeMgr()
{
    compMgr_ = std::make_shared<ComponentMgr>();
}

ComponentNodeMgr::~ComponentNodeMgr()
{
    if (compMgr_ != nullptr) {
        compMgr_ = nullptr;
    }

    auto iter = nodeMaps_.begin();
    while (iter != nodeMaps_.end()) {
        iter = nodeMaps_.erase(iter);
    }
}

int32_t ComponentNodeMgr::CreateComponent(OMX_HANDLETYPE *compHandle, char *compName, int8_t *appData,
                                          int32_t appDataSize, struct CodecCallbackType *callbacks)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }
    OMX_COMPONENTTYPE *comp = nullptr;
    std::shared_ptr<ComponentNode> node = std::make_shared<ComponentNode>(callbacks, appData, appDataSize);
    auto err = compMgr_->CreateComponentInstance(compName, &ComponentNode::callbacks_, node.get(), &comp);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s ceate component instance error", __func__);
        node = nullptr;
        return err;
    }
    HDF_LOGI("%{public}s ceate component handle [%{public}p] ", __func__, comp);

    *compHandle = (OMX_HANDLETYPE)comp;
    node->SetHandle((OMX_HANDLETYPE)comp);
    nodeMaps_.emplace(std::make_pair(comp, node));
    return err;
}

int32_t ComponentNodeMgr::DestoryComponent(OMX_HANDLETYPE compHandle)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    OMX_COMPONENTTYPE *comp = (OMX_COMPONENTTYPE *)compHandle;

    auto iter = nodeMaps_.find((OMX_HANDLETYPE)comp);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }

    int32_t err = compMgr_->DeleteComponentInstance(comp);
    if (err == OMX_ErrorNone) {
        nodeMaps_.erase(iter);
    }
    return err;
}

int32_t ComponentNodeMgr::GetComponentVersion(OMX_HANDLETYPE compHandle, struct CompVerInfo &verInfo)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }

    return iter->second->GetComponentVersion(verInfo);
}

int32_t ComponentNodeMgr::SendCommand(OMX_HANDLETYPE compHandle, enum OMX_COMMANDTYPE cmd, uint32_t param,
                                      int8_t *cmdData, uint32_t cmdDataLen)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->SendCommand(cmd, param, cmdData, cmdDataLen);
}

int32_t ComponentNodeMgr::GetParameter(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE paramIndex, int8_t *param,
                                       uint32_t paramLen)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->GetParameter(paramIndex, param, paramLen);
}

int32_t ComponentNodeMgr::SetParameter(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE paramIndex, int8_t *param,
                                       uint32_t paramLen)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->SetParameter(paramIndex, param, paramLen);
}

int32_t ComponentNodeMgr::GetConfig(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *config,
                                    uint32_t configLen)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->GetConfig(index, config, configLen);
}

int32_t ComponentNodeMgr::SetConfig(OMX_HANDLETYPE compHandle, enum OMX_INDEXTYPE index, int8_t *config,
                                    uint32_t configLen)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->SetConfig(index, config, configLen);
}

int32_t ComponentNodeMgr::GetExtensionIndex(OMX_HANDLETYPE compHandle, const char *parameterName,
                                            enum OMX_INDEXTYPE *indexType)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->GetExtensionIndex(parameterName, indexType);
}

int32_t ComponentNodeMgr::GetState(OMX_HANDLETYPE compHandle, enum OMX_STATETYPE *state)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->GetState(state);
}

int32_t ComponentNodeMgr::ComponentTunnelRequest(OMX_HANDLETYPE compHandle, uint32_t port,
                                                 int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                                 struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->ComponentTunnelRequest(port, omxHandleTypeTunneledComp, tunneledPort, tunnelSetup);
}

int32_t ComponentNodeMgr::UseBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->UseBuffer(portIndex, buffer);
}

int32_t ComponentNodeMgr::AllocateBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->AllocateBuffer(portIndex, buffer);
}

int32_t ComponentNodeMgr::FreeBuffer(OMX_HANDLETYPE compHandle, uint32_t portIndex, struct OmxCodecBuffer &buffer)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->FreeBuffer(portIndex, buffer);
}

int32_t ComponentNodeMgr::EmptyThisBuffer(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer &buffer)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->EmptyThisBuffer(buffer);
}

int32_t ComponentNodeMgr::FillThisBuffer(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer &buffer)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }
    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->FillThisBuffer(buffer);
}

int32_t ComponentNodeMgr::SetCallbacks(OMX_HANDLETYPE compHandle, struct CodecCallbackType *omxCallback,
                                       int8_t *appData, uint32_t appDataLen)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }
    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->SetCallbacks(omxCallback, appData, appDataLen);
}

int32_t ComponentNodeMgr::DeInit(OMX_HANDLETYPE compHandle)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }
    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->DeInit();
}

int32_t ComponentNodeMgr::UseEglImage(OMX_HANDLETYPE compHandle, struct OmxCodecBuffer &buffer, uint32_t portIndex,
                                      int8_t *eglImage, uint32_t eglImageLen)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->UseEglImage(buffer, portIndex, eglImage, eglImageLen);
}

int32_t ComponentNodeMgr::ComponentRoleEnum(OMX_HANDLETYPE compHandle, uint8_t *role, uint32_t roleLen, uint32_t index)
{
    if (!compMgr_->IsLoadLibSuc()) {
        HDF_LOGE("%{public}s error loaded lib failed", __func__);
        return OMX_ErrorInvalidComponent;
    }

    auto iter = nodeMaps_.find(compHandle);
    if (iter == nodeMaps_.end()) {
        HDF_LOGE("%{public}s can not find nodeInstance by component %{public}p", __func__, compHandle);
        return OMX_ErrorInvalidComponent;
    }
    return iter->second->ComponentRoleEnum(role, roleLen, index);
}
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS