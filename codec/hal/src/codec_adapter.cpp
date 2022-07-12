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
#include <memory.h>
#include <securec.h>
#include "codec_adapter_interface.h"
#include "component_mgr.h"
#include "component_node.h"
using namespace OHOS::Codec::Omx;

static ComponentMgr g_mgr;
struct CodecComponentNode {
    std::shared_ptr<ComponentNode> node;
};
#ifdef __cplusplus
extern "C" {
#endif

int32_t OMXAdapterCreateComponent(struct CodecComponentNode **codecNode, char *compName, int64_t appData,
                                  struct CodecCallbackType *callbacks)
{
    OMX_COMPONENTTYPE *comp = nullptr;
    CodecComponentNode *tempNode = new CodecComponentNode;
    if (codecNode == nullptr) {
        HDF_LOGE("%{public}s create CodecComponentNode error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }
    tempNode->node = std::make_shared<ComponentNode>(callbacks, appData);
    auto err = g_mgr.CreateComponentInstance(compName, &ComponentNode::callbacks_, tempNode->node.get(), &comp);
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s create component instance err[%{public}d]", __func__, err);
        delete tempNode;
        tempNode = nullptr;
        return err;
    }
    tempNode->node->SetHandle((OMX_HANDLETYPE)comp);

    *codecNode = tempNode;
    return HDF_SUCCESS;
}

int32_t OmxAdapterDestroyComponent(struct CodecComponentNode *codecNode)
{
    if (codecNode == nullptr || codecNode->node == nullptr) {
        HDF_LOGE("%{public}s codecNode is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    auto err = g_mgr.DeleteComponentInstance((OMX_COMPONENTTYPE *)codecNode->node->GetHandle());
    if (err != OMX_ErrorNone) {
        HDF_LOGE("%{public}s DeleteComponentInstance err[%{public}d]", __func__, err);
        return err;
    }
    codecNode->node = nullptr;
    delete codecNode;
    codecNode = nullptr;
    return HDF_SUCCESS;
}

int32_t OmxAdapterComponentVersion(struct CodecComponentNode *codecNode, struct CompVerInfo *verInfo)
{
    if (codecNode == nullptr || codecNode->node == nullptr || verInfo == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or verInfois is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetComponentVersion(*verInfo);
}

int32_t OmxAdapterSendCommand(struct CodecComponentNode *codecNode, enum OMX_COMMANDTYPE cmd, uint32_t param,
                              int8_t *cmdData, uint32_t cmdDataLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr) {
        HDF_LOGE("%{public}s codecNode or node is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SendCommand(cmd, param, cmdData, cmdDataLen);
}

int32_t OmxAdapterGetParameter(struct CodecComponentNode *codecNode, enum OMX_INDEXTYPE paramIndex, int8_t *param,
                               uint32_t paramLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || param == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return codecNode->node->GetParameter(paramIndex, param, paramLen);
}

int32_t OmxAdapterSetParameter(struct CodecComponentNode *codecNode, enum OMX_INDEXTYPE index, int8_t *param,
                               uint32_t paramLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || param == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SetParameter(index, param, paramLen);
}

int32_t OmxAdapterGetConfig(struct CodecComponentNode *codecNode, enum OMX_INDEXTYPE index, int8_t *config,
                            uint32_t configLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || config == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or config is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetConfig(index, config, configLen);
}

int32_t OmxAdapterSetConfig(struct CodecComponentNode *codecNode, enum OMX_INDEXTYPE index, int8_t *config,
                            uint32_t configLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || config == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or config is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SetConfig(index, config, configLen);
}

int32_t OmxAdapterGetExtensionIndex(struct CodecComponentNode *codecNode, const char *parameterName,
                                    enum OMX_INDEXTYPE *indexType)
{
    if (codecNode == nullptr || codecNode->node == nullptr || parameterName == nullptr || indexType == nullptr) {
        HDF_LOGE("%{public}s codecNode, node , parameterName or indexType is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetExtensionIndex(parameterName, indexType);
}

int32_t OmxAdapterGetState(struct CodecComponentNode *codecNode, enum OMX_STATETYPE *state)
{
    if (codecNode == nullptr || codecNode->node == nullptr || state == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or state is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetState(state);
}

int32_t OmxAdapterComponentTunnelRequest(struct CodecComponentNode *codecNode, uint32_t port,
                                         int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                         struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    if (codecNode == nullptr || codecNode->node == nullptr || tunnelSetup == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or tunnelSetup is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->ComponentTunnelRequest(port, omxHandleTypeTunneledComp, tunneledPort, tunnelSetup);
}

int32_t OmxAdapterUseBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->UseBuffer(portIndex, *omxBuffer);
}

int32_t OmxAdapterAllocateBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex,
                                 struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->AllocateBuffer(portIndex, *omxBuffer);
}

int32_t OmxAdapterFreeBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->FreeBuffer(portIndex, *omxBuffer);
}

int32_t OmxAdapterEmptyThisBuffer(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->EmptyThisBuffer(*omxBuffer);
}

int32_t OmxAdapterFillThisBuffer(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->FillThisBuffer(*omxBuffer);
}

int32_t OmxAdapterSetCallbacks(struct CodecComponentNode *codecNode, struct CodecCallbackType *omxCallback,
                               int64_t appData)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxCallback == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxCallback is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SetCallbacks(omxCallback, appData);
}

int32_t OmxAdapterDeInit(struct CodecComponentNode *codecNode)
{
    if (codecNode == nullptr || codecNode->node == nullptr) {
        HDF_LOGE("%{public}s codecNode or node is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->DeInit();
}

int32_t OmxAdapterUseEglImage(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *buffer, uint32_t portIndex,
                              int8_t *eglImage, uint32_t eglImageLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || buffer == nullptr || eglImage == nullptr) {
        HDF_LOGE("%{public}s codecNode, node, buffer or eglImage is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->UseEglImage(*buffer, portIndex, eglImage, eglImageLen);
}

int32_t OmxAdapterComponentRoleEnum(struct CodecComponentNode *codecNode, uint8_t *role, uint32_t roleLen,
                                    uint32_t index)
{
    if (codecNode == nullptr || codecNode->node == nullptr || role == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or role is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->ComponentRoleEnum(role, roleLen, index);
}
#ifdef __cplusplus
};
#endif
