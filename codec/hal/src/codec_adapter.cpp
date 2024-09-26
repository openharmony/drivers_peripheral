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

#include <hdf_log.h>
#include <memory.h>
#include <malloc.h>
#include <securec.h>
#include "codec_adapter_interface.h"
#include "codec_log_wrapper.h"
#include "component_mgr.h"
#include "component_node.h"
#include "hitrace_meter.h"

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
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecCreateComponent");
    OMX_COMPONENTTYPE *comp = nullptr;
    CodecComponentNode *tempNode = new CodecComponentNode;
    if (tempNode == nullptr) {
        CODEC_LOGE("create CodecComponentNode error");
        return HDF_ERR_MALLOC_FAIL;
    }
    tempNode->node = std::make_shared<ComponentNode>(callbacks, appData, compName);
    if (tempNode->node == nullptr) {
        CODEC_LOGE("fail to init ComponentNode");
        delete tempNode;
        tempNode = nullptr;
        return HDF_FAILURE;
    }
    auto err = g_mgr.CreateComponentInstance(compName, &ComponentNode::callbacks_, tempNode->node.get(), &comp);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("create component instance err[%{public}d]", err);
        delete tempNode;
        tempNode = nullptr;
        return err;
    }
    tempNode->node->SetHandle(static_cast<OMX_HANDLETYPE>(comp));

    *codecNode = tempNode;
    return HDF_SUCCESS;
}

int32_t OmxAdapterDestroyComponent(struct CodecComponentNode *codecNode)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecDestroyComponent");
    if (codecNode == nullptr) {
        CODEC_LOGE("codecNode is null");
        return HDF_ERR_INVALID_PARAM;
    }
    if (codecNode->node == nullptr) {
        delete codecNode;
        codecNode = nullptr;
        CODEC_LOGE("node is null");
        return HDF_ERR_INVALID_PARAM;
    }
    OMX_HANDLETYPE comp = codecNode->node->GetHandle();
    codecNode->node = nullptr;
    auto err = g_mgr.DeleteComponentInstance(static_cast<OMX_COMPONENTTYPE*>(comp));
    if (err != OMX_ErrorNone) {
        delete codecNode;
        codecNode = nullptr;
        CODEC_LOGE("DeleteComponentInstance err[%{public}d]", err);
        return err;
    }

    delete codecNode;
    codecNode = nullptr;
    return HDF_SUCCESS;
}

int32_t OmxAdapterComponentVersion(struct CodecComponentNode *codecNode, struct CompVerInfo *verInfo)
{
    if (codecNode == nullptr || codecNode->node == nullptr || verInfo == nullptr) {
        CODEC_LOGE("codecNode, node or verInfois is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetComponentVersion(*verInfo);
}

int32_t OmxAdapterSendCommand(struct CodecComponentNode *codecNode, OMX_COMMANDTYPE cmd, uint32_t param,
                              int8_t *cmdData, uint32_t cmdDataLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr) {
        CODEC_LOGE("codecNode or node is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SendCommand(cmd, param, cmdData, cmdDataLen);
}

int32_t OmxAdapterGetParameter(struct CodecComponentNode *codecNode, OMX_INDEXTYPE paramIndex, int8_t *param,
                               uint32_t paramLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || param == nullptr) {
        CODEC_LOGE("codecNode, node or param is null");
        return HDF_ERR_INVALID_PARAM;
    }

    return codecNode->node->GetParameter(paramIndex, param, paramLen);
}

int32_t OmxAdapterSetParameter(struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, int8_t *param,
                               uint32_t paramLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || param == nullptr) {
        CODEC_LOGE("codecNode, node or param is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SetParameter(index, param, paramLen);
}

int32_t OmxAdapterGetConfig(struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, int8_t *config,
                            uint32_t configLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || config == nullptr) {
        CODEC_LOGE("codecNode, node or config is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetConfig(index, config, configLen);
}

int32_t OmxAdapterSetConfig(struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, int8_t *config,
                            uint32_t configLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || config == nullptr) {
        CODEC_LOGE("codecNode, node or config is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SetConfig(index, config, configLen);
}

int32_t OmxAdapterGetExtensionIndex(struct CodecComponentNode *codecNode, const char *parameterName,
                                    OMX_INDEXTYPE *indexType)
{
    if (codecNode == nullptr || codecNode->node == nullptr || parameterName == nullptr || indexType == nullptr) {
        CODEC_LOGE("codecNode, node , parameterName or indexType is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetExtensionIndex(parameterName, indexType);
}

int32_t OmxAdapterGetState(struct CodecComponentNode *codecNode, OMX_STATETYPE *state)
{
    if (codecNode == nullptr || codecNode->node == nullptr || state == nullptr) {
        CODEC_LOGE("codecNode, node or state is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetState(state);
}

int32_t OmxAdapterComponentTunnelRequest(struct CodecComponentNode *codecNode, uint32_t port,
                                         int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort,
                                         struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    if (codecNode == nullptr || codecNode->node == nullptr || tunnelSetup == nullptr) {
        CODEC_LOGE("codecNode, node or tunnelSetup is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->ComponentTunnelRequest(port, omxHandleTypeTunneledComp, tunneledPort, tunnelSetup);
}

int32_t OmxAdapterUseBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecUseBuffer");
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        CODEC_LOGE("codecNode, node or omxBuffer is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->UseBuffer(portIndex, *omxBuffer);
}

int32_t OmxAdapterAllocateBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex,
                                 struct OmxCodecBuffer *omxBuffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecAllocateBuffer");
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        CODEC_LOGE("codecNode, node or omxBuffer is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->AllocateBuffer(portIndex, *omxBuffer);
}

int32_t OmxAdapterFreeBuffer(struct CodecComponentNode *codecNode, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecFreeBuffer");
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        CODEC_LOGE("codecNode, node or omxBuffer is null");
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = codecNode->node->FreeBuffer(portIndex, *omxBuffer);
    return ret;
}

int32_t OmxAdapterEmptyThisBuffer(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *omxBuffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecEmptyThisBuffer");
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        CODEC_LOGE("codecNode, node or omxBuffer is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->EmptyThisBuffer(*omxBuffer);
}

int32_t OmxAdapterFillThisBuffer(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *omxBuffer)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HdfCodecFillThisBuffer");
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        CODEC_LOGE("codecNode, node or omxBuffer is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->FillThisBuffer(*omxBuffer);
}

int32_t OmxAdapterSetCallbacks(struct CodecComponentNode *codecNode, struct CodecCallbackType *omxCallback,
                               int64_t appData)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxCallback == nullptr) {
        CODEC_LOGE("codecNode, node or omxCallback is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SetCallbacks(omxCallback, appData);
}

int32_t OmxAdapterDeInit(struct CodecComponentNode *codecNode)
{
    if (codecNode == nullptr || codecNode->node == nullptr) {
        CODEC_LOGE("codecNode or node is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->DeInit();
}

int32_t OmxAdapterUseEglImage(struct CodecComponentNode *codecNode, struct OmxCodecBuffer *buffer, uint32_t portIndex,
                              int8_t *eglImage, uint32_t eglImageLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || buffer == nullptr || eglImage == nullptr) {
        CODEC_LOGE("codecNode, node, buffer or eglImage is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->UseEglImage(*buffer, portIndex, eglImage, eglImageLen);
}

int32_t OmxAdapterComponentRoleEnum(struct CodecComponentNode *codecNode, uint8_t *role, uint32_t roleLen,
                                    uint32_t index)
{
    if (codecNode == nullptr || codecNode->node == nullptr || role == nullptr) {
        CODEC_LOGE("codecNode, node or role is null");
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->ComponentRoleEnum(role, roleLen, index);
}

int32_t OmxAdapterSetComponentRole(struct CodecComponentNode *codecNode, char *compName)
{
    if (codecNode == nullptr || codecNode->node == nullptr || compName == nullptr) {
        CODEC_LOGE("codecNode, compName is null");
        return HDF_ERR_INVALID_PARAM;
    }
    CodecOMXCore *core;
    auto err = g_mgr.GetCoreOfComponent(core, compName);
    if (err != HDF_SUCCESS || core == nullptr) {
        CODEC_LOGE("core is null");
        return err;
    }

    std::vector<std::string> roles;
    std::string name = compName;
    int32_t ret = core->GetRolesOfComponent(name, roles);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("GetRoleOfComponent return err [%{public}d]", ret);
        return ret;
    }
    if (roles.empty()) {
        CODEC_LOGE("role of component is empty");
        return HDF_ERR_INVALID_PARAM;
    }
    uint32_t roleIndex = 0;
    CODEC_LOGI("RoleName = [%{public}s]", roles[roleIndex].c_str());

    OMX_PARAM_COMPONENTROLETYPE role;
    errno_t res = strncpy_s(reinterpret_cast<char *>(role.cRole), OMX_MAX_STRINGNAME_SIZE,
                            roles[roleIndex].c_str(), roles[roleIndex].length());
    if (res != EOK) {
        CODEC_LOGE("strncpy_s return err [%{public}d]", err);
        return HDF_FAILURE;
    }
    role.nSize = sizeof(role);
    ret = codecNode->node->SetParameter(OMX_IndexParamStandardComponentRole,
                                        reinterpret_cast<int8_t *>(&role), sizeof(role));
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("OMX_IndexParamStandardComponentRole err [%{public}d]", ret);
    }

    return ret;
}

int32_t OmxAdapterWriteDumperData(char *info, uint32_t size, uint32_t compId, struct CodecComponentNode *codecNode)
{
    OMX_STATETYPE state;
    int32_t ret = OmxAdapterGetState(codecNode, &state);
    if (ret != HDF_SUCCESS) {
        CODEC_LOGE("OmxAdapterWriteDumperData error!");
        return HDF_FAILURE;
    }
    std::string dump = "compName = ";
    if (codecNode->node != nullptr) {
        dump.append(codecNode->node->GetCompName()).append(", compId = ").append(std::to_string(compId))
            .append(", state = ").append(std::to_string(state)).append(", bufferCount = ")
            .append(std::to_string(codecNode->node->GetBufferCount()));
    }
    dump.append("\n");
    errno_t error = strncpy_s(info, size, dump.c_str(), dump.length());
    if (error != EOK) {
        CODEC_LOGE("strncpy_s return err [%{public}d]", error);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
#ifdef __cplusplus
};
#endif
