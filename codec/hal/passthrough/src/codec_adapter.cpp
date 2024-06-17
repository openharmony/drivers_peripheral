/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <hdf_base.h>
#include <hdf_log.h>
#include <memory>
#include "codec_adapter_if.h"
#include "codec_capability_parser.h"
#include "codec_component_capability.h"
#include "component_manager.h"
#include "component_node.h"
#include "codec_omx_ext.h"
using namespace OHOS::Codec::CodecAdapter;

#define HDF_LOG_TAG codec_hdi_adapter

static ComponentManager g_mgr;
struct CodecComponentNode {
    std::shared_ptr<ComponentNode> node;
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t CodecAdapterCodecInit()
{
    return g_mgr.Init();
}

int32_t CodecAdapterCodecDeinit()
{
    return g_mgr.Deinit();
}

int32_t CodecAdapterCreateComponent(struct CodecComponentNode **codecNode, const char *compName, int64_t appData,
    const struct CodecCallbackType *callbacks)
{
    if (compName == nullptr || callbacks == nullptr) {
        HDF_LOGE("%{public}s compName or callbacks is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    CodecExInfo exInfo;
    auto ret = GetBasicInfoByCompName(reinterpret_cast<uint8_t *>(&exInfo), compName);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s GetBasicInfoByCompName error", __func__);
        return ret;
    }

    CODEC_HANDLETYPE comp = nullptr;
    CodecComponentNode *tempNode = new CodecComponentNode;
    if (tempNode == nullptr) {
        HDF_LOGE("%{public}s create CodecComponentNode error", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    ret = g_mgr.CreateComponentInstance(compName, comp);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s ceate component instance ret[%{public}d]", __func__, ret);
        delete tempNode;
        tempNode = nullptr;
        return ret;
    }

    tempNode->node = std::make_shared<ComponentNode>(comp, exInfo);
    if (tempNode->node == nullptr) {
        HDF_LOGE("fail to init ComponentNode");
        delete tempNode;
        tempNode = nullptr;
        return HDF_FAILURE;
    }
    ret = tempNode->node->SetCallbacks(callbacks, appData);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s SetCallbacks error", __func__);
        g_mgr.DeleteComponentInstance(comp);
        tempNode->node = nullptr;
        delete tempNode;
        tempNode = nullptr;
        return ret;
    }

    tempNode->node->SetState(OMX_StateLoaded);

    *codecNode = tempNode;
    return HDF_SUCCESS;
}

int32_t CodecAdapterDestroyComponent(struct CodecComponentNode *codecNode)
{
    if (codecNode == nullptr || codecNode->node == nullptr) {
        HDF_LOGE("%{public}s codecNode is null or node is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    auto ret = g_mgr.DeleteComponentInstance(codecNode->node->GetHandle());
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s DeleteComponentInstance ret[%{public}d]", __func__, ret);
        return ret;
    }
    codecNode->node = nullptr;
    delete codecNode;
    codecNode = nullptr;
    return HDF_SUCCESS;
}

int32_t CodecAdapterGetComponentVersion(const struct CodecComponentNode *codecNode, struct CompVerInfo *verInfo)
{
    if (codecNode == nullptr || codecNode->node == nullptr || verInfo == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or verInfois is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetComponentVersion(*verInfo);
}

int32_t CodecAdapterSendCommand(const struct CodecComponentNode *codecNode, OMX_COMMANDTYPE cmd, uint32_t param,
                                int8_t *cmdData, uint32_t cmdDataLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr) {
        HDF_LOGE("%{public}s codecNode or node is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SendCommand(cmd, param, cmdData, cmdDataLen);
}

int32_t CodecAdapterGetParameter(
    const struct CodecComponentNode *codecNode, OMX_INDEXTYPE paramIndex, int8_t *param, uint32_t paramLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || param == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!CheckParamStructLen(paramIndex, paramLen)) {
        HDF_LOGE("%{public}s param is invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return codecNode->node->GetParameter(paramIndex, param, paramLen);
}

int32_t CodecAdapterSetParameter(
    const struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, const int8_t *param, uint32_t paramLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || param == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or param is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!CheckParamStructLen(index, paramLen)) {
        HDF_LOGE("%{public}s param is invalid", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return codecNode->node->SetParameter(index, param, paramLen);
}

int32_t CodecAdapterGetConfig(
    const struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, int8_t *config, uint32_t configLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || config == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or config is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetConfig(index, config, configLen);
}

int32_t CodecAdapterSetConfig(
    const struct CodecComponentNode *codecNode, OMX_INDEXTYPE index, const int8_t *config, uint32_t configLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || config == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or config is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SetConfig(index, config, configLen);
}

int32_t CodecAdapterGetExtensionIndex(
    const struct CodecComponentNode *codecNode, const char *parameterName, OMX_INDEXTYPE *indexType)
{
    if (codecNode == nullptr || codecNode->node == nullptr || parameterName == nullptr || indexType == nullptr) {
        HDF_LOGE("%{public}s codecNode, node, parameterName or indexType is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetExtensionIndex(parameterName, indexType);
}

int32_t CodecAdapterGetState(const struct CodecComponentNode *codecNode, OMX_STATETYPE *state)
{
    if (codecNode == nullptr || codecNode->node == nullptr || state == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or state is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->GetState(state);
}

int32_t CodecAdapterComponentTunnelRequest(const struct CodecComponentNode *codecNode, uint32_t port,
    int32_t omxHandleTypeTunneledComp, uint32_t tunneledPort, struct OMX_TUNNELSETUPTYPE *tunnelSetup)
{
    if (codecNode == nullptr || codecNode->node == nullptr || tunnelSetup == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or tunnelSetup is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->ComponentTunnelRequest(port, omxHandleTypeTunneledComp, tunneledPort, tunnelSetup);
}

int32_t CodecAdapterUseBuffer(
    const struct CodecComponentNode *codecNode, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->UseBuffer(portIndex, *omxBuffer);
}

int32_t CodecAdapterAllocateBuffer(
    const struct CodecComponentNode *codecNode, uint32_t portIndex, struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->AllocateBuffer(portIndex, *omxBuffer);
}

int32_t CodecAdapterFreeBuffer(
    const struct CodecComponentNode *codecNode, uint32_t portIndex, const struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->FreeBuffer(portIndex, *omxBuffer);
}

int32_t CodecAdapterEmptyThisBuffer(const struct CodecComponentNode *codecNode, const struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->EmptyThisBuffer(*omxBuffer);
}

int32_t CodecAdapterFillThisBuffer(const struct CodecComponentNode *codecNode, const struct OmxCodecBuffer *omxBuffer)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxBuffer == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxBuffer is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->FillThisBuffer(*omxBuffer);
}

int32_t CodecAdapterSetCallbacks(
    const struct CodecComponentNode *codecNode, struct CodecCallbackType *omxCallback, int64_t appData)
{
    if (codecNode == nullptr || codecNode->node == nullptr || omxCallback == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or omxCallback is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->SetCallbacks(omxCallback, appData);
}

int32_t CodecAdapterComponentDeInit(const struct CodecComponentNode *codecNode)
{
    if (codecNode == nullptr || codecNode->node == nullptr) {
        HDF_LOGE("%{public}s codecNode or node is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->ComponentDeInit();
}

int32_t CodecAdapterUseEglImage(const struct CodecComponentNode *codecNode, struct OmxCodecBuffer *buffer,
                                uint32_t portIndex, int8_t *eglImage, uint32_t eglImageLen)
{
    if (codecNode == nullptr || codecNode->node == nullptr || buffer == nullptr || eglImage == nullptr) {
        HDF_LOGE("%{public}s codecNode, node, buffer or eglImage is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->UseEglImage(*buffer, portIndex, eglImage, eglImageLen);
}

int32_t CodecAdapterComponentRoleEnum(
    const struct CodecComponentNode *codecNode, uint8_t *role, uint32_t roleLen, uint32_t index)
{
    if (codecNode == nullptr || codecNode->node == nullptr || role == nullptr) {
        HDF_LOGE("%{public}s codecNode, node or role is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return codecNode->node->ComponentRoleEnum(role, roleLen, index);
}

bool CheckParamStructLen(int32_t paramIndex, uint32_t paramLen)
{
    uint32_t paramStructLen = 0;
    switch (paramIndex) {
        case OMX_IndexParamPortDefinition:
            paramStructLen = sizeof(OMX_PARAM_PORTDEFINITIONTYPE);
            break;
        case OMX_IndexParamAudioPortFormat:
            paramStructLen = sizeof(OMX_AUDIO_PARAM_PORTFORMATTYPE);
            break;
        case OMX_IndexParamAudioPcm:
            paramStructLen = sizeof(OMX_AUDIO_PARAM_PCMMODETYPE);
            break;
        case OMX_IndexParamAudioAac:
            paramStructLen = sizeof(OMX_AUDIO_PARAM_AACPROFILETYPE);
            break;
        case OMX_IndexParamAudioMp3:
            paramStructLen = sizeof(OMX_AUDIO_PARAM_MP3TYPE);
            break;
        case OMX_IndexParamAudioG726:
            paramStructLen = sizeof(OMX_AUDIO_PARAM_G726TYPE);
            break;
        case OMX_IndexParamImagePortFormat:
            paramStructLen = sizeof(OMX_IMAGE_PARAM_PORTFORMATTYPE);
            break;
        case OMX_IndexParamQFactor:
            paramStructLen = sizeof(OMX_IMAGE_PARAM_QFACTORTYPE);
            break;
        case OMX_IndexParamVideoPortFormat:
            paramStructLen = sizeof(OMX_VIDEO_PARAM_PORTFORMATTYPE);
            break;
        case OMX_IndexParamVideoMpeg2:
            paramStructLen = sizeof(OMX_VIDEO_PARAM_MPEG2TYPE);
            break;
        case OMX_IndexParamVideoMpeg4:
            paramStructLen = sizeof(OMX_VIDEO_PARAM_MPEG4TYPE);
            break;
        case OMX_IndexParamVideoAvc:
            paramStructLen = sizeof(OMX_VIDEO_PARAM_AVCTYPE);
            break;
        case OMX_IndexParamVideoBitrate:
            paramStructLen = sizeof(OMX_VIDEO_PARAM_BITRATETYPE);
            break;
        case OMX_IndexParamPassthrough:
            paramStructLen = sizeof(PassthroughParam);
            break;

        default:
            return false;
    }
    return (paramStructLen == paramLen);
}
#ifdef __cplusplus
};
#endif
