/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "audio_common_vdi.h"

#include "osal_mem.h"
#include "securec.h"
#include <hdf_base.h>
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL
#define AUDIO_FORMAT_NUM_MAX 15
#define AUDIO_ROUTE_NUM_MAX 2
#define AUDIO_SAMPLE_FORMAT_NUM_MAX 30
#define AUDIO_SUB_PORT_NUM_MAX 10

int32_t AudioCommonDevDescToVdiDevDescVdi(const struct AudioDeviceDescriptor *desc,
    struct AudioDeviceDescriptorVdi *vdiDesc)
{
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_FAILURE);
    CHECK_NULL_PTR_RETURN_VALUE(vdiDesc, HDF_FAILURE);

    vdiDesc->portId = desc->portId;
    vdiDesc->pins = (enum AudioPortPinVdi)desc->pins;
    vdiDesc->desc = strdup(desc->desc); // free by caller
    if (vdiDesc->desc == NULL) {
        AUDIO_FUNC_LOGE("strdup fail, desc->desc = %{public}s", desc->desc);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void AudioCommonAttrsToVdiAttrsVdi(const struct AudioSampleAttributes *attrs, struct AudioSampleAttributesVdi *vdiAttrs)
{
    CHECK_NULL_PTR_RETURN(attrs);
    CHECK_NULL_PTR_RETURN(vdiAttrs);
    AUDIO_FUNC_LOGI("render or capture type is %{public}d", attrs->type);
    vdiAttrs->type = (enum AudioCategoryVdi)attrs->type;
    vdiAttrs->interleaved = attrs->interleaved;
    vdiAttrs->format = (enum AudioFormatVdi)attrs->format;
    vdiAttrs->sampleRate = attrs->sampleRate;
    vdiAttrs->channelCount = attrs->channelCount;
    vdiAttrs->channelLayout = attrs->channelLayout;
    vdiAttrs->period = attrs->period;
    vdiAttrs->frameSize = attrs->frameSize;
    vdiAttrs->isBigEndian = attrs->isBigEndian;
    vdiAttrs->isSignedData = attrs->isSignedData;
    vdiAttrs->startThreshold = attrs->startThreshold;
    vdiAttrs->stopThreshold = attrs->stopThreshold;
    vdiAttrs->silenceThreshold = attrs->silenceThreshold;
    vdiAttrs->streamId = attrs->streamId;
    vdiAttrs->sourceType = attrs->sourceType;
    if (vdiAttrs->type == AUDIO_VDI_OFFLOAD) {
        vdiAttrs->offloadInfo.sampleRate = attrs->offloadInfo.sampleRate;
        vdiAttrs->offloadInfo.channelCount = attrs->offloadInfo.channelCount;
        vdiAttrs->offloadInfo.channelLayout = attrs->offloadInfo.channelLayout;
        vdiAttrs->offloadInfo.bitRate = attrs->offloadInfo.bitRate;
        vdiAttrs->offloadInfo.bitWidth = attrs->offloadInfo.bitWidth;
        vdiAttrs->offloadInfo.format = (enum AudioFormatVdi)attrs->offloadInfo.format;
        vdiAttrs->offloadInfo.offloadBufferSize = attrs->offloadInfo.offloadBufferSize;
        vdiAttrs->offloadInfo.duration = attrs->offloadInfo.duration;
    }
}

int32_t AudioCommonPortToVdiPortVdi(const struct AudioPort *port, struct AudioPortVdi *vdiPort)
{
    CHECK_NULL_PTR_RETURN_VALUE(vdiPort, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(port, HDF_ERR_INVALID_PARAM);

    vdiPort->dir = (enum AudioPortDirectionVdi)port->dir;
    vdiPort->portId = port->portId;
    vdiPort->portName = strdup(port->portName); // free by caller
    if (vdiPort->portName == NULL) {
        AUDIO_FUNC_LOGE("strdup fail, port->portName = %{public}s", port->portName);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t AudioFormatsToFormatsVdi(const enum AudioFormatVdi *vdiFormats, uint32_t vdiFormatNum,
    enum AudioFormat **formats, uint32_t *formatsLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(vdiFormats, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(formats, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(formatsLen, HDF_ERR_INVALID_PARAM);

    if (vdiFormatNum >= AUDIO_FORMAT_NUM_MAX || vdiFormatNum == 0) {
        AUDIO_FUNC_LOGE("VdiFormats to formats len fail");
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t size = vdiFormatNum * sizeof(enum AudioFormat);
    enum AudioFormat *formatTmp = (enum AudioFormat *)OsalMemCalloc(size);  // free by caller
    if (formatTmp == NULL) {
        AUDIO_FUNC_LOGE("formatTmp malloc fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    int32_t ret = memcpy_s((void*)formatTmp, size, (void*)vdiFormats, vdiFormatNum * sizeof(enum AudioFormatVdi));
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)formatTmp);
        AUDIO_FUNC_LOGE("format cpy fail=%{public}d", ret);
        return HDF_FAILURE;
    }

    *formats = formatTmp;
    *formatsLen = size;
    return HDF_SUCCESS;
}

static void AudioReleaseSubPortsVdi(struct AudioSubPortCapability **subPorts, uint32_t *subPortsLen)
{
    struct AudioSubPortCapability *subPortsTmp = NULL;

    CHECK_NULL_PTR_RETURN(subPorts);
    CHECK_NULL_PTR_RETURN(subPortsLen);

    uint32_t subPortsNum = *subPortsLen / sizeof(struct AudioSubPortCapability);
    if (subPortsNum >= AUDIO_SUB_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("AudioReleaseSubPortsVdi len fail");
        return;
    }

    subPortsTmp = *subPorts;
    for (uint32_t i = 0; i < subPortsNum; i++) {
        OsalMemFree((void *)subPortsTmp[i].desc);
    }

    OsalMemFree((void *)subPortsTmp);
    subPortsTmp = NULL;
}

static int32_t AudioSubPortsToSubPortsVdi(const struct AudioSubPortCapabilityVdi *vdiSubPorts, uint32_t vdiSubPortsNum,
    struct AudioSubPortCapability **subPorts, uint32_t *subPortsLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(vdiSubPorts, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(subPorts, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(subPortsLen, HDF_ERR_INVALID_PARAM);

    if (vdiSubPortsNum >= AUDIO_SUB_PORT_NUM_MAX || vdiSubPortsNum == 0) {
        AUDIO_FUNC_LOGE("VdiSubPorts to subPorts len fail");
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t size = vdiSubPortsNum * sizeof(struct AudioSubPortCapability);
    struct AudioSubPortCapability *subPortsTmp = (struct AudioSubPortCapability *)OsalMemCalloc(size);
    if (subPortsTmp == NULL) {
        AUDIO_FUNC_LOGE("subPortsTmp malloc fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < vdiSubPortsNum; i++) {
        subPortsTmp[i].portId = vdiSubPorts[i].portId;
        subPortsTmp[i].mask = (enum AudioPortPassthroughMode)vdiSubPorts[i].mask;
        subPortsTmp[i].desc = strdup(vdiSubPorts[i].desc);
        if (subPortsTmp[i].desc == NULL) {
            *subPorts = subPortsTmp;
            *subPortsLen = size;
            AUDIO_FUNC_LOGE("strdup fail, vdiSubPorts[%{public}d].desc = %{public}s", i, vdiSubPorts[i].desc);
            return HDF_FAILURE;
        }
    }

    *subPorts = subPortsTmp;
    *subPortsLen = size;
    return HDF_SUCCESS;
}

static int32_t AudioSampleFormatToSampleFormatsVdi(const enum AudioSampleFormatVdi *vdiSampleFormat,
    uint32_t vdiSupportSampleFormatNum, enum AudioSampleFormat **sampleFormat, uint32_t *sampleFormatsLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(vdiSampleFormat, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(sampleFormat, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(sampleFormatsLen, HDF_ERR_INVALID_PARAM);

    if (vdiSupportSampleFormatNum >= AUDIO_SAMPLE_FORMAT_NUM_MAX || vdiSupportSampleFormatNum == 0) {
        AUDIO_FUNC_LOGE("vdiSampleFormat to sampleFormats len fail");
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t size = vdiSupportSampleFormatNum * sizeof(enum AudioSampleFormat);
    enum AudioSampleFormat *sampleFormatTmp = (enum AudioSampleFormat *)OsalMemCalloc(size);
    if (sampleFormatTmp == NULL) {
        AUDIO_FUNC_LOGE("sampleFormatTmp malloc fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    int32_t ret = memcpy_s((void *)sampleFormatTmp, size, (void*)vdiSampleFormat,
        vdiSupportSampleFormatNum * sizeof(enum AudioSampleFormatVdi));
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)sampleFormatTmp);
        AUDIO_FUNC_LOGE("sampleFormatTmp cpy fail=%{public}d", ret);
        return HDF_FAILURE;
    }

    *sampleFormat = sampleFormatTmp;
    *sampleFormatsLen = size;
    return HDF_SUCCESS;
}

void AudioCommonVdiPortCapToPortCapVdi(const struct AudioPortCapabilityVdi *vdiPortCap,
    struct AudioPortCapability *portCap)
{
    CHECK_NULL_PTR_RETURN(portCap);
    CHECK_NULL_PTR_RETURN(vdiPortCap);

    portCap->deviceType = vdiPortCap->deviceType;
    portCap->deviceId = vdiPortCap->deviceId;
    portCap->hardwareMode = vdiPortCap->hardwareMode;
    portCap->sampleRateMasks = vdiPortCap->sampleRateMasks;
    portCap->channelMasks = (enum AudioChannelMask)vdiPortCap->channelMasks;
    portCap->channelCount = vdiPortCap->channelCount;

    int32_t ret = AudioFormatsToFormatsVdi(vdiPortCap->formats, vdiPortCap->formatNum, &portCap->formats,
        &portCap->formatsLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioFormatsToFormatsVdi fail");
        return;
    }

    ret = AudioSubPortsToSubPortsVdi(vdiPortCap->subPorts, vdiPortCap->subPortsLen,
        &portCap->subPorts, &portCap->subPortsLen);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)portCap->formats);
        AudioReleaseSubPortsVdi(&portCap->subPorts, &portCap->subPortsLen);
        portCap->formats = NULL;
        AUDIO_FUNC_LOGE("VdiSubPortsToSubPorts fail");
        return;
    }

    ret = AudioSampleFormatToSampleFormatsVdi(vdiPortCap->supportSampleFormats, vdiPortCap->supportSampleFormatsLen,
        &portCap->supportSampleFormats, &portCap->supportSampleFormatsLen);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)portCap->formats);
        AudioReleaseSubPortsVdi(&portCap->subPorts, &portCap->subPortsLen);
        portCap->formats = NULL;
        AUDIO_FUNC_LOGE("VdiSampleFormatToSampleFormats fail");
        return;
    }
}

void AudioCommonFreeVdiRouteVdi(struct AudioRouteVdi *vdiRoute)
{
    CHECK_NULL_PTR_RETURN(vdiRoute);

    if (vdiRoute->sinks != NULL) {
        if (vdiRoute->sinksLen > AUDIO_ROUTE_NUM_MAX) {
            AUDIO_FUNC_LOGE("sinksLen para error");
            return;
        }

        for (uint32_t i = 0; i < vdiRoute->sinksLen; i++) {
            if (vdiRoute->sinks[i].type == AUDIO_VDI_PORT_DEVICE_TYPE) {
                OsalMemFree((void *)vdiRoute->sinks[i].ext.device.desc);
            }
        }
        OsalMemFree((void *)vdiRoute->sinks);
    }

    if (vdiRoute->sources != NULL) {
        if (vdiRoute->sourcesLen > AUDIO_ROUTE_NUM_MAX) {
            AUDIO_FUNC_LOGE("sourcesLen para error");
            return;
        }

        for (uint32_t i = 0; i < vdiRoute->sourcesLen; i++) {
            if (vdiRoute->sources[i].type == AUDIO_VDI_PORT_DEVICE_TYPE) {
                OsalMemFree((void *)vdiRoute->sources[i].ext.device.desc);
            }
        }
        OsalMemFree((void *)vdiRoute->sources);
    }
}

static int32_t AudioCommonRouteNodeToVdiRouteNodeVdi(struct AudioRouteNode *routeNode,
    struct AudioRouteNodeVdi *vdiRouteNode)
{
    vdiRouteNode->portId = routeNode->portId;
    vdiRouteNode->role = (enum AudioPortRoleVdi)routeNode->role;
    vdiRouteNode->type = (enum AudioPortTypeVdi)routeNode->type;

    if (routeNode->type == AUDIO_VDI_PORT_DEVICE_TYPE) {
        vdiRouteNode->ext.device.moduleId = routeNode->ext.device.moduleId;
        vdiRouteNode->ext.device.type = (enum AudioPortPinVdi)routeNode->ext.device.type;
        vdiRouteNode->ext.device.desc = strdup(routeNode->ext.device.desc);
        if (vdiRouteNode->ext.device.desc == NULL) {
            AUDIO_FUNC_LOGE("strdup fail, routeNode->ext.device.desc = %{public}s", routeNode->ext.device.desc);
            return HDF_FAILURE;
        }
        return HDF_SUCCESS;
    }

    if (routeNode->type == AUDIO_VDI_PORT_MIX_TYPE) {
        vdiRouteNode->ext.mix.moduleId = routeNode->ext.mix.moduleId;
        vdiRouteNode->ext.mix.streamId = routeNode->ext.mix.streamId;
        return HDF_SUCCESS;
    }

    if (routeNode->type == AUDIO_VDI_PORT_SESSION_TYPE) {
        vdiRouteNode->ext.session.sessionType = (enum AudioSessionTypeVdi)routeNode->ext.session.sessionType;
        return HDF_SUCCESS;
    }

    AUDIO_FUNC_LOGE("not match route node type");
    return HDF_FAILURE;
}

static int32_t AudioCommonSinkToVdiSinkVdi(const struct AudioRoute *route, struct AudioRouteVdi *vdiRoute)
{
    struct AudioRouteNodeVdi *nodes = NULL;
    if (route->sinksLen > AUDIO_ROUTE_NUM_MAX) {
        AUDIO_FUNC_LOGE("sinksLen para err");
        return HDF_ERR_INVALID_PARAM;
    }

    nodes = (struct AudioRouteNodeVdi *)OsalMemCalloc(route->sinksLen * sizeof(struct AudioRouteNodeVdi));
    if (nodes == NULL) {
        AUDIO_FUNC_LOGE("nodes null");
        return HDF_ERR_MALLOC_FAIL;
    }
    vdiRoute->sinks = nodes;
    vdiRoute->sinksLen = route->sinksLen;

    for (uint32_t i = 0; i < vdiRoute->sinksLen; i++) {
        int32_t ret = AudioCommonRouteNodeToVdiRouteNodeVdi(&route->sinks[i], &vdiRoute->sinks[i]);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("sink routeNode to vdiRouteNode fail");
            /* nodes release by AudioCommonFreeVdiRouteVdi */
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

static int32_t AudioCommonSourceToVdiSourceVdi(const struct AudioRoute *route, struct AudioRouteVdi *vdiRoute)
{
    struct AudioRouteNodeVdi *nodes = NULL;
    if (route->sourcesLen > AUDIO_ROUTE_NUM_MAX) {
        AUDIO_FUNC_LOGE("sinksLen para err");
        return HDF_ERR_INVALID_PARAM;
    }

    nodes = (struct AudioRouteNodeVdi *)OsalMemCalloc(route->sourcesLen * sizeof(struct AudioRouteNodeVdi));
    if (nodes == NULL) {
        AUDIO_FUNC_LOGE("nodes null");
        return HDF_ERR_MALLOC_FAIL;
    }
    vdiRoute->sources = nodes;
    vdiRoute->sourcesLen = route->sourcesLen;

    for (uint32_t i = 0; i < vdiRoute->sourcesLen; i++) {
        int32_t ret = AudioCommonRouteNodeToVdiRouteNodeVdi(&route->sources[i], &vdiRoute->sources[i]);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE(" source routeNode to vdiRouteNode fail");
            /* nodes release by AudioCommonFreeVdiRouteVdi */
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioCommonRouteToVdiRouteVdi(const struct AudioRoute *route, struct AudioRouteVdi *vdiRoute)
{
    int32_t sinkRet = HDF_SUCCESS;
    int32_t sourcesRet = HDF_SUCCESS;

    CHECK_NULL_PTR_RETURN_VALUE(route, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRoute, HDF_ERR_INVALID_PARAM);

    if (route->sinks != NULL) {
        sinkRet = AudioCommonSinkToVdiSinkVdi(route, vdiRoute);
        if (sinkRet != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE(" sink routeNode to vdiRouteNode fail");
        }
    }

    if (route->sources != NULL) {
        sourcesRet = AudioCommonSourceToVdiSourceVdi(route, vdiRoute);
        if (sourcesRet != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE(" source routeNode to vdiRouteNode fail");
            return HDF_FAILURE;
        }
    }

    if (sinkRet != HDF_SUCCESS || sourcesRet != HDF_SUCCESS) {
        /* free nodes by sink and source malloc nodes memory */
        AudioCommonFreeVdiRouteVdi(vdiRoute);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioCommonSceneToVdiSceneVdi(const struct AudioSceneDescriptor *scene,
    struct AudioSceneDescriptorVdi *vdiScene)
{
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiScene, HDF_ERR_INVALID_PARAM);

    vdiScene->scene.id = scene->scene.id;
    return AudioCommonDevDescToVdiDevDescVdi(&scene->desc, &vdiScene->desc);
}

int32_t AudioCommonSampleAttrToVdiSampleAttrVdi(const struct AudioSampleAttributes *attrs,
    struct AudioSampleAttributesVdi *vdiAttrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiAttrs, HDF_ERR_INVALID_PARAM);

    vdiAttrs->type = (enum AudioCategoryVdi)attrs->type;
    vdiAttrs->interleaved = attrs->interleaved;
    vdiAttrs->format = (enum AudioFormatVdi)attrs->format;
    vdiAttrs->sampleRate = attrs->sampleRate;
    vdiAttrs->channelCount = attrs->channelCount;
    vdiAttrs->channelLayout = attrs->channelLayout;
    vdiAttrs->period = attrs->period;
    vdiAttrs->frameSize = attrs->frameSize;
    vdiAttrs->isBigEndian = attrs->isBigEndian;
    vdiAttrs->isSignedData = attrs->isSignedData;
    vdiAttrs->startThreshold = attrs->startThreshold;
    vdiAttrs->stopThreshold = attrs->stopThreshold;
    vdiAttrs->silenceThreshold = attrs->silenceThreshold;
    vdiAttrs->streamId = attrs->streamId;
    vdiAttrs->sourceType = attrs->sourceType;
    if (vdiAttrs->type == AUDIO_VDI_OFFLOAD) {
        vdiAttrs->offloadInfo.sampleRate = attrs->offloadInfo.sampleRate;
        vdiAttrs->offloadInfo.channelCount = attrs->offloadInfo.channelCount;
        vdiAttrs->offloadInfo.channelLayout = attrs->offloadInfo.channelLayout;
        vdiAttrs->offloadInfo.bitRate = attrs->offloadInfo.bitRate;
        vdiAttrs->offloadInfo.bitWidth = attrs->offloadInfo.bitWidth;
        vdiAttrs->offloadInfo.format = (enum AudioFormatVdi)attrs->offloadInfo.format;
        vdiAttrs->offloadInfo.offloadBufferSize = attrs->offloadInfo.offloadBufferSize;
        vdiAttrs->offloadInfo.duration = attrs->offloadInfo.duration;
    }
    return HDF_SUCCESS;
}

int32_t AudioCommonVdiSampleAttrToSampleAttrVdi(const struct AudioSampleAttributesVdi *vdiAttrs,
    struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiAttrs, HDF_ERR_INVALID_PARAM);

    attrs->type = (enum AudioCategory)vdiAttrs->type;
    attrs->interleaved = vdiAttrs->interleaved;
    attrs->format = (enum AudioFormat)vdiAttrs->format;
    attrs->sampleRate = vdiAttrs->sampleRate;
    attrs->channelCount = vdiAttrs->channelCount;
    attrs->period = vdiAttrs->period;
    attrs->frameSize = vdiAttrs->frameSize;
    attrs->isBigEndian = vdiAttrs->isBigEndian;
    attrs->isSignedData = vdiAttrs->isSignedData;
    attrs->startThreshold = vdiAttrs->startThreshold;
    attrs->stopThreshold = vdiAttrs->stopThreshold;
    attrs->silenceThreshold = vdiAttrs->silenceThreshold;
    attrs->streamId = vdiAttrs->streamId;

    return HDF_SUCCESS;
}
