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
#include "audio_common_vendor.h"

#include <hdf_base.h>
#include "audio_uhdf_log.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

#define AUDIO_SAMPLE_FORMAT_NUM_MAX 30
#define AUDIO_FORMAT_NUM_MAX 15
#define AUDIO_SUB_PORT_NUM_MAX 10
#define AUDIO_ROUTE_NUM_MAX 2

void AudioHwiCommonDevDescToHwiDevDesc(const struct AudioDeviceDescriptor *desc,
    struct AudioHwiDeviceDescriptor *hwiDesc)
{
    CHECK_NULL_PTR_RETURN(desc);
    CHECK_NULL_PTR_RETURN(hwiDesc);

    hwiDesc->portId = desc->portId;
    hwiDesc->pins = (enum AudioHwiPortPin)desc->pins;
    hwiDesc->desc = strdup(desc->desc); // free by caller
}

void AudioHwiCommonAttrsToHwiAttrs(const struct AudioSampleAttributes *attrs, struct AudioHwiSampleAttributes *hwiAttrs)
{
    CHECK_NULL_PTR_RETURN(attrs);
    CHECK_NULL_PTR_RETURN(hwiAttrs);

    hwiAttrs->type = (enum AudioHwiCategory)attrs->type;
    hwiAttrs->interleaved = attrs->interleaved;
    hwiAttrs->format = (enum AudioHwiFormat)attrs->format;
    hwiAttrs->sampleRate = attrs->sampleRate;
    hwiAttrs->channelCount = attrs->channelCount;
    hwiAttrs->period = attrs->period;
    hwiAttrs->frameSize = attrs->frameSize;
    hwiAttrs->isBigEndian = attrs->isBigEndian;
    hwiAttrs->isSignedData = attrs->isSignedData;
    hwiAttrs->startThreshold = attrs->startThreshold;
    hwiAttrs->stopThreshold = attrs->stopThreshold;
    hwiAttrs->silenceThreshold = attrs->silenceThreshold;
    hwiAttrs->streamId = attrs->streamId;
}

int32_t AudioHwiCommonPortToHwiPort(const struct AudioPort *port, struct AudioHwiPort *hwiPort)
{
    CHECK_NULL_PTR_RETURN_VALUE(hwiPort, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(port, HDF_ERR_INVALID_PARAM);

    hwiPort->dir = (enum AudioHwiPortDirection)port->dir;
    hwiPort->portId = port->portId;
    hwiPort->portName = strdup(port->portName); // free by caller

    return HDF_SUCCESS;
}

static int32_t AudioHwiFormatsToFormats(const enum AudioHwiFormat *hwiFormats, uint32_t hwiFormatNum,
    enum AudioFormat **formats, uint32_t *formatsLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(hwiFormats, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(formats, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(formatsLen, HDF_ERR_INVALID_PARAM);

    if (hwiFormatNum >= AUDIO_FORMAT_NUM_MAX) {
        AUDIO_FUNC_LOGE("HwiFormats to formats len fail");
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t size = hwiFormatNum * sizeof(enum AudioFormat);
    enum AudioFormat *formatTmp = (enum AudioFormat *)OsalMemCalloc(size);  // free by caller
    if (formatTmp == NULL) {
        AUDIO_FUNC_LOGE("formatTmp malloc fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    int32_t ret = memcpy_s((void*)formatTmp, size, (void*)hwiFormats, hwiFormatNum * sizeof(enum AudioHwiFormat));
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)formatTmp);
        AUDIO_FUNC_LOGE("format cpy fail=%{public}d", ret);
        return HDF_FAILURE;
    }

    *formats = formatTmp;
    *formatsLen = size;

    return HDF_SUCCESS;
}


static void AudioHwiReleaseSubPorts(struct AudioSubPortCapability **subPorts, uint32_t *subPortsLen)
{
    struct AudioSubPortCapability *subPortsTmp = NULL;

    CHECK_NULL_PTR_RETURN(subPorts);
    CHECK_NULL_PTR_RETURN(subPortsLen);

    uint32_t subPortsNum = *subPortsLen / sizeof(struct AudioSubPortCapability);
    if (subPortsNum >= AUDIO_SUB_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("AudioHwiReleaseSubPorts len fail");
        return;
    }

    subPortsTmp = *subPorts;
    for (uint32_t i = 0; i < subPortsNum; i++) {
        OsalMemFree((void *)subPortsTmp[i].desc);
    }

    OsalMemFree((void *)subPortsTmp);
    subPortsTmp = NULL;
}

static int32_t AudioHwiSubPortsToSubPorts(const struct AudioHwiSubPortCapability *hwiSubPorts, uint32_t hwiSubPortsNum,
    struct AudioSubPortCapability **subPorts, uint32_t *subPortsLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(hwiSubPorts, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(subPorts, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(subPortsLen, HDF_ERR_INVALID_PARAM);

    if (hwiSubPortsNum >= AUDIO_SUB_PORT_NUM_MAX) {
        AUDIO_FUNC_LOGE("HwiSubPorts to subPorts len fail");
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t size = hwiSubPortsNum * sizeof(struct AudioSubPortCapability);
    struct AudioSubPortCapability *subPortsTmp = (struct AudioSubPortCapability *)OsalMemCalloc(size);
    if (subPortsTmp == NULL) {
        AUDIO_FUNC_LOGE("subPortsTmp malloc fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    for (uint32_t i = 0; i < hwiSubPortsNum; i++) {
        subPortsTmp[i].portId = hwiSubPorts[i].portId;
        subPortsTmp[i].mask = (enum AudioPortPassthroughMode)hwiSubPorts[i].mask;
        subPortsTmp[i].desc = strdup(hwiSubPorts[i].desc);
    }

    *subPorts = subPortsTmp;
    *subPortsLen = size;

    return HDF_SUCCESS;
}

static int32_t AudioHwiSampleFormatToSampleFormats(const enum AudioHwiSampleFormat *hwiSampleFormat,
    uint32_t hwiSupportSampleFormatNum, enum AudioSampleFormat **sampleFormat, uint32_t *sampleFormatsLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(hwiSampleFormat, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(sampleFormat, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(sampleFormatsLen, HDF_ERR_INVALID_PARAM);

    if (hwiSupportSampleFormatNum >= AUDIO_SAMPLE_FORMAT_NUM_MAX) {
        AUDIO_FUNC_LOGE("hwiSampleFormat to sampleFormats len fail");
        return HDF_ERR_INVALID_PARAM;
    }

    uint32_t size = hwiSupportSampleFormatNum * sizeof(enum AudioSampleFormat);
    enum AudioSampleFormat *sampleFormatTmp = (enum AudioSampleFormat *)OsalMemCalloc(size);
    if (sampleFormatTmp == NULL) {
        AUDIO_FUNC_LOGE("sampleFormatTmp malloc fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    int32_t ret = memcpy_s((void *)sampleFormatTmp, size, (void*)hwiSampleFormat,
        hwiSupportSampleFormatNum * sizeof(enum AudioHwiSampleFormat));
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)sampleFormatTmp);
        AUDIO_FUNC_LOGE("sampleFormatTmp cpy fail=%{public}d", ret);
        return HDF_FAILURE;
    }

    *sampleFormat = sampleFormatTmp;
    *sampleFormatsLen = size;

    return HDF_SUCCESS;
}

int32_t AudioHwiCommonHwiPortCapToPortCap(const struct AudioHwiPortCapability *hwiPortCap,
    struct AudioPortCapability *portCap)
{
    CHECK_NULL_PTR_RETURN_VALUE(portCap, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiPortCap, HDF_ERR_INVALID_PARAM);

    portCap->deviceType = hwiPortCap->deviceType;
    portCap->deviceId = hwiPortCap->deviceId;
    portCap->hardwareMode = hwiPortCap->hardwareMode;
    portCap->sampleRateMasks= hwiPortCap->sampleRateMasks;
    portCap->channelMasks = (enum AudioChannelMask)hwiPortCap->channelMasks;
    portCap->channelCount = hwiPortCap->channelCount;

    int32_t ret = AudioHwiFormatsToFormats(hwiPortCap->formats, hwiPortCap->formatNum, &portCap->formats,
        &portCap->formatsLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioHwiFormatsToFormats fail");
        return ret;
    }

    ret = AudioHwiSubPortsToSubPorts(hwiPortCap->subPorts, hwiPortCap->subPortsNum,
        &portCap->subPorts, &portCap->subPortsLen);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)portCap->formats);
        portCap->formats = NULL;
        AUDIO_FUNC_LOGE("HwiSubPortsToSubPorts fail");
        return ret;
    }

    ret = AudioHwiSampleFormatToSampleFormats(hwiPortCap->supportSampleFormats, hwiPortCap->supportSampleFormatNum,
        &portCap->supportSampleFormats, &portCap->supportSampleFormatsLen);
    if (ret != HDF_SUCCESS) {
        OsalMemFree((void *)portCap->formats);
        AudioHwiReleaseSubPorts(&portCap->subPorts, &portCap->subPortsLen);
        portCap->formats = NULL;
        AUDIO_FUNC_LOGE("HwiSampleFormatToSampleFormats fail");
        return ret;
    }

    return ret;
}

void AudioHwiCommonFreeHwiRoute(struct AudioHwiRoute *hwiRoute)
{
    CHECK_NULL_PTR_RETURN(hwiRoute);

    if (hwiRoute->sinks != NULL) {
        if (hwiRoute->sinksNum > AUDIO_ROUTE_NUM_MAX) {
            AUDIO_FUNC_LOGE("sinksNum para error");
            return;
        }

        for (uint32_t i = 0; i < hwiRoute->sinksNum; i++) {
            if (hwiRoute->sinks[i].type == AUDIO_HW_PORT_DEVICE_TYPE) {
                OsalMemFree((void *)hwiRoute->sinks[i].ext.device.desc);
            }
        }
        OsalMemFree((void *)hwiRoute->sinks);
    }

    if (hwiRoute->sources != NULL) {
        if (hwiRoute->sourcesNum > AUDIO_ROUTE_NUM_MAX) {
            AUDIO_FUNC_LOGE("sourcesNum para error");
            return;
        }

        for (uint32_t i = 0; i < hwiRoute->sourcesNum; i++) {
            if (hwiRoute->sources[i].type == AUDIO_HW_PORT_DEVICE_TYPE) {
                OsalMemFree((void *)hwiRoute->sources[i].ext.device.desc);
            }
        }
        OsalMemFree((void *)hwiRoute->sources);
    }
}

static int32_t AudioHwiCommonRouteNodeToHwiRouteNode(struct AudioRouteNode *routeNode,
    struct AudioHwiRouteNode *hwiRouteNode)
{
    hwiRouteNode->portId = routeNode->portId;
    hwiRouteNode->role = (enum AudioHwiPortRole)routeNode->role;
    hwiRouteNode->type = (enum AudioHwiPortType)routeNode->type;

    if (routeNode->type == AUDIO_HW_PORT_DEVICE_TYPE) {
        hwiRouteNode->ext.device.moduleId = routeNode->ext.device.moduleId;
        hwiRouteNode->ext.device.type = (enum AudioHwiPortPin)routeNode->ext.device.type;
        hwiRouteNode->ext.device.desc = strdup(routeNode->ext.device.desc);
        return HDF_SUCCESS;
    }

    if (routeNode->type == AUDIO_HW_PORT_MIX_TYPE) {
        hwiRouteNode->ext.mix.moduleId = routeNode->ext.mix.moduleId;
        hwiRouteNode->ext.mix.streamId = routeNode->ext.mix.streamId;
        return HDF_SUCCESS;
    }

    if (routeNode->type == AUDIO_HW_PORT_SESSION_TYPE) {
        hwiRouteNode->ext.session.sessionType = (enum AudioHwiSessionType)routeNode->ext.session.sessionType;
        return HDF_SUCCESS;
    }

    AUDIO_FUNC_LOGE("not match route node type");
    return HDF_FAILURE;
}

static int32_t AudioHwiCommonSinkToHwiSink(const struct AudioRoute *route, struct AudioHwiRoute *hwiRoute)
{
    struct AudioHwiRouteNode *nodes = NULL;
    if (route->sinksLen > AUDIO_ROUTE_NUM_MAX) {
        AUDIO_FUNC_LOGE("sinksLen para err");
        return HDF_ERR_INVALID_PARAM;
    }

    nodes = (struct AudioHwiRouteNode *)OsalMemCalloc(route->sinksLen * sizeof(struct AudioHwiRouteNode));
    if (nodes == NULL) {
        AUDIO_FUNC_LOGE("nodes null");
        return HDF_ERR_MALLOC_FAIL;
    }
    hwiRoute->sinks = nodes;
    hwiRoute->sinksNum = route->sinksLen;

    for (uint32_t i = 0; i < hwiRoute->sinksNum; i++) {
        int32_t ret = AudioHwiCommonRouteNodeToHwiRouteNode(&route->sinks[i], &hwiRoute->sinks[i]);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("sink routeNode to hwiRouteNode fail");
            /* nodes release by AudioHwiCommonFreeHwiRoute */
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

static int32_t AudioHwiCommonSourceToHwiSource(const struct AudioRoute *route, struct AudioHwiRoute *hwiRoute)
{
    struct AudioHwiRouteNode *nodes = NULL;
    if (route->sourcesLen > AUDIO_ROUTE_NUM_MAX) {
        AUDIO_FUNC_LOGE("sinksLen para err");
        return HDF_ERR_INVALID_PARAM;
    }

    nodes = (struct AudioHwiRouteNode *)OsalMemCalloc(route->sourcesLen * sizeof(struct AudioHwiRouteNode));
    if (nodes == NULL) {
        AUDIO_FUNC_LOGE("nodes null");
        return HDF_ERR_MALLOC_FAIL;
    }
    hwiRoute->sources = nodes;
    hwiRoute->sourcesNum = route->sourcesLen;

    for (uint32_t i = 0; i < hwiRoute->sourcesNum; i++) {
        int32_t ret = AudioHwiCommonRouteNodeToHwiRouteNode(&route->sources[i], &hwiRoute->sources[i]);
        if (ret != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE(" source routeNode to hwiRouteNode fail");
            /* nodes release by AudioHwiCommonFreeHwiRoute */
            return HDF_FAILURE;
        }
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCommonRouteToHwiRoute(const struct AudioRoute *route, struct AudioHwiRoute *hwiRoute)
{
    int32_t sinkRet;
    int32_t sourcesRet;

    CHECK_NULL_PTR_RETURN_VALUE(route, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRoute, HDF_ERR_INVALID_PARAM);

    if (route->sinks != NULL) {
        sinkRet = AudioHwiCommonSinkToHwiSink(route, hwiRoute);
        if (sinkRet != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE(" sink routeNode to hwiRouteNode fail");
        }
    }

    if (route->sources != NULL) {
        sourcesRet = AudioHwiCommonSourceToHwiSource(route, hwiRoute);
        if (sourcesRet != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE(" source routeNode to hwiRouteNode fail");
            return HDF_FAILURE;
        }
    }

    if (sinkRet != HDF_SUCCESS || sourcesRet != HDF_SUCCESS) {
        /* free nodes by sink and source malloc nodes memory */
        AudioHwiCommonFreeHwiRoute(hwiRoute);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCommonSceneToHwiScene(const struct AudioSceneDescriptor *scene,
    struct AudioHwiSceneDescriptor *hwiScene)
{
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiScene, HDF_ERR_INVALID_PARAM);

    hwiScene->scene.id = scene->scene.id;
    AudioHwiCommonDevDescToHwiDevDesc(&scene->desc, &hwiScene->desc);

    return HDF_SUCCESS;
}

int32_t AudioHwiCommonSampleAttrToHwiSampleAttr(const struct AudioSampleAttributes *attrs,
    struct AudioHwiSampleAttributes *hwiAttrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAttrs, HDF_ERR_INVALID_PARAM);

    hwiAttrs->type = (enum AudioHwiCategory)attrs->type;
    hwiAttrs->interleaved = attrs->interleaved;
    hwiAttrs->format = (enum AudioHwiFormat)attrs->format;
    hwiAttrs->sampleRate = attrs->sampleRate;
    hwiAttrs->channelCount = attrs->channelCount;
    hwiAttrs->period = attrs->period;
    hwiAttrs->frameSize = attrs->frameSize;
    hwiAttrs->isBigEndian = attrs->isBigEndian;
    hwiAttrs->isSignedData = attrs->isSignedData;
    hwiAttrs->startThreshold = attrs->startThreshold;
    hwiAttrs->stopThreshold = attrs->stopThreshold;
    hwiAttrs->silenceThreshold = attrs->silenceThreshold;
    hwiAttrs->streamId = attrs->streamId;

    return HDF_SUCCESS;
}

int32_t AudioHwiCommonHwiSampleAttrToSampleAttr(const struct AudioHwiSampleAttributes *hwiAttrs,
    struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiAttrs, HDF_ERR_INVALID_PARAM);

    attrs->type = (enum AudioCategory)hwiAttrs->type;
    attrs->interleaved = hwiAttrs->interleaved;
    attrs->format = (enum AudioFormat)hwiAttrs->format;
    attrs->sampleRate = hwiAttrs->sampleRate;
    attrs->channelCount = hwiAttrs->channelCount;
    attrs->period = hwiAttrs->period;
    attrs->frameSize = hwiAttrs->frameSize;
    attrs->isBigEndian = hwiAttrs->isBigEndian;
    attrs->isSignedData = hwiAttrs->isSignedData;
    attrs->startThreshold = hwiAttrs->startThreshold;
    attrs->stopThreshold = hwiAttrs->stopThreshold;
    attrs->silenceThreshold = hwiAttrs->silenceThreshold;
    attrs->streamId = hwiAttrs->streamId;

    return HDF_SUCCESS;
}
