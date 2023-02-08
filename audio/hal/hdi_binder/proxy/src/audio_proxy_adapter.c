/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "hdf_remote_service.h"
#include "osal_mem.h"
#include "audio_adapter_info_common.h"
#include "audio_proxy_common.h"
#include "audio_proxy_internal.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_PROXY

static int32_t AudioProxyCommonInitAttrs(struct HdfSBuf *data, const struct AudioSampleAttributes *attrs)
{
    if (data == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("data == NULL || attrs == NULL");
        return HDF_FAILURE;
    }
    uint32_t tempAtrr;
    tempAtrr = (uint32_t)attrs->interleaved;
    if (!HdfSbufWriteUint32(data, tempAtrr)) {
        AUDIO_FUNC_LOGE("interleaved Write Fail");
        return HDF_FAILURE;
    }
    tempAtrr = (uint32_t)attrs->type;
    if (!HdfSbufWriteUint32(data, tempAtrr)) {
        AUDIO_FUNC_LOGE("type Write Fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->period)) {
        AUDIO_FUNC_LOGE("period Write Fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->frameSize)) {
        AUDIO_FUNC_LOGE("frameSize Write Fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->startThreshold)) {
        AUDIO_FUNC_LOGE("startThreshold Write Fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->stopThreshold)) {
        AUDIO_FUNC_LOGE("stopThreshold Write Fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->silenceThreshold)) {
        AUDIO_FUNC_LOGE("silenceThreshold Write Fail");
        return HDF_FAILURE;
    }
    tempAtrr = (uint32_t)attrs->isBigEndian;
    if (!HdfSbufWriteUint32(data, tempAtrr)) {
        AUDIO_FUNC_LOGE("isBigEndian Write Fail");
        return HDF_FAILURE;
    }
    tempAtrr = (uint32_t)attrs->isSignedData;
    if (!HdfSbufWriteUint32(data, tempAtrr)) {
        AUDIO_FUNC_LOGE("isSignedData Write Fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioProxyCommonInitCreateData(struct HdfSBuf *data, const struct AudioHwAdapter *adapter,
    const struct AudioDeviceDescriptor *desc, const struct AudioSampleAttributes *attrs)
{
    AUDIO_FUNC_LOGI();
    if (data == NULL || adapter == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("data == NULL || adapter == NULL || desc == NULL || attrs == NULL");
        return HDF_FAILURE;
    }
    uint32_t tempDesc;
    uint32_t tempAtrr;
    int32_t pid = getpid();
    const char *adapterName = adapter->adapterDescriptor.adapterName;
    if (adapterName == NULL) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(data, adapterName)) {
        AUDIO_FUNC_LOGE("adapterName Write Fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(data, pid)) {
        AUDIO_FUNC_LOGE("pid Write Fail");
        return HDF_FAILURE;
    }
    tempAtrr = (uint32_t)attrs->format;
    if (!HdfSbufWriteUint32(data, tempAtrr)) {
        AUDIO_FUNC_LOGE("format Write Fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->channelCount)) {
        AUDIO_FUNC_LOGE("channelCount Write Fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->sampleRate)) {
        AUDIO_FUNC_LOGE("sampleRate Write Fail");
        return HDF_FAILURE;
    }
    if (AudioProxyCommonInitAttrs(data, attrs) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, desc->portId)) {
        AUDIO_FUNC_LOGE("portId Write Fail");
        return HDF_FAILURE;
    }
    tempDesc = (uint32_t)desc->pins;
    if (!HdfSbufWriteUint32(data, tempDesc)) {
        AUDIO_FUNC_LOGE("pins Write Fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t GetAudioProxyRenderFunc(struct AudioHwRender *hwRender)
{
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("hwRender is null");
        return HDF_FAILURE;
    }
    hwRender->common.control.Start = AudioProxyRenderStart;
    hwRender->common.control.Stop = AudioProxyRenderStop;
    hwRender->common.control.Pause = AudioProxyRenderPause;
    hwRender->common.control.Resume = AudioProxyRenderResume;
    hwRender->common.control.Flush = AudioProxyRenderFlush;
    hwRender->common.control.TurnStandbyMode = AudioProxyRenderTurnStandbyMode;
    hwRender->common.control.AudioDevDump = AudioProxyRenderAudioDevDump;
    hwRender->common.attr.GetFrameSize = AudioProxyRenderGetFrameSize;
    hwRender->common.attr.GetFrameCount = AudioProxyRenderGetFrameCount;
    hwRender->common.attr.SetSampleAttributes = AudioProxyRenderSetSampleAttributes;
    hwRender->common.attr.GetSampleAttributes = AudioProxyRenderGetSampleAttributes;
    hwRender->common.attr.GetCurrentChannelId = AudioProxyRenderGetCurrentChannelId;
    hwRender->common.attr.SetExtraParams = AudioProxyRenderSetExtraParams;
    hwRender->common.attr.GetExtraParams = AudioProxyRenderGetExtraParams;
    hwRender->common.attr.ReqMmapBuffer = AudioProxyRenderReqMmapBuffer;
    hwRender->common.attr.GetMmapPosition = AudioProxyRenderGetMmapPosition;
    hwRender->common.attr.AddAudioEffect = AudioProxyRenderAddEffect;
    hwRender->common.attr.RemoveAudioEffect = AudioProxyRenderRemoveEffect;
    hwRender->common.scene.CheckSceneCapability = AudioProxyRenderCheckSceneCapability;
    hwRender->common.scene.SelectScene = AudioProxyRenderSelectScene;
    hwRender->common.volume.SetMute = AudioProxyRenderSetMute;
    hwRender->common.volume.GetMute = AudioProxyRenderGetMute;
    hwRender->common.volume.SetVolume = AudioProxyRenderSetVolume;
    hwRender->common.volume.GetVolume = AudioProxyRenderGetVolume;
    hwRender->common.volume.GetGainThreshold = AudioProxyRenderGetGainThreshold;
    hwRender->common.volume.GetGain = AudioProxyRenderGetGain;
    hwRender->common.volume.SetGain = AudioProxyRenderSetGain;
    hwRender->common.GetLatency = AudioProxyRenderGetLatency;
    hwRender->common.RenderFrame = AudioProxyRenderRenderFrame;
    hwRender->common.GetRenderPosition = AudioProxyRenderGetRenderPosition;
    hwRender->common.SetRenderSpeed = AudioProxyRenderSetRenderSpeed;
    hwRender->common.GetRenderSpeed = AudioProxyRenderGetRenderSpeed;
    hwRender->common.SetChannelMode = AudioProxyRenderSetChannelMode;
    hwRender->common.GetChannelMode = AudioProxyRenderGetChannelMode;
    hwRender->common.RegCallback = AudioProxyRenderRegCallback;
    hwRender->common.DrainBuffer = AudioProxyRenderDrainBuffer;
    return HDF_SUCCESS;
}

int32_t InitHwRenderParam(struct AudioHwRender *hwRender, const struct AudioDeviceDescriptor *desc,
                          const struct AudioSampleAttributes *attrs)
{
    if (hwRender == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("InitHwRenderParam param Is NULL");
        return HDF_FAILURE;
    }
    hwRender->renderParam.renderMode.hwInfo.deviceDescript = *desc;
    hwRender->renderParam.frameRenderMode.attrs = *attrs;
    return HDF_SUCCESS;
}

enum AudioFormat g_formatIdZero = AUDIO_FORMAT_PCM_16_BIT;
int32_t InitForGetPortCapability(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex)
{
    if (capabilityIndex == NULL) {
        AUDIO_FUNC_LOGE("Parameter is null");
        return HDF_FAILURE;
    }
    /* get capabilityIndex from driver or default */
    if (portIndex.dir != PORT_OUT) {
        capabilityIndex->hardwareMode = true;
        capabilityIndex->channelMasks = AUDIO_CHANNEL_STEREO;
        capabilityIndex->channelCount = CONFIG_CHANNEL_COUNT;
        return HDF_SUCCESS;
    }
    if (InitPortForCapabilitySub(portIndex, capabilityIndex) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("InitPortForCapability fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void AudioAdapterReleaseCapSubPorts(const struct AudioPortAndCapability *portCapabilitys, const int32_t num)
{
    int32_t i = 0;
    if (portCapabilitys == NULL) {
        return;
    }
    while (i < num) {
        if (&portCapabilitys[i] == NULL) {
            break;
        }
        AudioMemFree((void **)(&portCapabilitys[i].capability.subPorts));
        i++;
    }
    return;
}
static int32_t InitAllPortsDispatchSplit(struct AudioHwAdapter *hwAdapter)
{
    if (hwAdapter == NULL || hwAdapter->adapterDescriptor.adapterName == NULL || hwAdapter->proxyRemoteHandle == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    const char *adapterName = NULL;
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(hwAdapter->proxyRemoteHandle, data)) {
        AUDIO_FUNC_LOGE("write interface token failed");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    adapterName = hwAdapter->adapterDescriptor.adapterName;
    if (!HdfSbufWriteString(data, adapterName)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_INIT_PORTS, data, reply);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get Failed AudioAdapter!");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyAdapterInitAllPorts(struct AudioAdapter *adapter)
{
    int32_t ret = AUDIO_HAL_SUCCESS;

    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || hwAdapter->adapterDescriptor.adapterName == NULL ||
        hwAdapter->proxyRemoteHandle == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter Is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    /* Fake data */
    uint32_t portNum = hwAdapter->adapterDescriptor.portNum;
    struct AudioPort *ports = hwAdapter->adapterDescriptor.ports;
    if (ports == NULL || portNum == 0) {
        AUDIO_FUNC_LOGE("ports is NULL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioPortAndCapability *portCapability = (struct AudioPortAndCapability *)OsalMemCalloc(
        portNum * sizeof(struct AudioPortAndCapability));
    if (portCapability == NULL) {
        AUDIO_FUNC_LOGE("portCapability is NULL!");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    for (uint32_t i = 0; i < portNum; i++) {
        portCapability[i].port = ports[i];
        if (InitForGetPortCapability(ports[i], &portCapability[i].capability)) {
            AUDIO_FUNC_LOGE("ports Init Invalid!");
            AudioAdapterReleaseCapSubPorts(portCapability, portNum);
            AudioMemFree((void **)&portCapability);
            return AUDIO_HAL_ERR_INTERNAL;
        }
    }
    hwAdapter->portCapabilitys = portCapability;
    hwAdapter->portCapabilitys->mode = PORT_PASSTHROUGH_LPCM;
    ret = InitAllPortsDispatchSplit(hwAdapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("InitAllPortsDispatchSplit Fail");
        return ret;
    }
    return AUDIO_HAL_SUCCESS;
}

static int32_t AudioProxyAdapterCreateRenderSplit(const struct AudioHwAdapter *hwAdapter,
    struct AudioHwRender *hwRender)
{
    if (hwAdapter == NULL || hwRender == NULL) {
        return HDF_FAILURE;
    }
    if (hwAdapter->adapterDescriptor.adapterName == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter->adapterDescriptor.adapterName is null!");
        return HDF_FAILURE;
    }
    uint32_t adapterNameLen = strlen(hwAdapter->adapterDescriptor.adapterName);
    /* Get Adapter name */
    int32_t ret = strncpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName, NAME_LEN,
        hwAdapter->adapterDescriptor.adapterName, adapterNameLen);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("strncpy_s hwAdapter->adapterDescriptor.adapterName failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioProxyRenderDispatchSplit(const struct AudioHwAdapter *hwAdapter,
    struct AudioHwRender *hwRender, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (hwAdapter == NULL || hwRender == NULL ||
        hwRender->proxyRemoteHandle == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyAdapterCreateRenderSplit(hwAdapter, hwRender) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAddRenderAddrToList((AudioHandle)(&hwRender->common));
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The proxyRender address get is invalid");
        return ret;
    }
    ret = AudioProxyDispatchCall(hwRender->proxyRemoteHandle, AUDIO_HDI_RENDER_CREATE_RENDER, data, reply);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Send Server fail!");
        if (AudioDelRenderAddrFromList((AudioHandle)(&hwRender->common)) < 0) {
            AUDIO_FUNC_LOGE("AudioDelRenderAddrFromList failed.");
        }
        return ret;
    }
    return AUDIO_HAL_SUCCESS;
}

static inline int32_t AudioProxyWriteTokenAndInitData(struct AudioHwAdapter *hwAdapter, struct HdfSBuf *data,
    const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs)
{
    if (!HdfRemoteServiceWriteInterfaceToken(hwAdapter->proxyRemoteHandle, data)) {
        AUDIO_FUNC_LOGE("write interface token failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyCommonInitCreateData(data, hwAdapter, desc, attrs) < 0) {
        AUDIO_FUNC_LOGE("Failed to obtain reply");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyAdapterCreateRender(struct AudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
                                      const struct AudioSampleAttributes *attrs, struct AudioRender **render)
{
    AUDIO_FUNC_LOGI();
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    int32_t ret = AUDIO_HAL_SUCCESS;

    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || hwAdapter->proxyRemoteHandle == NULL || desc == NULL || attrs == NULL || render == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioHwRender *hwRender = (struct AudioHwRender *)OsalMemCalloc(sizeof(*hwRender));
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("hwRender is NULL!");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    hwRender->proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    if (GetAudioProxyRenderFunc(hwRender) < 0) {
        AudioMemFree((void **)&hwRender);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    /* Fill hwRender para */
    if (InitHwRenderParam(hwRender, desc, attrs) < 0) {
        AudioMemFree((void **)&hwRender);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        AudioMemFree((void **)&hwRender);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyWriteTokenAndInitData(hwAdapter, data, desc, attrs) != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("Render write interface token or initdata failed");
        AudioProxyBufReplyRecycle(data, reply);
        AudioMemFree((void **)&hwRender);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioProxyRenderDispatchSplit(hwAdapter, hwRender, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        AudioMemFree((void **)&hwRender);
        return ret;
    }
    *render = &hwRender->common;
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyAdapterDestroyRender(struct AudioAdapter *adapter, struct AudioRender *render)
{
    int32_t ret = AUDIO_HAL_SUCCESS;
    if (adapter == NULL || render == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    ret = AudioCheckRenderAddr((AudioHandle)render);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The proxyRender address passed in is invalid");
        return ret;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    if (hwRender->proxyRemoteHandle == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessRender((AudioHandle)render, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioProxyDispatchCall(hwRender->proxyRemoteHandle, AUDIO_HDI_RENDER_DESTROY, data, reply);
    if (ret < 0) {
        if (ret != AUDIO_HAL_ERR_INVALID_OBJECT) {
            AUDIO_FUNC_LOGE("AudioRenderRenderFrame FAIL");
            AudioProxyBufReplyRecycle(data, reply);
            return ret;
        }
    }
    if (AudioDelRenderAddrFromList((AudioHandle)render) < 0) {
        AUDIO_FUNC_LOGE("proxyAdapter or proxyRender not in MgrList");
    }
    AudioMemFree((void **)&hwRender->renderParam.frameRenderMode.buffer);
    AudioMemFree((void **)&render);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

static int32_t GetAudioProxyCaptureFunc(struct AudioHwCapture *hwCapture)
{
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture is null");
        return HDF_FAILURE;
    }
    hwCapture->common.control.Start = AudioProxyCaptureStart;
    hwCapture->common.control.Stop = AudioProxyCaptureStop;
    hwCapture->common.control.Pause = AudioProxyCapturePause;
    hwCapture->common.control.Resume = AudioProxyCaptureResume;
    hwCapture->common.control.Flush = AudioProxyCaptureFlush;
    hwCapture->common.control.TurnStandbyMode = AudioProxyCaptureTurnStandbyMode;
    hwCapture->common.control.AudioDevDump = AudioProxyCaptureAudioDevDump;
    hwCapture->common.attr.GetFrameSize = AudioProxyCaptureGetFrameSize;
    hwCapture->common.attr.GetFrameCount = AudioProxyCaptureGetFrameCount;
    hwCapture->common.attr.SetSampleAttributes = AudioProxyCaptureSetSampleAttributes;
    hwCapture->common.attr.GetSampleAttributes = AudioProxyCaptureGetSampleAttributes;
    hwCapture->common.attr.GetCurrentChannelId = AudioProxyCaptureGetCurrentChannelId;
    hwCapture->common.attr.SetExtraParams = AudioProxyCaptureSetExtraParams;
    hwCapture->common.attr.GetExtraParams = AudioProxyCaptureGetExtraParams;
    hwCapture->common.attr.ReqMmapBuffer = AudioProxyCaptureReqMmapBuffer;
    hwCapture->common.attr.GetMmapPosition = AudioProxyCaptureGetMmapPosition;
    hwCapture->common.attr.AddAudioEffect = AudioProxyCaptureAddEffect;
    hwCapture->common.attr.RemoveAudioEffect = AudioProxyCaptureRemoveEffect;
    hwCapture->common.scene.CheckSceneCapability = AudioProxyCaptureCheckSceneCapability;
    hwCapture->common.scene.SelectScene = AudioProxyCaptureSelectScene;
    hwCapture->common.volume.SetMute = AudioProxyCaptureSetMute;
    hwCapture->common.volume.GetMute = AudioProxyCaptureGetMute;
    hwCapture->common.volume.SetVolume = AudioProxyCaptureSetVolume;
    hwCapture->common.volume.GetVolume = AudioProxyCaptureGetVolume;
    hwCapture->common.volume.GetGainThreshold = AudioProxyCaptureGetGainThreshold;
    hwCapture->common.volume.GetGain = AudioProxyCaptureGetGain;
    hwCapture->common.volume.SetGain = AudioProxyCaptureSetGain;
    hwCapture->common.CaptureFrame = AudioProxyCaptureCaptureFrame;
    hwCapture->common.GetCapturePosition = AudioProxyCaptureGetCapturePosition;
    return HDF_SUCCESS;
}

static int32_t InitProxyHwCaptureParam(struct AudioHwCapture *hwCapture, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs)
{
    if (hwCapture == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("InitHwCaptureParam param Is NULL");
        return HDF_FAILURE;
    }
    hwCapture->captureParam.captureMode.hwInfo.deviceDescript = *desc;
    hwCapture->captureParam.frameCaptureMode.attrs = *attrs;
    return HDF_SUCCESS;
}

static int32_t AudioProxyAdapterCreateCaptureSplit(const struct AudioHwAdapter *hwAdapter,
    struct AudioHwCapture *hwCapture)
{
    if (hwAdapter == NULL || hwCapture == NULL) {
        AUDIO_FUNC_LOGE("param Is NULL");
        return HDF_FAILURE;
    }
    if (hwAdapter->adapterDescriptor.adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName Is NULL");
        return HDF_FAILURE;
    }
    uint32_t adapterNameLen = strlen(hwAdapter->adapterDescriptor.adapterName);
    /* Get AdapterName */
    int32_t ret = strncpy_s(hwCapture->captureParam.captureMode.hwInfo.adapterName, NAME_LEN,
        hwAdapter->adapterDescriptor.adapterName, adapterNameLen);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioProxyCaptureDispatchSplit(const struct AudioHwAdapter *hwAdapter,
    struct AudioHwCapture *hwCapture, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (hwAdapter == NULL || hwCapture == NULL || hwCapture->proxyRemoteHandle == NULL ||
        data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyAdapterCreateCaptureSplit(hwAdapter, hwCapture) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAddCaptureAddrToList((AudioHandle)(&hwCapture->common));
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The proxyCapture address get is invalid");
        return ret;
    }
    ret = AudioProxyDispatchCall(hwCapture->proxyRemoteHandle, AUDIO_HDI_CAPTURE_CREATE_CAPTURE, data, reply);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Send Server fail!");
        if (AudioDelCaptureAddrFromList((AudioHandle)(&hwCapture->common)) < 0) {
            AUDIO_FUNC_LOGE("AudioDelRenderAddrFromList failed.");
        }
        return ret;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyAdapterCreateCapture(struct AudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
                                       const struct AudioSampleAttributes *attrs, struct AudioCapture **capture)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AUDIO_HAL_SUCCESS;

    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || hwAdapter->proxyRemoteHandle == NULL || desc == NULL ||
        attrs == NULL || capture == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)OsalMemCalloc(sizeof(struct AudioHwCapture));
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture is NULL!");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    hwCapture->proxyRemoteHandle = hwAdapter->proxyRemoteHandle;
    if (GetAudioProxyCaptureFunc(hwCapture) < 0) {
        AudioMemFree((void **)&hwCapture);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    /* Fill hwRender para */
    if (InitProxyHwCaptureParam(hwCapture, desc, attrs) < 0) {
        AudioMemFree((void **)&hwCapture);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        AudioMemFree((void **)&hwCapture);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyWriteTokenAndInitData(hwAdapter, data, desc, attrs) != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("Capture write interface token or initdata failed");
        AudioProxyBufReplyRecycle(data, reply);
        AudioMemFree((void **)&hwCapture);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioProxyCaptureDispatchSplit(hwAdapter, hwCapture, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        AudioMemFree((void **)&hwCapture);
        return ret;
    }
    *capture = &hwCapture->common;
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyAdapterDestroyCapture(struct AudioAdapter *adapter, struct AudioCapture *capture)
{
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (adapter == NULL || capture == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = AUDIO_HAL_SUCCESS;

    ret = AudioCheckCaptureAddr((AudioHandle)capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The proxy capture address passed in is invalid");
        return ret;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    if (hwCapture == NULL || hwCapture->proxyRemoteHandle == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessCapture((AudioHandle)capture, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioProxyDispatchCall(hwCapture->proxyRemoteHandle, AUDIO_HDI_CAPTURE_DESTROY, data, reply);
    if (ret < 0) {
        if (ret != AUDIO_HAL_ERR_INVALID_OBJECT) {
            AUDIO_FUNC_LOGE("AudioCaptureCaptuerFrame fail!");
            AudioProxyBufReplyRecycle(data, reply);
            return ret;
        }
    }
    if (AudioDelCaptureAddrFromList((AudioHandle)capture)) {
        AUDIO_FUNC_LOGE("proxy adapter or capture not in MgrList");
    }
    AudioMemFree((void **)&hwCapture->captureParam.frameCaptureMode.buffer);
    AudioMemFree((void **)&capture);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}
static int32_t AudioProxyAdapterWritePortCapability(const struct AudioHwAdapter *hwAdapter,
    const struct AudioPort *port, struct HdfSBuf *data)
{
    if (hwAdapter == NULL || port == NULL || data == NULL) {
        return HDF_FAILURE;
    }
    if (hwAdapter->adapterDescriptor.adapterName == NULL) {
        return HDF_FAILURE;
    }
    const char *adapterName = hwAdapter->adapterDescriptor.adapterName;
    if (!HdfSbufWriteString(data, adapterName)) {
        return HDF_FAILURE;
    }
    uint32_t tempDir = (uint32_t)port->dir;
    if (!HdfSbufWriteUint32(data, tempDir)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, port->portId)) {
        return HDF_FAILURE;
    }
    if (port->portName == NULL) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(data, port->portName)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyAdapterGetPortCapability(struct AudioAdapter *adapter,
    const struct AudioPort *port, struct AudioPortCapability *capability)
{
    AUDIO_FUNC_LOGI();
    int32_t ret = AUDIO_HAL_SUCCESS;

    if (adapter == NULL || port == NULL || port->portName == NULL || capability == NULL || (port->portId < 0)) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->proxyRemoteHandle == NULL) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(hwAdapter->proxyRemoteHandle, data)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyAdapterWritePortCapability(hwAdapter, port, data)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_GET_PORT_CAPABILITY, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    AudioProxyBufReplyRecycle(data, reply);
    /* proxy must init local capability ,this capability the same of Server's */
    struct AudioPortAndCapability *hwAdapterPortCapabilitys = hwAdapter->portCapabilitys;
    if (hwAdapterPortCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter portCapabilitys is NULL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    uint32_t portNum = hwAdapter->adapterDescriptor.portNum;
    while (hwAdapterPortCapabilitys != NULL && (portNum > 0)) {
        if (hwAdapterPortCapabilitys->port.portId == port->portId) {
            *capability = hwAdapterPortCapabilitys->capability;
            return AUDIO_HAL_SUCCESS;
        }
        hwAdapterPortCapabilitys++;
        portNum--;
    }
    return AUDIO_HAL_ERR_INTERNAL;
}

static int32_t AudioProxyAdapterSetAndGetPassthroughModeSBuf(struct HdfSBuf *data,
    const struct HdfSBuf *reply, const struct AudioPort *port)
{
    (void)reply;
    if (data == NULL || port == NULL || port->portName == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempDir = port->dir;
    if (!HdfSbufWriteUint32(data, tempDir)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, port->portId)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(data, port->portName)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteString error");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioProxyWriteTokenAndNameForSetPassThrough(struct AudioHwAdapter *hwAdapter, struct HdfSBuf *data)
{
    if (hwAdapter == NULL || hwAdapter->proxyRemoteHandle == NULL ||
        hwAdapter->adapterDescriptor.adapterName == NULL) {
        AUDIO_FUNC_LOGE("The input para is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(hwAdapter->proxyRemoteHandle, data)) {
        AUDIO_FUNC_LOGE("write interface token failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    const char *adapterName = hwAdapter->adapterDescriptor.adapterName;
    if (!HdfSbufWriteString(data, adapterName)) {
        AUDIO_FUNC_LOGE("adapterName Write Fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyAdapterSetPassthroughMode(struct AudioAdapter *adapter,
    const struct AudioPort *port, enum AudioPortPassthroughMode mode)
{
    AUDIO_FUNC_LOGI();
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    int32_t ret = AUDIO_HAL_SUCCESS;

    if (adapter == NULL || port == NULL || port->portName == NULL) {
        AUDIO_FUNC_LOGE("Params is null.");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (port->dir != PORT_OUT || port->portId < 0 || strcmp(port->portName, "AOP") != 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->proxyRemoteHandle == NULL ||
        hwAdapter->adapterDescriptor.adapterName == NULL) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (AudioProxyWriteTokenAndNameForSetPassThrough(hwAdapter, data) != AUDIO_HAL_SUCCESS) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyAdapterSetAndGetPassthroughModeSBuf(data, reply, port) < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteUint32(data, (uint32_t)mode)) {
        AUDIO_FUNC_LOGE("Mode Write Fail");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_SET_PASS_MODE, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        AUDIO_FUNC_LOGE("Failed to send server, ret = %{public}d", ret);
        return ret;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

static int32_t AudioProxyWriteTokenAndNameForGetPassThrough(struct AudioHwAdapter *hwAdapter, struct HdfSBuf *data)
{
    if (hwAdapter == NULL || hwAdapter->proxyRemoteHandle == NULL ||
        hwAdapter->adapterDescriptor.adapterName == NULL) {
        AUDIO_FUNC_LOGE("The input para is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(hwAdapter->proxyRemoteHandle, data)) {
        AUDIO_FUNC_LOGE("write interface token failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    const char *adapterName = hwAdapter->adapterDescriptor.adapterName;
    if (!HdfSbufWriteString(data, adapterName)) {
        AUDIO_FUNC_LOGE("adapterName Write Fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyAdapterGetPassthroughMode(struct AudioAdapter *adapter,
    const struct AudioPort *port, enum AudioPortPassthroughMode *mode)
{
    int32_t ret = AUDIO_HAL_SUCCESS;

    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (adapter == NULL || port == NULL || port->portName == NULL || mode == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (port->dir != PORT_OUT || port->portId < 0 || strcmp(port->portName, "AOP") != 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->proxyRemoteHandle == NULL) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyWriteTokenAndNameForGetPassThrough(hwAdapter, data) != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to write token or adapter name");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioProxyAdapterSetAndGetPassthroughModeSBuf(data, reply, port) < 0) {
        AUDIO_FUNC_LOGE("Failed to obtain data");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_GET_PASS_MODE, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    uint32_t tempMode = 0;
    if (!HdfSbufReadUint32(reply, &tempMode)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    *mode = (enum AudioPortPassthroughMode)tempMode;
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyAdapterSetMicMute(struct AudioAdapter *adapter, bool mute)
{
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || hwAdapter->proxyRemoteHandle == NULL) {
        AUDIO_FUNC_LOGE("the parameter is null");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        AUDIO_FUNC_LOGE("AudioProxyAdapterSetMicMute FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (AudioProxyWriteTokenAndNameForSetPassThrough(hwAdapter, data) != AUDIO_HAL_SUCCESS) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteUint32(data, (uint32_t)mute)) {
        AUDIO_FUNC_LOGE("tempMute Write Fail");
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }

    int ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_SET_MIC_MUTE, data, reply);
    if (ret != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("%{public}s:set parameter failed!", __func__);
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyAdapterGetMicMute(struct AudioAdapter *adapter, bool *mute)
{
    uint32_t tempMute = 0;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || hwAdapter->proxyRemoteHandle == NULL || mute == NULL) {
        AUDIO_FUNC_LOGE("the parameter is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        AUDIO_FUNC_LOGE("AudioProxyAdapterGetMicMute FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (AudioProxyWriteTokenAndNameForSetPassThrough(hwAdapter, data) != AUDIO_HAL_SUCCESS) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    int32_t ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_GET_MIC_MUTE, data, reply);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioProxyAdapterGetMicMute FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }

    if (!HdfSbufReadUint32(reply, &tempMute)) {
        AUDIO_FUNC_LOGE("tempMute Read Fail");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    *mute = (bool)tempMute;
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyAdapterSetVoiceVolume(struct AudioAdapter *adapter, float volume)
{
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("the parameter is empty");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }

    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->proxyRemoteHandle == NULL) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (AudioProxyWriteTokenAndNameForSetPassThrough(hwAdapter, data) != AUDIO_HAL_SUCCESS) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteFloat(data, volume)) {
        AUDIO_FUNC_LOGE("adapterName Write Fail");
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }

    int ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_SET_VOICE_VOLUME, data, reply);
    if (ret != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("%{public}s:set parameter failed!", __func__);
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyAdapterSetExtraParams(struct AudioAdapter *adapter, enum AudioExtParamKey key,
                                        const char *condition, const char *value)
{
    if (adapter == NULL || value == NULL) {
        AUDIO_FUNC_LOGE("the parameter is empty");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    (void)key;
    (void)condition;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        AUDIO_FUNC_LOGE("AudioProxyAdapterSetExtraParams FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->proxyRemoteHandle == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter->proxyRemoteHandle is NULL");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (AudioProxyWriteTokenAndNameForSetPassThrough(hwAdapter, data) != AUDIO_HAL_SUCCESS) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteString(data, value)) {
        AUDIO_FUNC_LOGE("value write fail");
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }

    int ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_SET_EXTRA_PARAMS, data, reply);
    if (ret != AUDIO_HAL_SUCCESS) {
        AUDIO_FUNC_LOGE("%{public}s:set parameter failed!", __func__);
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyAdapterGetExtraParams(struct AudioAdapter *adapter, enum AudioExtParamKey key,
                                        const char *condition, char *value, int32_t length)
{
    if (adapter == NULL || value == NULL || condition == NULL || length <= 0) {
        AUDIO_FUNC_LOGE("AudioProxyAdapterGetExtraParams FAIL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    (void)key;
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    const char *strValue = NULL;
    if (AudioProxyPreprocessSBuf(&data, &reply) < 0) {
        AUDIO_FUNC_LOGE("AudioProxyAdapterGetExtraParams FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->proxyRemoteHandle == NULL) {
        AUDIO_FUNC_LOGE("parameter is null");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (AudioProxyWriteTokenAndNameForSetPassThrough(hwAdapter, data) != AUDIO_HAL_SUCCESS) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteString(data, condition)) {
        AUDIO_FUNC_LOGE("condition write fail");
        AudioProxyBufReplyRecycle(data, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(data, length)) {
        AUDIO_FUNC_LOGE("length write fail");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    int ret = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_GET_EXTRA_PARAMS, data, reply);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioProxyAdapterGetExtraParams FAIL");
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }

    strValue = HdfSbufReadString(reply);
    if (strValue == NULL) {
        AUDIO_FUNC_LOGE("value is empty");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (length < (int32_t)(strlen(strValue) + 1)) {
        AUDIO_FUNC_LOGE("length less than strlen(strValue)!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    ret = strncpy_s(value, length, strValue, strlen(strValue));
    if (ret != 0) {
        AUDIO_FUNC_LOGE("copy failed!");
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }

    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyAdapterUpdateAudioRoute(struct AudioAdapter *adapter,
    const struct AudioRoute *route, int32_t *routeHandle)
{
    int32_t audioAdapterRet = HDF_FAILURE;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || hwAdapter->proxyRemoteHandle == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct HdfSBuf *audioAdapterData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *audioAdapterReply = HdfSbufTypedObtain(SBUF_IPC);

    if (audioAdapterData == NULL || audioAdapterReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        audioAdapterRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (AudioProxyWriteTokenAndNameForSetPassThrough(hwAdapter, audioAdapterData) != AUDIO_HAL_SUCCESS) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        audioAdapterRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!AudioRouteBlockMarshalling(audioAdapterData, route)) {
        HDF_LOGE("%{public}s: write route failed!", __func__);
        audioAdapterRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    audioAdapterRet = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_UPDATE_ROUTE,
                                             audioAdapterData, audioAdapterReply);
    if (audioAdapterRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, audioAdapterRet);
        goto FINISHED;
    }

    if (!HdfSbufReadInt32(audioAdapterReply, routeHandle)) {
        HDF_LOGE("%{public}s: read routeHandle failed!", __func__);
        audioAdapterRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

FINISHED:
    if (audioAdapterData != NULL) {
        HdfSbufRecycle(audioAdapterData);
    }
    if (audioAdapterReply != NULL) {
        HdfSbufRecycle(audioAdapterReply);
    }
    return audioAdapterRet;
}

int32_t AudioProxyAdapterReleaseAudioRoute(struct AudioAdapter *adapter, int32_t routeHandle)
{
    int32_t audioAdapterRet = HDF_FAILURE;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || hwAdapter->proxyRemoteHandle == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    struct HdfSBuf *audioAdapterData = HdfSbufTypedObtain(SBUF_IPC);
    struct HdfSBuf *audioAdapterReply = HdfSbufTypedObtain(SBUF_IPC);
    if (audioAdapterData == NULL || audioAdapterReply == NULL) {
        HDF_LOGE("%{public}s: HdfSubf malloc failed!", __func__);
        audioAdapterRet = HDF_ERR_MALLOC_FAIL;
        goto FINISHED;
    }

    if (AudioProxyWriteTokenAndNameForSetPassThrough(hwAdapter, audioAdapterData) != AUDIO_HAL_SUCCESS) {
        HDF_LOGE("%{public}s: write interface token failed!", __func__);
        audioAdapterRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    if (!HdfSbufWriteInt32(audioAdapterData, routeHandle)) {
        HDF_LOGE("%{public}s: write routeHandle failed!", __func__);
        audioAdapterRet = HDF_ERR_INVALID_PARAM;
        goto FINISHED;
    }

    audioAdapterRet = AudioProxyDispatchCall(hwAdapter->proxyRemoteHandle, AUDIO_HDI_ADT_RELEASE_ROUTE,
                                             audioAdapterData, audioAdapterData);
    if (audioAdapterRet != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: call failed! error code is %{public}d", __func__, audioAdapterRet);
        goto FINISHED;
    }

FINISHED:
    if (audioAdapterData != NULL) {
        HdfSbufRecycle(audioAdapterData);
    }
    if (audioAdapterReply != NULL) {
        HdfSbufRecycle(audioAdapterReply);
    }
    return audioAdapterRet;
}
int32_t AudioProxyAdapterGetDeviceStatus(struct AudioAdapter *adapter, struct AudioDeviceStatus *status)
{
    (void)adapter;
    (void)status;
    return HDF_ERR_NOT_SUPPORT;
}
