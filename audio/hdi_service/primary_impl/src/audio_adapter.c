/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "audio_adapter_info_common.h"
#include "audio_common.h"
#include "audio_interface_lib_capture.h"
#include "audio_interface_lib_render.h"
#include "audio_internal.h"
#include "audio_uhdf_log.h"
#include "hdf_types.h"
#include "osal_mem.h"
#include "securec.h"
#include "stub_collector.h"

#define HDF_LOG_TAG HDF_AUDIO_PRIMARY_IMPL

#define CONFIG_CHANNEL_COUNT            2 // two channels
#define GAIN_MAX                        50.0
#define DEFAULT_RENDER_SAMPLING_RATE    48000
#define DEEP_BUFFER_RENDER_PERIOD_SIZE  4096
#define DEEP_BUFFER_RENDER_PERIOD_COUNT 8
#define TYPE_RENDER                     "Render"
#define TYPE_CAPTURE                    "Capture"
#define INT_32_MAX                      0x7fffffff
#define SHIFT_RIGHT_31_BITS             31

static int32_t AudioHwRenderInit(struct AudioHwRender *hwRender)
{
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }
    hwRender->common.Start = AudioRenderStart;
    hwRender->common.Stop = AudioRenderStop;
    hwRender->common.Pause = AudioRenderPause;
    hwRender->common.Resume = AudioRenderResume;
    hwRender->common.Flush = AudioRenderFlush;
    hwRender->common.TurnStandbyMode = AudioRenderTurnStandbyMode;
    hwRender->common.AudioDevDump = AudioRenderAudioDevDump;
    hwRender->common.GetFrameSize = AudioRenderGetFrameSize;
    hwRender->common.GetFrameCount = AudioRenderGetFrameCount;
    hwRender->common.SetSampleAttributes = AudioRenderSetSampleAttributes;
    hwRender->common.GetSampleAttributes = AudioRenderGetSampleAttributes;
    hwRender->common.GetCurrentChannelId = AudioRenderGetCurrentChannelId;
    hwRender->common.SetExtraParams = AudioRenderSetExtraParams;
    hwRender->common.GetExtraParams = AudioRenderGetExtraParams;
    hwRender->common.ReqMmapBuffer = AudioRenderReqMmapBuffer;
    hwRender->common.GetMmapPosition = AudioRenderGetMmapPosition;
    hwRender->common.CheckSceneCapability = AudioRenderCheckSceneCapability;
    hwRender->common.SelectScene = AudioRenderSelectScene;
    hwRender->common.SetMute = AudioRenderSetMute;
    hwRender->common.GetMute = AudioRenderGetMute;
    hwRender->common.SetVolume = AudioRenderSetVolume;
    hwRender->common.GetVolume = AudioRenderGetVolume;
    hwRender->common.GetGainThreshold = AudioRenderGetGainThreshold;
    hwRender->common.GetGain = AudioRenderGetGain;
    hwRender->common.SetGain = AudioRenderSetGain;
    hwRender->common.GetLatency = AudioRenderGetLatency;
    hwRender->common.RenderFrame = AudioRenderRenderFrame;
    hwRender->common.GetRenderPosition = AudioRenderGetRenderPosition;
    hwRender->common.SetRenderSpeed = AudioRenderSetRenderSpeed;
    hwRender->common.GetRenderSpeed = AudioRenderGetRenderSpeed;
    hwRender->common.SetChannelMode = AudioRenderSetChannelMode;
    hwRender->common.GetChannelMode = AudioRenderGetChannelMode;
    hwRender->common.RegCallback = AudioRenderRegCallback;
    hwRender->common.DrainBuffer = AudioRenderDrainBuffer;
    hwRender->renderParam.frameRenderMode.callbackProcess = CallbackProcessing;
    return HDF_SUCCESS;
}

int32_t CheckParaDesc(const struct AudioDeviceDescriptor *desc, const char *type)
{
    if (desc == NULL || type == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }

    if ((desc->portId) >> SHIFT_RIGHT_31_BITS) {
        AUDIO_FUNC_LOGE("portId error!");
        return HDF_ERR_NOT_SUPPORT;
    }

    enum AudioPortPin pins = desc->pins;
    if (!strcmp(type, TYPE_CAPTURE)) {
        if (pins == PIN_IN_MIC || pins == PIN_IN_HS_MIC || pins == PIN_IN_LINEIN) {
            return HDF_SUCCESS;
        }
    } else if (!strcmp(type, TYPE_RENDER)) {
        if (pins == PIN_OUT_SPEAKER || pins == PIN_OUT_HEADSET || pins == PIN_OUT_LINEOUT || pins == PIN_OUT_HDMI
            || pins == (PIN_OUT_SPEAKER | PIN_OUT_HEADSET)) {
            return HDF_SUCCESS;
        }
    }
    AUDIO_FUNC_LOGE("Unknow pin!");

    return HDF_ERR_NOT_SUPPORT;
}

int32_t CheckParaAttr(const struct AudioSampleAttributes *attrs)
{
    if (attrs == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = ((attrs->sampleRate) >> SHIFT_RIGHT_31_BITS) + ((attrs->channelCount) >> SHIFT_RIGHT_31_BITS) +
        ((attrs->period) >> SHIFT_RIGHT_31_BITS) + ((attrs->frameSize) >> SHIFT_RIGHT_31_BITS) +
        ((attrs->startThreshold) >> SHIFT_RIGHT_31_BITS) + ((attrs->stopThreshold) >> SHIFT_RIGHT_31_BITS) +
        ((attrs->silenceThreshold) >> SHIFT_RIGHT_31_BITS);
    if (ret > 0) {
        AUDIO_FUNC_LOGE("Sample attributes error!");
        return HDF_ERR_NOT_SUPPORT;
    }

    enum AudioCategory audioCategory = attrs->type;
    if (audioCategory < AUDIO_IN_MEDIA || audioCategory > AUDIO_MMAP_NOIRQ) {
        AUDIO_FUNC_LOGE("Audio category error!");
        return HDF_ERR_NOT_SUPPORT;
    }

    enum AudioFormat audioFormat = attrs->format;
    return CheckAttrFormat(audioFormat);
}

int32_t AttrFormatToBit(const struct AudioSampleAttributes *attrs, int32_t *format)
{
    if (attrs == NULL || format == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }

    enum AudioFormat audioFormat = attrs->format;
    switch (audioFormat) {
        case AUDIO_FORMAT_TYPE_PCM_8_BIT:
            *format = BIT_NUM_8;
            break;
        case AUDIO_FORMAT_TYPE_PCM_16_BIT:
            *format = BIT_NUM_16;
            break;
        case AUDIO_FORMAT_TYPE_PCM_24_BIT:
            *format = BIT_NUM_24;
            break;
        case AUDIO_FORMAT_TYPE_PCM_32_BIT:
            *format = BIT_NUM_32;
            break;
        default:
            AUDIO_FUNC_LOGE("Audio format error!");
            return HDF_ERR_NOT_SUPPORT;
    }

    return HDF_SUCCESS;
}

static int32_t AudioFormatServiceName(char *cardServiceName, char *adapterName, uint32_t id)
{
    if (cardServiceName == NULL || adapterName == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }

    if (snprintf_s(cardServiceName, NAME_LEN, NAME_LEN - 1, "%s%u", adapterName, id) < 0) {
        AUDIO_FUNC_LOGE("snprintf_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioCheckDescPortId(
    const struct AudioAdapterDescriptor *adapterDescriptor, uint32_t portId, uint32_t *id)
{
    if (adapterDescriptor == NULL || adapterDescriptor->ports == NULL || id == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }

    int adapterNum = AudioAdapterGetAdapterNum();
    if (adapterNum <= 0) {
        AUDIO_FUNC_LOGE("Get adapterNum fail!");
        return HDF_FAILURE;
    }
    struct AudioAdapterDescriptor *descs = AudioAdapterGetConfigDescs();
    if (descs == NULL) {
        AUDIO_FUNC_LOGE("Get adapterDescs is NULL!");
        return HDF_FAILURE;
    }
    bool checkFlag = false;
    for (int index = 0; index < adapterNum; index++) {
        if (strcmp(descs[index].adapterName, adapterDescriptor->adapterName) == 0) {
            if (descs[index].ports[0].portId == portId) {
                checkFlag = true;
                break;
            } else {
                AUDIO_FUNC_LOGE("The Audio Port ID is invalid, please check!");
                return HDF_FAILURE;
            }
        }
    }
    if (!checkFlag) {
        AUDIO_FUNC_LOGE("The Audio AdapterName is illegal, please check!");
        return HDF_FAILURE;
    }
    for (int index = 0; index < adapterNum; index++) {
        if (strncmp(descs[index].adapterName, PRIMARY, strlen(PRIMARY)) == 0) {
            if (descs[index].ports[0].portId <= AUDIO_PRIMARY_ID_MAX &&
                descs[index].ports[0].portId >= AUDIO_PRIMARY_ID_MIN) {
                *id = descs[index].ports[0].portId;
                break;
            }
        }
    }

    return HDF_SUCCESS;
}

static int32_t AudioMakeCardServiceName(
    char *cardServiceName, const struct AudioAdapterDescriptor *adapterDescriptor, uint32_t portId)
{
    uint32_t priPortId = 0;

    if (cardServiceName == NULL || adapterDescriptor == NULL || adapterDescriptor->ports == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = AudioCheckDescPortId(adapterDescriptor, portId, &priPortId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("The Audio Port ID is illegal, please check!");
        return HDF_FAILURE;
    }
    if (strncmp(adapterDescriptor->adapterName, PRIMARY, strlen(PRIMARY)) == 0) {
        ret = AudioFormatServiceName(cardServiceName, HDF_AUDIO_CODEC_PRIMARY_DEV, portId);
    } else if (strncmp(adapterDescriptor->adapterName, HDMI, strlen(HDMI)) == 0) {
        ret = AudioFormatServiceName(cardServiceName, HDF_AUDIO_CODEC_HDMI_DEV, priPortId);
    } else if (strncmp(adapterDescriptor->adapterName, USB, strlen(USB)) == 0) {
        ret = AudioFormatServiceName(cardServiceName, HDF_AUDIO_CODEC_USB_DEV, priPortId);
    } else if (strncmp(adapterDescriptor->adapterName, A2DP, strlen(A2DP)) == 0) {
        ret = AudioFormatServiceName(cardServiceName, HDF_AUDIO_CODEC_A2DP_DEV, portId);
    } else {
        AUDIO_FUNC_LOGE("The selected sound card is not in the range of sound card list, please check!");
        return HDF_FAILURE;
    }

    return ret;
}

int32_t InitHwRenderParam(
    struct AudioHwRender *hwRender, const struct AudioDeviceDescriptor *desc, const struct AudioSampleAttributes *attrs)
{
    if (hwRender == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = CheckParaDesc(desc, TYPE_RENDER);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CheckParaDesc Fail");
        return ret;
    }
    ret = CheckParaAttr(attrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CheckParaAttr Fail");
        return ret;
    }
    int32_t formatValue = -1;
    ret = AttrFormatToBit(attrs, &formatValue);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AttrFormatToBit Fail");
        return ret;
    }
    if (attrs->channelCount == 0) {
        AUDIO_FUNC_LOGE("channelCount is zero!");
        return HDF_FAILURE;
    }
    hwRender->renderParam.renderMode.hwInfo.deviceDescript = *desc;
    hwRender->renderParam.renderMode.hwInfo.callBackEnable = false;
    hwRender->renderParam.frameRenderMode.attrs = *attrs;
    hwRender->renderParam.renderMode.ctlParam.audioGain.gainMax = GAIN_MAX; // init gainMax
    hwRender->renderParam.renderMode.ctlParam.audioGain.gainMin = 0;
    hwRender->renderParam.frameRenderMode.frames = 0;
    hwRender->renderParam.frameRenderMode.time.tvNSec = 0;
    hwRender->renderParam.frameRenderMode.time.tvSec = 0;
    hwRender->renderParam.frameRenderMode.byteRate = DEFAULT_RENDER_SAMPLING_RATE;
    hwRender->renderParam.frameRenderMode.periodSize = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    hwRender->renderParam.frameRenderMode.periodCount = DEEP_BUFFER_RENDER_PERIOD_COUNT;
    hwRender->renderParam.frameRenderMode.renderhandle = (AudioHandle)hwRender;
    pthread_mutex_init(&hwRender->renderParam.frameRenderMode.mutex, NULL);
    hwRender->renderParam.renderMode.ctlParam.turnStandbyStatus = AUDIO_TURN_STANDBY_LATER;
    return HDF_SUCCESS;
}

int32_t InitForGetPortCapability(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex)
{
    if (capabilityIndex == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_ERR_INVALID_PARAM;
    }

    /* get capabilityIndex from driver or default */
    if (portIndex.dir != PORT_OUT) {
        capabilityIndex->hardwareMode = true;
        capabilityIndex->channelMasks = AUDIO_CHANNEL_STEREO;
        capabilityIndex->channelCount = CONFIG_CHANNEL_COUNT;
        return HDF_SUCCESS;
    }

    if (InitPortForCapabilitySub(portIndex, capabilityIndex) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("PortInitForCapability fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void AudioAdapterReleaseCapSubPorts(const struct AudioPortAndCapability *portCapabilitys, int32_t num)
{
    int32_t i = 0;

    if (portCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return;
    }

    while (i < num) {
        if (&portCapabilitys[i] == NULL) {
            break;
        }
        AudioMemFree((void **)(&portCapabilitys[i].capability.subPorts));
        i++;
    }
}

int32_t AudioAdapterInitAllPorts(struct IAudioAdapter *adapter)
{
    AUDIO_FUNC_LOGD("Enter.");
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter Is NULL");
        return AUDIO_ERR_INVALID_PARAM;
    }
    if (hwAdapter->portCapabilitys != NULL) {
        AUDIO_FUNC_LOGI("portCapabilitys already Init!");
        return AUDIO_SUCCESS;
    }
    uint32_t portsLen = hwAdapter->adapterDescriptor.portsLen;
    struct AudioPort *ports = hwAdapter->adapterDescriptor.ports;
    if (ports == NULL) {
        AUDIO_FUNC_LOGE("ports is NULL!");
        return AUDIO_ERR_INTERNAL;
    }
    if (portsLen == 0) {
        AUDIO_FUNC_LOGE("portsLen is 0!");
        return AUDIO_ERR_INTERNAL;
    }
    struct AudioPortAndCapability *portCapability =
        (struct AudioPortAndCapability *)OsalMemCalloc(portsLen * sizeof(struct AudioPortAndCapability));
    if (portCapability == NULL) {
        AUDIO_FUNC_LOGE("portCapability is NULL!");
        return AUDIO_ERR_INTERNAL;
    }
    for (uint32_t i = 0; i < portsLen; i++) {
        portCapability[i].port = ports[i];
        if (InitForGetPortCapability(ports[i], &portCapability[i].capability)) {
            AUDIO_FUNC_LOGE("ports Init Fail!");
            AudioAdapterReleaseCapSubPorts(portCapability, portsLen);
            AudioMemFree((void **)&portCapability);
            return AUDIO_ERR_INTERNAL;
        }
    }
    hwAdapter->portCapabilitys = portCapability;
    hwAdapter->portCapabilitys->mode = PORT_PASSTHROUGH_LPCM;
    return AUDIO_SUCCESS;
}

void AudioReleaseRenderHandle(struct AudioHwRender *hwRender)
{
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return;
    }
    CloseServiceRenderPassthrough *pCloseRenderService = AudioPassthroughGetCloseServiceRender();
    if (pCloseRenderService == NULL || (*pCloseRenderService) == NULL) {
        AUDIO_FUNC_LOGE("pCloseRenderService func not exist");
        return;
    }
    if (hwRender->devDataHandle != NULL) {
        (*pCloseRenderService)(hwRender->devDataHandle);
        hwRender->devDataHandle = NULL;
    }
    if (hwRender->devCtlHandle != NULL) {
        (*pCloseRenderService)(hwRender->devCtlHandle);
        hwRender->devCtlHandle = NULL;
    }
}

int32_t AudioAdapterCreateRenderPre(struct AudioHwRender *hwRender, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, const struct AudioHwAdapter *hwAdapter)
{
    if (hwAdapter == NULL || hwRender == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    PathSelAnalysisJson *pPathSelAnalysisJson = AudioPassthroughGetPathSelAnalysisJson();
    if (pPathSelAnalysisJson == NULL || *pPathSelAnalysisJson == NULL) {
        AUDIO_FUNC_LOGE("PathSelAnalysisJson not exist");
        return HDF_FAILURE;
    }
#endif
    if (AudioHwRenderInit(hwRender) < 0) {
        AUDIO_FUNC_LOGE("AudioHwRenderInit error!");
        return HDF_FAILURE;
    }
    /* Fill hwRender para */
    if (InitHwRenderParam(hwRender, desc, attrs) < 0) {
        AUDIO_FUNC_LOGE("InitHwRenderParam error!");
        return HDF_FAILURE;
    }

    if (hwAdapter->adapterDescriptor.adapterName == NULL) {
        AUDIO_FUNC_LOGE("pointer is null!");
        return HDF_FAILURE;
    }
    uint32_t adapterNameLen = strlen(hwAdapter->adapterDescriptor.adapterName);
    if (adapterNameLen == 0) {
        AUDIO_FUNC_LOGE("adapterNameLen is null!");
        return HDF_FAILURE;
    }
    /* Get Adapter name */
    int32_t ret = strncpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName, NAME_LEN - 1,
        hwAdapter->adapterDescriptor.adapterName, adapterNameLen);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("copy fail");
        return HDF_FAILURE;
    }
    uint32_t portId = hwRender->renderParam.renderMode.hwInfo.deviceDescript.portId;
    ret = AudioMakeCardServiceName(
        hwRender->renderParam.renderMode.hwInfo.cardServiceName, &hwAdapter->adapterDescriptor, portId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioMakeCardServiceName fail");
        return HDF_FAILURE;
    }

    /* Select Path */
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    if ((*pPathSelAnalysisJson)((void *)&hwRender->renderParam, RENDER_PATH_SELECT) < 0) {
        AUDIO_FUNC_LOGE("Path Select Fail!");
        return HDF_FAILURE;
    }
#endif
    return HDF_SUCCESS;
}

static int32_t BindServiceRenderOpen(struct AudioHwRender *hwRender,
    InterfaceLibModeRenderPassthrough *pInterfaceLibModeRender)
{
    if (hwRender == NULL || hwRender->devDataHandle == NULL || pInterfaceLibModeRender == NULL ||
        *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    int32_t ret =
        (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("IAudioRender render open FAIL");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtrlRenderClose(struct AudioHwRender *hwRender, InterfaceLibModeRenderPassthrough *pInterfaceLibModeRender)
{
    if (hwRender == NULL || hwRender->devDataHandle == NULL || pInterfaceLibModeRender == NULL ||
        *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    int32_t ret =
        (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Audio render close fail, ret is %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioAdapterBindServiceRender(struct AudioHwRender *hwRender)
{
    int32_t ret;
    if (hwRender == NULL || hwRender->devDataHandle == NULL || hwRender->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    InterfaceLibModeRenderPassthrough *pInterfaceLibModeRender = AudioPassthroughGetInterfaceLibModeRender();
    if (pInterfaceLibModeRender == NULL || *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("InterfaceLibModeRender not exist");
        return HDF_FAILURE;
    }
    if (BindServiceRenderOpen(hwRender, pInterfaceLibModeRender) != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    /* Init RenderPathSelect send first */
    /* Internel Indicates the path selection for the sound card */
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    uint32_t portId = hwRender->renderParam.renderMode.hwInfo.deviceDescript.portId;
    if (portId < AUDIO_USB_ID_MIN) {
        ret = (*pInterfaceLibModeRender)(
            hwRender->devCtlHandle, &hwRender->renderParam, AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("SetParams FAIL!");
            (void)AudioCtrlRenderClose(hwRender, pInterfaceLibModeRender);
            return HDF_FAILURE;
        }
    }
#endif
    /* set Attr Para */
    ret = (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam, AUDIO_DRV_PCM_IOCTL_HW_PARAMS);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("IAudioRender SetParams FAIL");
        (void)AudioCtrlRenderClose(hwRender, pInterfaceLibModeRender);
        return HDF_FAILURE;
    }

    /* get volThreshold */
    ret = (*pInterfaceLibModeRender)(
        hwRender->devCtlHandle, &hwRender->renderParam, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetParams FAIL!");
        (void)AudioCtrlRenderClose(hwRender, pInterfaceLibModeRender);
        return HDF_FAILURE;
    }

    ret = (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam, AUDIO_DRV_PCM_IOCTL_PREPARE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("IAudioRender perpare FAIL");
        (void)AudioCtrlRenderClose(hwRender, pInterfaceLibModeRender);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioRenderBindService(struct AudioHwRender *hwRender, BindServiceRenderPassthrough *pBindServiceRender)
{
    if (hwRender == NULL || pBindServiceRender == NULL || *pBindServiceRender == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    /* bindRenderService */
    hwRender->devDataHandle = (*pBindServiceRender)(RENDER_CMD);
    if (hwRender->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("Render bind service failed");
        return AUDIO_ERR_INTERNAL;
    }

    hwRender->devCtlHandle = (*pBindServiceRender)(CTRL_CMD);
    if (hwRender->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("Render bind service failed");
        return AUDIO_ERR_INTERNAL;
    }

    int32_t ret = AudioAdapterBindServiceRender(hwRender);
    if (ret != HDF_SUCCESS) {
        return AUDIO_ERR_INTERNAL;
    }
    return AUDIO_SUCCESS;
}

static uint32_t GetAvailableRenderID(struct AudioHwAdapter *hwAdapter)
{
    uint32_t renderId = MAX_AUDIO_STREAM_NUM;
    uint32_t index = 0;
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return renderId;
    }

    if (hwAdapter->infos.renderCnt < MAX_AUDIO_STREAM_NUM) {
        renderId = hwAdapter->infos.renderCnt;
        hwAdapter->infos.renderCnt++;
    } else {
        for (index = 0; index < MAX_AUDIO_STREAM_NUM; index++) {
            if (hwAdapter->infos.renderServicePtr[index] == NULL) {
                renderId = index;
                break;
            }
        }
    }

    return renderId;
}

int32_t AudioAdapterCreateRender(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct IAudioRender **render, uint32_t *renderId)
{
    AUDIO_FUNC_LOGD("Enter.");
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || desc == NULL || attrs == NULL || render == NULL || renderId == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    BindServiceRenderPassthrough *pBindServiceRender = AudioPassthroughGetBindServiceRender();
    if (pBindServiceRender == NULL || *pBindServiceRender == NULL) {
        AUDIO_FUNC_LOGE("lib render func not exist");
        return AUDIO_ERR_INTERNAL;
    }

    struct AudioHwRender *hwRender = (struct AudioHwRender *)OsalMemCalloc(sizeof(*hwRender));
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("hwRender is NULL!");
        return AUDIO_ERR_MALLOC_FAIL;
    }

    int32_t ret = AudioAdapterCreateRenderPre(hwRender, desc, attrs, hwAdapter);
    if (ret != HDF_SUCCESS) {
        AudioMemFree((void **)&hwRender);
        return AUDIO_ERR_INTERNAL;
    }

    ret = AudioRenderBindService(hwRender, pBindServiceRender);
    if (ret != AUDIO_SUCCESS) {
        AudioReleaseRenderHandle(hwRender);
        AudioMemFree((void **)&hwRender);
        return ret;
    }

    *renderId = GetAvailableRenderID(hwAdapter);
    if (*renderId == MAX_AUDIO_STREAM_NUM) {
        AUDIO_FUNC_LOGE("there is no available renderId");
        AudioReleaseRenderHandle(hwRender);
        AudioMemFree((void **)&hwRender);
        return HDF_FAILURE;
    }
    hwAdapter->infos.renderServicePtr[*renderId] = hwRender;

    *render = &hwRender->common;
    return AUDIO_SUCCESS;
}

int32_t AudioAdapterDestroyRender(struct IAudioAdapter *adapter, uint32_t renderId)
{
    AUDIO_FUNC_LOGD("Enter.");
    int32_t ret = 0;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || renderId >= MAX_AUDIO_STREAM_NUM) {
        AUDIO_FUNC_LOGE("Invalid input param!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    struct IAudioRender *render = (struct IAudioRender *)hwAdapter->infos.renderServicePtr[renderId];
    StubCollectorRemoveObject(IAUDIORENDER_INTERFACE_DESC, render);

    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("hwRender is NULL!");
        return AUDIO_ERR_INTERNAL;
    }
    pthread_mutex_lock(&hwRender->renderParam.frameRenderMode.mutex);
    if (hwRender->renderParam.frameRenderMode.buffer != NULL) {
        ret = render->Stop((AudioHandle)render);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("render Stop failed");
        }
    }

    InterfaceLibModeRenderPassthrough *pInterfaceLibModeRender = AudioPassthroughGetInterfaceLibModeRender();
    if (pInterfaceLibModeRender == NULL || *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("InterfaceLibModeRender not exist");
        pthread_mutex_unlock(&hwRender->renderParam.frameRenderMode.mutex);
        return HDF_FAILURE;
    }
    ret =
        (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam, AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Audio RENDER_CLOSE FAIL");
    }
    AudioReleaseRenderHandle(hwRender);
    AudioMemFree((void **)&hwRender->renderParam.frameRenderMode.buffer);
    pthread_mutex_unlock(&hwRender->renderParam.frameRenderMode.mutex);
    pthread_mutex_destroy(&hwRender->renderParam.frameRenderMode.mutex);
    for (int i = 0; i < ERROR_LOG_MAX_NUM; i++) {
        AudioMemFree((void **)&hwRender->errorLog.errorDump[i].reason);
        AudioMemFree((void **)&hwRender->errorLog.errorDump[i].currentTime);
    }
    for (int i = 0; i < HDF_PATH_NUM_MAX; i++) {
        AudioMemFree((void **)&hwRender->renderParam.renderMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[i].value);
    }
    AudioMemFree((void **)&render);
    hwAdapter->infos.renderServicePtr[renderId] = NULL;
    return AUDIO_SUCCESS;
}

static int32_t AudioHwCaptureInit(struct AudioHwCapture *hwCapture)
{
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }
    hwCapture->common.Start = AudioCaptureStart;
    hwCapture->common.Stop = AudioCaptureStop;
    hwCapture->common.Pause = AudioCapturePause;
    hwCapture->common.Resume = AudioCaptureResume;
    hwCapture->common.Flush = AudioCaptureFlush;
    hwCapture->common.TurnStandbyMode = AudioCaptureTurnStandbyMode;
    hwCapture->common.AudioDevDump = AudioCaptureAudioDevDump;
    hwCapture->common.GetFrameSize = AudioCaptureGetFrameSize;
    hwCapture->common.GetFrameCount = AudioCaptureGetFrameCount;
    hwCapture->common.SetSampleAttributes = AudioCaptureSetSampleAttributes;
    hwCapture->common.GetSampleAttributes = AudioCaptureGetSampleAttributes;
    hwCapture->common.GetCurrentChannelId = AudioCaptureGetCurrentChannelId;
    hwCapture->common.SetExtraParams = AudioCaptureSetExtraParams;
    hwCapture->common.GetExtraParams = AudioCaptureGetExtraParams;
    hwCapture->common.ReqMmapBuffer = AudioCaptureReqMmapBuffer;
    hwCapture->common.GetMmapPosition = AudioCaptureGetMmapPosition;
    hwCapture->common.CheckSceneCapability = AudioCaptureCheckSceneCapability;
    hwCapture->common.SelectScene = AudioCaptureSelectScene;
    hwCapture->common.SetMute = AudioCaptureSetMute;
    hwCapture->common.GetMute = AudioCaptureGetMute;
    hwCapture->common.SetVolume = AudioCaptureSetVolume;
    hwCapture->common.GetVolume = AudioCaptureGetVolume;
    hwCapture->common.GetGainThreshold = AudioCaptureGetGainThreshold;
    hwCapture->common.GetGain = AudioCaptureGetGain;
    hwCapture->common.SetGain = AudioCaptureSetGain;
    hwCapture->common.CaptureFrame = AudioCaptureCaptureFrame;
    hwCapture->common.GetCapturePosition = AudioCaptureGetCapturePosition;
    return HDF_SUCCESS;
}

int32_t InitHwCaptureParam(struct AudioHwCapture *hwCapture, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs)
{
    if (hwCapture == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }
    int32_t ret = CheckParaDesc(desc, TYPE_CAPTURE);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    ret = CheckParaAttr(attrs);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    int32_t formatValue = -1;
    ret = AttrFormatToBit(attrs, &formatValue);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    if (attrs->channelCount == 0) {
        AUDIO_FUNC_LOGE("channelCount is zero!");
        return HDF_FAILURE;
    }
    hwCapture->captureParam.captureMode.hwInfo.deviceDescript = *desc;
    hwCapture->captureParam.frameCaptureMode.attrs = *attrs;
    hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMax = GAIN_MAX; // init gainMax
    hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMin = 0;
    hwCapture->captureParam.frameCaptureMode.frames = 0;
    hwCapture->captureParam.frameCaptureMode.time.tvNSec = 0;
    hwCapture->captureParam.frameCaptureMode.time.tvSec = 0;
    hwCapture->captureParam.frameCaptureMode.byteRate = DEFAULT_RENDER_SAMPLING_RATE;
    hwCapture->captureParam.frameCaptureMode.periodSize = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    hwCapture->captureParam.frameCaptureMode.periodCount = DEEP_BUFFER_RENDER_PERIOD_COUNT;
    hwCapture->captureParam.frameCaptureMode.attrs.period = attrs->period;
    hwCapture->captureParam.frameCaptureMode.attrs.frameSize = attrs->frameSize;
    hwCapture->captureParam.frameCaptureMode.attrs.startThreshold = attrs->startThreshold;
    hwCapture->captureParam.frameCaptureMode.attrs.stopThreshold = attrs->stopThreshold;
    hwCapture->captureParam.frameCaptureMode.attrs.silenceThreshold = attrs->silenceThreshold;
    hwCapture->captureParam.frameCaptureMode.attrs.isBigEndian = attrs->isBigEndian;
    hwCapture->captureParam.frameCaptureMode.attrs.isSignedData = attrs->isSignedData;
    return HDF_SUCCESS;
}

void AudioReleaseCaptureHandle(struct AudioHwCapture *hwCapture)
{
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return;
    }

    CloseServiceCapturePassthrough *pCloseCaptureService = AudioPassthroughGetCloseServiceCapture();
    if (pCloseCaptureService == NULL || (*pCloseCaptureService) == NULL) {
        AUDIO_FUNC_LOGE("pCloseCaptureService func not exist");
        return;
    }
    if (hwCapture->devDataHandle != NULL) {
        (*pCloseCaptureService)(hwCapture->devDataHandle);
        hwCapture->devDataHandle = NULL;
    }
    if (hwCapture->devCtlHandle != NULL) {
        (*pCloseCaptureService)(hwCapture->devCtlHandle);
        hwCapture->devCtlHandle = NULL;
    }
}

int32_t AudioAdapterCreateCapturePre(struct AudioHwCapture *hwCapture, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct AudioHwAdapter *hwAdapter)
{
    if (hwCapture == NULL || desc == NULL || attrs == NULL || hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    PathSelAnalysisJson *pPathSelAnalysisJson = AudioPassthroughGetPathSelAnalysisJson();
    if (pPathSelAnalysisJson == NULL || *pPathSelAnalysisJson == NULL) {
        AUDIO_FUNC_LOGE("PathSelAnalysisJson not exist");
        return HDF_FAILURE;
    }
#endif
    if (AudioHwCaptureInit(hwCapture) < 0) {
        return HDF_FAILURE;
    }
    if (InitHwCaptureParam(hwCapture, desc, attrs) < 0) {
        AUDIO_FUNC_LOGE("InitHwCaptureParam error!");
        return HDF_FAILURE;
    }

    if (hwAdapter->adapterDescriptor.adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is NULL!");
        return HDF_FAILURE;
    }
    uint32_t adapterNameLen = strlen(hwAdapter->adapterDescriptor.adapterName);
    if (adapterNameLen == 0) {
        AUDIO_FUNC_LOGE("adapterNameLen is zero!");
        return HDF_FAILURE;
    }
    int32_t ret = strncpy_s(hwCapture->captureParam.captureMode.hwInfo.adapterName, NAME_LEN - 1,
        hwAdapter->adapterDescriptor.adapterName, adapterNameLen);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("Copy adapterName is failed!");
        return HDF_FAILURE;
    }
    uint32_t portId = hwCapture->captureParam.captureMode.hwInfo.deviceDescript.portId;
    ret = AudioMakeCardServiceName(
        hwCapture->captureParam.captureMode.hwInfo.cardServiceName, &hwAdapter->adapterDescriptor, portId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioMakeCardServiceName fail");
        return HDF_FAILURE;
    }

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    if ((*pPathSelAnalysisJson)((void *)&hwCapture->captureParam, CAPTURE_PATH_SELECT) < 0) {
        AUDIO_FUNC_LOGE("Path Select Fail!");
        return HDF_FAILURE;
    }
#endif

    return HDF_SUCCESS;
}

static int32_t AudioCtrlCaptureClose(struct AudioHwCapture *hwCapture,
    InterfaceLibModeCapturePassthrough *pInterfaceLibModeCapture)
{
    if (hwCapture == NULL || hwCapture->devDataHandle == NULL || pInterfaceLibModeCapture == NULL ||
        *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    int32_t ret = (*pInterfaceLibModeCapture)(
        hwCapture->devDataHandle, &hwCapture->captureParam, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Audio capture close fail, ret is %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioAdapterInterfaceLibModeCapture(struct AudioHwCapture *hwCapture)
{
    if (hwCapture == NULL || hwCapture->devCtlHandle == NULL || hwCapture->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return HDF_FAILURE;
    }

    InterfaceLibModeCapturePassthrough *pInterfaceLibModeCapture = AudioPassthroughGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("lib capture func not exist");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(
        hwCapture->devDataHandle, &hwCapture->captureParam, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CAPTURE_OPEN FAIL");
        return HDF_FAILURE;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    ret = (*pInterfaceLibModeCapture)(
        hwCapture->devCtlHandle, &hwCapture->captureParam, AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetParams FAIL!");
        (void)AudioCtrlCaptureClose(hwCapture, pInterfaceLibModeCapture);
        return HDF_FAILURE;
    }
#endif
    ret =
        (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam, AUDIO_DRV_PCM_IOCTL_HW_PARAMS);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureStart SetParams FAIL");
        (void)AudioCtrlCaptureClose(hwCapture, pInterfaceLibModeCapture);
        return HDF_FAILURE;
    }
    ret = (*pInterfaceLibModeCapture)(
        hwCapture->devCtlHandle, &hwCapture->captureParam, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetParams FAIL!");
        (void)AudioCtrlCaptureClose(hwCapture, pInterfaceLibModeCapture);
        return HDF_FAILURE;
    }
    ret = (*pInterfaceLibModeCapture)(
        hwCapture->devDataHandle, &hwCapture->captureParam, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureStart prepare FAIL");
        (void)AudioCtrlCaptureClose(hwCapture, pInterfaceLibModeCapture);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureBindService(struct AudioHwCapture *hwCapture, BindServiceCapturePassthrough *pBindServiceCapture)
{
    if (hwCapture == NULL || pBindServiceCapture == NULL || *pBindServiceCapture == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    hwCapture->devDataHandle = (*pBindServiceCapture)(CAPTURE_CMD);
    if (hwCapture->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("Capture bind service failed");
        return AUDIO_ERR_INTERNAL;
    }
    hwCapture->devCtlHandle = (*pBindServiceCapture)(CTRL_CMD);
    if (hwCapture->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("Capture bind service failed");
        return AUDIO_ERR_INTERNAL;
    }
    int32_t ret = AudioAdapterInterfaceLibModeCapture(hwCapture);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("AudioAdapterInterfaceLibModeCapture failed");
        return AUDIO_ERR_INTERNAL;
    }
    return AUDIO_SUCCESS;
}

static uint32_t GetAvailableCaptureID(struct AudioHwAdapter *hwAdapter)
{
    uint32_t captureId = MAX_AUDIO_STREAM_NUM;
    uint32_t index = 0;
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return captureId;
    }

    if (hwAdapter->infos.captureCnt < MAX_AUDIO_STREAM_NUM) {
        captureId = hwAdapter->infos.captureCnt;
        hwAdapter->infos.captureCnt++;
    } else {
        for (index = 0; index < MAX_AUDIO_STREAM_NUM; index++) {
            if (hwAdapter->infos.captureServicePtr[index] == NULL) {
                captureId = index;
                break;
            }
        }
    }

    return captureId;
}

int32_t AudioAdapterCreateCapture(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct IAudioCapture **capture, uint32_t *captureId)
{
    AUDIO_FUNC_LOGD("Enter.");
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || desc == NULL || attrs == NULL || capture == NULL || captureId == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    BindServiceCapturePassthrough *pBindServiceCapture = AudioPassthroughGetBindServiceCapture();
    if (pBindServiceCapture == NULL || *pBindServiceCapture == NULL) {
        AUDIO_FUNC_LOGE("lib capture func not exist");
        return AUDIO_ERR_INTERNAL;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)OsalMemCalloc(sizeof(*hwCapture));
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("calloc AudioHwCapture failed!");
        return AUDIO_ERR_MALLOC_FAIL;
    }
    int32_t ret = AudioAdapterCreateCapturePre(hwCapture, desc, attrs, hwAdapter);
    if (ret != AUDIO_SUCCESS) {
        AUDIO_FUNC_LOGE("call AudioAdapterCreateCapturePre failed %{public}d", ret);
        AudioMemFree((void **)&hwCapture);
        return AUDIO_ERR_INTERNAL;
    }
    ret = AudioCaptureBindService(hwCapture, pBindServiceCapture);
    if (ret < 0) {
        AudioReleaseCaptureHandle(hwCapture);
        AudioMemFree((void **)&hwCapture);
        return ret;
    }

    *captureId = GetAvailableCaptureID(hwAdapter);
    if (*captureId == MAX_AUDIO_STREAM_NUM) {
        AUDIO_FUNC_LOGE("there is no available captureId");
        AudioReleaseCaptureHandle(hwCapture);
        AudioMemFree((void **)&hwCapture);
        return HDF_FAILURE;
    }
    hwAdapter->infos.captureServicePtr[*captureId] = hwCapture;

    *capture = &hwCapture->common;
    return AUDIO_SUCCESS;
}

int32_t AudioAdapterDestroyCapture(struct IAudioAdapter *adapter, uint32_t captureId)
{
    AUDIO_FUNC_LOGD("Enter.");
    int32_t ret = 0;
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || captureId >= MAX_AUDIO_STREAM_NUM) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }
    struct IAudioCapture *capture = (struct IAudioCapture *)hwAdapter->infos.captureServicePtr[captureId];

    StubCollectorRemoveObject(IAUDIOCAPTURE_INTERFACE_DESC, capture);

    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture is NULL!");
        return AUDIO_ERR_INTERNAL;
    }
    if (hwCapture->captureParam.frameCaptureMode.buffer != NULL) {
        ret = capture->Stop((AudioHandle)capture);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("capture Stop failed");
        }
    }
    InterfaceLibModeCapturePassthrough *pInterfaceLibModeCapture = AudioPassthroughGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("lib capture func not exist");
        return HDF_FAILURE;
    }
    ret = (*pInterfaceLibModeCapture)(
        hwCapture->devDataHandle, &hwCapture->captureParam, AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CAPTURE_CLOSE FAIL");
    }
    AudioReleaseCaptureHandle(hwCapture);
    AudioMemFree((void **)&hwCapture->captureParam.frameCaptureMode.buffer);
    for (int i = 0; i < ERROR_LOG_MAX_NUM; i++) {
        AudioMemFree((void **)&hwCapture->errorLog.errorDump[i].reason);
        AudioMemFree((void **)&hwCapture->errorLog.errorDump[i].currentTime);
    }
    for (int i = 0; i < HDF_PATH_NUM_MAX; i++) {
        AudioMemFree((void **)&hwCapture->captureParam.captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[i].value);
    }
    AudioMemFree((void **)&capture);
    hwAdapter->infos.captureServicePtr[captureId] = NULL;
    return AUDIO_SUCCESS;
}

static void AudioSubPortCapabilityDestroy(struct AudioSubPortCapability *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (dataBlock->desc != NULL) {
        OsalMemFree(dataBlock->desc);
        dataBlock->desc = NULL;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

static void AudioPortCapabilityDeepFree(struct AudioPortCapability *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (dataBlock->formats != NULL) {
        OsalMemFree(dataBlock->formats);
        dataBlock->formats = NULL;
    }

    if (dataBlock->subPorts != NULL) {
        for (uint32_t i = 0; i < dataBlock->subPortsLen; i++) {
            AudioSubPortCapabilityDestroy(&dataBlock->subPorts[i], false);
        }
        OsalMemFree(dataBlock->subPorts);
        dataBlock->subPorts = NULL;
    }

    if (dataBlock->supportSampleFormats != NULL) {
        OsalMemFree(dataBlock->supportSampleFormats);
        dataBlock->supportSampleFormats = NULL;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

static int32_t AudioDeepCopySubCapability(
    struct AudioSubPortCapability **dstSubPortsOut, struct AudioSubPortCapability *srcSubPorts, uint32_t subPortsLen)
{
    struct AudioSubPortCapability *dstSubPorts = NULL;

    if (dstSubPortsOut == NULL || srcSubPorts == NULL || subPortsLen == 0) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }
    dstSubPorts = (struct AudioSubPortCapability *)OsalMemCalloc(subPortsLen * sizeof(struct AudioSubPortCapability));
    if (dstSubPorts == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc fail");
        return AUDIO_ERR_MALLOC_FAIL;
    }
    *dstSubPortsOut = dstSubPorts;
    for (uint32_t i = 0; i < subPortsLen; i++) {
        dstSubPorts[i] = srcSubPorts[i];
        if (srcSubPorts[i].desc != NULL) {
            dstSubPorts[i].desc = (char *)OsalMemCalloc(strlen(srcSubPorts[i].desc) + 1);
            if (dstSubPorts[i].desc == NULL) {
                AUDIO_FUNC_LOGE("OsalMemCalloc fail");
                return AUDIO_ERR_MALLOC_FAIL;
            }
            int32_t ret = memcpy_s(
                dstSubPorts[i].desc, strlen(srcSubPorts[i].desc), srcSubPorts[i].desc, strlen(srcSubPorts[i].desc));
            if (ret != EOK) {
                AUDIO_FUNC_LOGE("memcpy_s fail");
                return AUDIO_ERR_INTERNAL;
            }
        }
    }
    return AUDIO_SUCCESS;
}

static int32_t AudioDeepCopyCapability(struct AudioPortCapability *destCap, struct AudioPortCapability *sourceCap)
{
    if (destCap == NULL || sourceCap == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }

    *destCap = *sourceCap;
    destCap->formats = NULL;
    destCap->supportSampleFormats = NULL;
    destCap->subPorts = NULL;

    if (sourceCap->formats != NULL) {
        destCap->formats = (enum AudioFormat *)OsalMemCalloc(sizeof(enum AudioFormat));
        if (destCap->formats == NULL) {
            AUDIO_FUNC_LOGE("OsalMemCalloc fail");
            return AUDIO_ERR_MALLOC_FAIL;
        }
        *destCap->formats = *sourceCap->formats;
    }
    if (sourceCap->supportSampleFormats != NULL) {
        destCap->supportSampleFormats = (enum AudioSampleFormat *)OsalMemCalloc(sizeof(enum AudioSampleFormat));
        if (destCap->supportSampleFormats == NULL) {
            AUDIO_FUNC_LOGE("OsalMemCalloc fail");
            AudioPortCapabilityDeepFree(destCap, false);
            return AUDIO_ERR_MALLOC_FAIL;
        }
        *destCap->supportSampleFormats = *sourceCap->supportSampleFormats;
    }
    int32_t ret = AudioDeepCopySubCapability(&(destCap->subPorts), sourceCap->subPorts, sourceCap->subPortsLen);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioDeepCopySubCapability copy fail");
        AudioPortCapabilityDeepFree(destCap, false);
        return AUDIO_ERR_MALLOC_FAIL;
    }
    return AUDIO_SUCCESS;
}

int32_t AudioAdapterGetPortCapability(
    struct IAudioAdapter *adapter, const struct AudioPort *port, struct AudioPortCapability *capability)
{
    AUDIO_FUNC_LOGD("Enter.");
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || port == NULL || port->portName == NULL || capability == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }
    struct AudioPortAndCapability *hwAdapterPortCapabilitys = hwAdapter->portCapabilitys;
    if (hwAdapterPortCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter portCapabilitys is NULL!");
        return AUDIO_ERR_INTERNAL;
    }
    uint32_t portsLen = hwAdapter->adapterDescriptor.portsLen;
    while (hwAdapterPortCapabilitys != NULL && portsLen > 0) {
        if (hwAdapterPortCapabilitys->port.portId == port->portId) {
            if (AudioDeepCopyCapability(capability, &hwAdapterPortCapabilitys->capability) < 0) {
                return AUDIO_ERR_INTERNAL;
            }
            return AUDIO_SUCCESS;
        }
        hwAdapterPortCapabilitys++;
        portsLen--;
    }
    return AUDIO_ERR_INTERNAL;
}

int32_t AudioAdapterSetPassthroughMode(
    struct IAudioAdapter *adapter, const struct AudioPort *port, enum AudioPortPassthroughMode mode)
{
    AUDIO_FUNC_LOGD("Enter.");
    if (adapter == NULL || port == NULL || port->portName == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }
    if (port->dir != PORT_OUT || port->portId < 0 || strcmp(port->portName, "AOP") != 0) {
        AUDIO_FUNC_LOGE("Port error!");
        return AUDIO_ERR_INTERNAL;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->portCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null!");
        return AUDIO_ERR_INTERNAL;
    }
    struct AudioPortAndCapability *portCapabilityTemp = hwAdapter->portCapabilitys;
    struct AudioPortCapability *portCapability = NULL;
    uint32_t portsLen = hwAdapter->adapterDescriptor.portsLen;
    while (portCapabilityTemp != NULL && portsLen > 0) {
        if (portCapabilityTemp->port.portId == port->portId) {
            portCapability = &portCapabilityTemp->capability;
            break;
        }
        portCapabilityTemp++;
        portsLen--;
    }
    if (portCapability == NULL || portsLen == 0) {
        AUDIO_FUNC_LOGE("hwAdapter portCapabilitys is Not Find!");
        return AUDIO_ERR_INTERNAL;
    }
    struct AudioSubPortCapability *subPortCapability = portCapability->subPorts;
    if (subPortCapability == NULL) {
        AUDIO_FUNC_LOGE("portCapability->subPorts is NULL!");
        return AUDIO_ERR_INTERNAL;
    }
    uint32_t subportsLen = portCapability->subPortsLen;
    while (subPortCapability != NULL && subportsLen > 0) {
        if (subPortCapability->mask == mode) {
            portCapabilityTemp->mode = mode;
            break;
        }
        subPortCapability++;
        subportsLen--;
    }
    if (subportsLen == 0) {
        AUDIO_FUNC_LOGE("subPortCapability's Temp mode is not find!");
        return AUDIO_ERR_INTERNAL;
    }
    return AUDIO_SUCCESS;
}

int32_t AudioAdapterGetPassthroughMode(
    struct IAudioAdapter *adapter, const struct AudioPort *port, enum AudioPortPassthroughMode *mode)
{
    AUDIO_FUNC_LOGD("Enter.");
    if (adapter == NULL || port == NULL || port->portName == NULL || mode == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return AUDIO_ERR_INVALID_PARAM;
    }
    if (port->dir != PORT_OUT || port->portId < 0 || strcmp(port->portName, "AOP") != 0) {
        AUDIO_FUNC_LOGE("Port error!");
        return AUDIO_ERR_INTERNAL;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->portCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("portCapabilitys pointer is null!");
        return AUDIO_ERR_INTERNAL;
    }
    struct AudioPortAndCapability *portCapabilitys = hwAdapter->portCapabilitys;
    uint32_t portsLen = hwAdapter->adapterDescriptor.portsLen;
    while (portCapabilitys != NULL && portsLen > 0) {
        if (portCapabilitys->port.portId == port->portId) {
            *mode = portCapabilitys->mode;
            return AUDIO_SUCCESS;
        }
        portCapabilitys++;
        portsLen--;
    }
    return AUDIO_ERR_INTERNAL;
}
int32_t AudioAdapterGetDeviceStatus(struct IAudioAdapter *adapter, struct AudioDeviceStatus *status)
{
    AUDIO_FUNC_LOGD("Enter.");
    (void)adapter;
    (void)status;
    return AUDIO_SUCCESS;
}
void AudioAdapterRelease(struct IAudioAdapter *instance)
{
    (void)instance;
}
