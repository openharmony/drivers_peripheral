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

#include "audio_adapter.h"
#include "osal_mem.h"
#include "audio_adapter_info_common.h"
#include "audio_uhdf_log.h"
#include "audio_interface_lib_capture.h"
#include "audio_interface_lib_render.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_IMPL

#define CONFIG_CHANNEL_COUNT  2 // two channels
#define GAIN_MAX 50.0
#define DEFAULT_RENDER_SAMPLING_RATE 48000
#define DEEP_BUFFER_RENDER_PERIOD_SIZE 4096
#define DEEP_BUFFER_RENDER_PERIOD_COUNT 8
#define TYPE_RENDER "Render"
#define TYPE_CAPTURE "Capture"
#define INT_32_MAX 0x7fffffff
#define SHIFT_RIGHT_31_BITS 31

int32_t GetAudioRenderFunc(struct AudioHwRender *hwRender)
{
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("param hwRender is null!");
        return HDF_FAILURE;
    }
    hwRender->common.control.Start = AudioRenderStart;
    hwRender->common.control.Stop = AudioRenderStop;
    hwRender->common.control.Pause = AudioRenderPause;
    hwRender->common.control.Resume = AudioRenderResume;
    hwRender->common.control.Flush = AudioRenderFlush;
    hwRender->common.control.TurnStandbyMode = AudioRenderTurnStandbyMode;
    hwRender->common.control.AudioDevDump = AudioRenderAudioDevDump;
    hwRender->common.attr.GetFrameSize = AudioRenderGetFrameSize;
    hwRender->common.attr.GetFrameCount = AudioRenderGetFrameCount;
    hwRender->common.attr.SetSampleAttributes = AudioRenderSetSampleAttributes;
    hwRender->common.attr.GetSampleAttributes = AudioRenderGetSampleAttributes;
    hwRender->common.attr.GetCurrentChannelId = AudioRenderGetCurrentChannelId;
    hwRender->common.attr.SetExtraParams = AudioRenderSetExtraParams;
    hwRender->common.attr.GetExtraParams = AudioRenderGetExtraParams;
    hwRender->common.attr.ReqMmapBuffer = AudioRenderReqMmapBuffer;
    hwRender->common.attr.GetMmapPosition = AudioRenderGetMmapPosition;
    hwRender->common.attr.AddAudioEffect = AudioRenderAddEffect;
    hwRender->common.attr.RemoveAudioEffect = AudioRenderRemoveEffect;
    hwRender->common.scene.CheckSceneCapability = AudioRenderCheckSceneCapability;
    hwRender->common.scene.SelectScene = AudioRenderSelectScene;
    hwRender->common.volume.SetMute = AudioRenderSetMute;
    hwRender->common.volume.GetMute = AudioRenderGetMute;
    hwRender->common.volume.SetVolume = AudioRenderSetVolume;
    hwRender->common.volume.GetVolume = AudioRenderGetVolume;
    hwRender->common.volume.GetGainThreshold = AudioRenderGetGainThreshold;
    hwRender->common.volume.GetGain = AudioRenderGetGain;
    hwRender->common.volume.SetGain = AudioRenderSetGain;
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
        AUDIO_FUNC_LOGE("param desc or type is null!");
        return HDF_FAILURE;
    }
    if ((desc->portId) >> SHIFT_RIGHT_31_BITS) {
        AUDIO_FUNC_LOGE("The highest bit of portId:%{public}u is not a valid value!", desc->portId);
        return HDF_ERR_NOT_SUPPORT;
    }
    enum AudioPortPin pins = desc->pins;
    if (!strcmp(type, TYPE_CAPTURE)) {
        if (pins == PIN_IN_MIC || pins == PIN_IN_HS_MIC || pins == PIN_IN_LINEIN) {
            return HDF_SUCCESS;
        } else {
            AUDIO_FUNC_LOGE("TYPE_CAPTURE does not support this pins:%{public}d!", pins);
            return HDF_ERR_NOT_SUPPORT;
        }
    } else if (!strcmp(type, TYPE_RENDER)) {
        if (pins == PIN_OUT_SPEAKER || pins == PIN_OUT_HEADSET || pins == PIN_OUT_LINEOUT || pins == PIN_OUT_HDMI) {
            return HDF_SUCCESS;
        } else {
            AUDIO_FUNC_LOGE("TYPE_RENDER does not support this pins:%{public}d!", pins);
            return HDF_ERR_NOT_SUPPORT;
        }
    }
    AUDIO_FUNC_LOGE("This Type:%{public}s not support!", type);
    return HDF_ERR_NOT_SUPPORT;
}

int32_t CheckParaAttr(const struct AudioSampleAttributes *attrs)
{
    if (attrs == NULL) {
        AUDIO_FUNC_LOGE("param attrs is null!");
        return HDF_FAILURE;
    }
    int32_t ret = ((attrs->sampleRate) >> SHIFT_RIGHT_31_BITS) + ((attrs->channelCount) >> SHIFT_RIGHT_31_BITS) +
        ((attrs->period) >> SHIFT_RIGHT_31_BITS) + ((attrs->frameSize) >> SHIFT_RIGHT_31_BITS) +
        ((attrs->startThreshold) >> SHIFT_RIGHT_31_BITS) + ((attrs->stopThreshold) >> SHIFT_RIGHT_31_BITS) +
        ((attrs->silenceThreshold) >> SHIFT_RIGHT_31_BITS);
    if (ret > 0) {
        AUDIO_FUNC_LOGE("CheckParaAttr does not support! ret = %{public}d", ret);
        return HDF_ERR_NOT_SUPPORT;
    }
    enum AudioCategory audioCategory = attrs->type;
    if (audioCategory != AUDIO_IN_MEDIA && audioCategory != AUDIO_IN_COMMUNICATION) {
        AUDIO_FUNC_LOGE("audioCategory:%{public}d is neither AUDIO_IN_MEDIA not or AUDIO_IN_COMMUNICATION",
            audioCategory);
        return HDF_ERR_NOT_SUPPORT;
    }
    enum AudioFormat audioFormat = attrs->format;
    return CheckAttrFormat(audioFormat);
}

int32_t AttrFormatToBit(const struct AudioSampleAttributes *attrs, int32_t *format)
{
    if (attrs == NULL || format == NULL) {
        AUDIO_FUNC_LOGE("param attrs or format is null!");
        return HDF_FAILURE;
    }
    enum AudioFormat audioFormat = attrs->format;
    switch (audioFormat) {
        case AUDIO_FORMAT_PCM_8_BIT:
            *format = BIT_NUM_8;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_16_BIT:
            *format = BIT_NUM_16;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_24_BIT:
            *format = BIT_NUM_24;
            return HDF_SUCCESS;
        case AUDIO_FORMAT_PCM_32_BIT:
            *format = BIT_NUM_32;
            return HDF_SUCCESS;
        default:
            return HDF_ERR_NOT_SUPPORT;
    }
}

static int32_t AudioFormatServiceName(char *cardServiceName, char *adapterName, uint32_t id)
{
    if (cardServiceName == NULL || adapterName == NULL) {
        AUDIO_FUNC_LOGE("Pointer Is Empty!");
        return HDF_FAILURE;
    }

    if (snprintf_s(cardServiceName, NAME_LEN, NAME_LEN - 1, "%s%u", adapterName, id) < 0) {
        AUDIO_FUNC_LOGE("snprintf_s failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioCheckDescPortId(const struct AudioAdapterDescriptor *adapterDescriptor, uint32_t portId,
    uint32_t *id)
{
    if (adapterDescriptor == NULL || adapterDescriptor->ports == NULL || id == NULL) {
        AUDIO_FUNC_LOGE("Pointer Is Empty!");
        return HDF_FAILURE;
    }
    int adapterNum = AudioAdapterGetAdapterNum();
    if (adapterNum <= 0) {
        AUDIO_FUNC_LOGE("Get adapterNum fail!");
        return HDF_FAILURE;
    }
    struct AudioAdapterDescriptor *descs = AudioAdapterGetConfigOut();
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

static int32_t AudioMakeCardServiceName(char *cardServiceName, const struct AudioAdapterDescriptor *adapterDescriptor,
    uint32_t portId)
{
    if (cardServiceName == NULL || adapterDescriptor == NULL || adapterDescriptor->ports == NULL) {
        AUDIO_FUNC_LOGE("Pointer Is Empty!");
        return HDF_FAILURE;
    }
    uint32_t priPortId = 0;
    int32_t ret;
    ret = AudioCheckDescPortId(adapterDescriptor, portId, &priPortId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("The Audio Port ID is illegal, please check!");
        return HDF_FAILURE;
    }
    if (strncmp(adapterDescriptor->adapterName, PRIMARY, strlen(PRIMARY)) == 0) {
        ret = AudioFormatServiceName(cardServiceName, HDF_AUDIO_CODEC_PRIMARY_DEV, portId);
    } else if (strncmp(adapterDescriptor->adapterName, USB, strlen(USB)) == 0) {
        ret = AudioFormatServiceName(cardServiceName, HDF_AUDIO_CODEC_PRIMARY_DEV, priPortId);
    } else if (strncmp(adapterDescriptor->adapterName, A2DP, strlen(A2DP)) == 0) {
        ret = AudioFormatServiceName(cardServiceName, HDF_AUDIO_CODEC_A2DP_DEV, portId);
    } else {
        AUDIO_FUNC_LOGE("The selected sound card is not in the range of sound card list, please check!");
        return HDF_FAILURE;
    }
    return ret;
}

int32_t InitHwRenderParam(struct AudioHwRender *hwRender, const struct AudioDeviceDescriptor *desc,
                          const struct AudioSampleAttributes *attrs)
{
    if (hwRender == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("InitHwRenderParam param Is NULL");
        return HDF_FAILURE;
    }
    int32_t ret = CheckParaDesc(desc, TYPE_RENDER);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CheckParaDesc Fail ret = %{public}d", ret);
        return ret;
    }
    ret = CheckParaAttr(attrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CheckParaAttr Fail ret = %{public}d", ret);
        return ret;
    }
    int32_t formatValue = -1;
    ret = AttrFormatToBit(attrs, &formatValue);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AttrFormatToBit Fail ret = %{public}d", ret);
        return ret;
    }
    if (attrs->channelCount == 0) {
        AUDIO_FUNC_LOGE("attrs->channelCount is zero!");
        return HDF_FAILURE;
    }
    hwRender->renderParam.renderMode.hwInfo.deviceDescript = *desc;
    hwRender->renderParam.renderMode.hwInfo.callBackEnable = false;
    hwRender->renderParam.frameRenderMode.attrs = *attrs;
    hwRender->renderParam.renderMode.ctlParam.audioGain.gainMax = GAIN_MAX;  // init gainMax
    hwRender->renderParam.renderMode.ctlParam.audioGain.gainMin = 0;
    hwRender->renderParam.renderMode.ctlParam.stop = true;
    hwRender->renderParam.frameRenderMode.frames = 0;
    hwRender->renderParam.frameRenderMode.time.tvNSec = 0;
    hwRender->renderParam.frameRenderMode.time.tvSec = 0;
    hwRender->renderParam.frameRenderMode.byteRate = DEFAULT_RENDER_SAMPLING_RATE;
    hwRender->renderParam.frameRenderMode.periodSize = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    hwRender->renderParam.frameRenderMode.periodCount = DEEP_BUFFER_RENDER_PERIOD_COUNT;
    hwRender->renderParam.frameRenderMode.renderhandle = (AudioHandle)hwRender;
    if ((hwRender->renderParam.frameRenderMode.buffer = (char *)OsalMemCalloc(FRAME_DATA)) == NULL) {
        AUDIO_FUNC_LOGE("alloc frame render buffer failed");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    hwRender->renderParam.renderMode.ctlParam.turnStandbyStatus = AUDIO_TURN_STANDBY_LATER;
    return HDF_SUCCESS;
}

int32_t InitForGetPortCapability(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex)
{
    if (capabilityIndex == NULL) {
        AUDIO_FUNC_LOGE("capabilityIndex is null");
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
        AUDIO_FUNC_LOGE("PortInitForCapability fail");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void AudioAdapterReleaseCapSubPorts(const struct AudioPortAndCapability *portCapabilitys, int32_t num)
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

int32_t AudioAdapterInitAllPorts(struct AudioAdapter *adapter)
{
    int32_t ret = AudioCheckAdapterAddr((AudioHandle)adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid");
        return ret;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter Is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwAdapter->portCapabilitys != NULL) {
        AUDIO_FUNC_LOGI("portCapabilitys already Init!");
        return AUDIO_HAL_SUCCESS;
    }
    uint32_t portNum = hwAdapter->adapterDescriptor.portNum;
    struct AudioPort *ports = hwAdapter->adapterDescriptor.ports;
    if (ports == NULL) {
        AUDIO_FUNC_LOGE("ports is NULL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (portNum == 0) {
        AUDIO_FUNC_LOGE("portNum is zero!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioPortAndCapability *portCapability = (struct AudioPortAndCapability *)OsalMemCalloc(
        portNum * sizeof(struct AudioPortAndCapability));
    if (portCapability == NULL) {
        AUDIO_FUNC_LOGE("portCapability is NULL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    for (uint32_t i = 0; i < portNum; i++) {
        portCapability[i].port = ports[i];
        if (InitForGetPortCapability(ports[i], &portCapability[i].capability)) {
            AUDIO_FUNC_LOGE("ports Init Fail!");
            AudioAdapterReleaseCapSubPorts(portCapability, portNum);
            AudioMemFree((void **)&portCapability);
            return AUDIO_HAL_ERR_INTERNAL;
        }
    }
    hwAdapter->portCapabilitys = portCapability;
    hwAdapter->portCapabilitys->mode = PORT_PASSTHROUGH_LPCM;
    return AUDIO_HAL_SUCCESS;
}

void AudioReleaseRenderHandle(struct AudioHwRender *hwRender)
{
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("param hwRender is null!");
        return;
    }
    CloseServiceRenderSo *pCloseServiceRender = AudioSoGetCloseServiceRender();
    if (pCloseServiceRender == NULL || (*pCloseServiceRender) == NULL) {
        AUDIO_FUNC_LOGE("pCloseServiceRender func not exist");
        return;
    }
    if (hwRender->devDataHandle != NULL) {
        (*pCloseServiceRender)(hwRender->devDataHandle);
        hwRender->devDataHandle = NULL;
    }
    if (hwRender->devCtlHandle != NULL) {
        (*pCloseServiceRender)(hwRender->devCtlHandle);
        hwRender->devCtlHandle = NULL;
    }
    return;
}

int32_t AudioAdapterCreateRenderPre(struct AudioHwRender *hwRender, const struct AudioDeviceDescriptor *desc,
                                    const struct AudioSampleAttributes *attrs, const struct AudioHwAdapter *hwAdapter)
{
    if (hwAdapter == NULL || hwRender == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("Pointer is null!");
        return HDF_FAILURE;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    PathSelAnalysisJson *pPathSelAnalysisJson = AudioSoGetPathSelAnalysisJson();
    if (pPathSelAnalysisJson == NULL || *pPathSelAnalysisJson == NULL) {
        AUDIO_FUNC_LOGE("PathSelAnalysisJson not exist");
        return HDF_FAILURE;
    }
#endif
    if (GetAudioRenderFunc(hwRender) < 0) {
        AUDIO_FUNC_LOGE("GetAudioRenderFunc failed!");
        return HDF_FAILURE;
    }
    /* Fill hwRender para */
    if (InitHwRenderParam(hwRender, desc, attrs) < 0) {
        AUDIO_FUNC_LOGE("InitHwRenderParam failed!");
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
    int32_t ret = strncpy_s(hwRender->renderParam.renderMode.hwInfo.adapterName, NAME_LEN,
                            hwAdapter->adapterDescriptor.adapterName, adapterNameLen);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("copy fail");
        return HDF_FAILURE;
    }
    uint32_t portId = hwRender->renderParam.renderMode.hwInfo.deviceDescript.portId;
    ret = AudioMakeCardServiceName(hwRender->renderParam.renderMode.hwInfo.cardServiceName,
                                   &hwAdapter->adapterDescriptor, portId);
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
    InterfaceLibModeRenderSo *pInterfaceLibModeRender)
{
    if (hwRender == NULL || hwRender->devDataHandle == NULL ||
        pInterfaceLibModeRender == NULL || *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("Input para is null!");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeRender)(hwRender->devDataHandle,
        &hwRender->renderParam, AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioRender render open FAIL");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioCtrlRenderClose(struct AudioHwRender *hwRender, InterfaceLibModeRenderSo *pInterfaceLibModeRender)
{
    if (hwRender == NULL || hwRender->devDataHandle == NULL ||
        pInterfaceLibModeRender == NULL || *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("Audio render handle param not exist");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam,
                                             AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Audio render close fail, ret is %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioSetParamToDev(struct AudioHwRender *hwRender, InterfaceLibModeRenderSo *pInterfaceLibModeRender)
{
    int32_t ret;
    if (hwRender == NULL || hwRender->devDataHandle == NULL || hwRender->devCtlHandle == NULL ||
        pInterfaceLibModeRender == NULL || *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("The parameter is empty.");
        return HDF_FAILURE;
    }
    /* Init RenderPathSelect send first */
    /* portId small than  AUDIO_SERVICE_PORTID_FLAG should SceneSelect */
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    uint32_t portId = hwRender->renderParam.renderMode.hwInfo.deviceDescript.portId;
    if (portId < AUDIO_USB_ID_MIN) {
        ret = (*pInterfaceLibModeRender)(hwRender->devCtlHandle, &hwRender->renderParam,
            AUDIODRV_CTL_IOCTL_SCENESELECT_WRITE);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("SetParams FAIL!");
            return HDF_FAILURE;
        }
    }
#endif
    /* set Attr Para */
    ret = (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam, AUDIO_DRV_PCM_IOCTL_HW_PARAMS);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioRender SetParams FAIL");
        return HDF_FAILURE;
    }
    /* get volThreshold */
    ret = (*pInterfaceLibModeRender)(hwRender->devCtlHandle, &hwRender->renderParam,
        AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_READ);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetParams FAIL!");
        return HDF_FAILURE;
    }
    ret = (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam, AUDIO_DRV_PCM_IOCTL_PREPARE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioRender perpare FAIL");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioAdapterBindServiceRender(struct AudioHwRender *hwRender)
{
    int32_t ret;
    if (hwRender == NULL || hwRender->devDataHandle == NULL || hwRender->devCtlHandle == NULL) {
        return HDF_FAILURE;
    }
    InterfaceLibModeRenderSo *pInterfaceLibModeRender = AudioSoGetInterfaceLibModeRender();
    if (pInterfaceLibModeRender == NULL || *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("InterfaceLibModeRender not exist");
        return HDF_FAILURE;
    }
    if (BindServiceRenderOpen(hwRender, pInterfaceLibModeRender)) {
        return HDF_FAILURE;
    }
    ret = AudioSetParamToDev(hwRender, pInterfaceLibModeRender);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioSetParamToDev FAIL.");
        (void)AudioCtrlRenderClose(hwRender, pInterfaceLibModeRender);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t AudioRenderBindService(struct AudioHwRender *hwRender, BindServiceRenderSo *pBindServiceRender)
{
    if (hwRender == NULL || pBindServiceRender == NULL || *pBindServiceRender == NULL) {
        AUDIO_FUNC_LOGE("hwRender or pBindServiceRender or *pBindServiceRender is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    /* bindRenderService */
    hwRender->devDataHandle = (*pBindServiceRender)(RENDER_CMD);
    if (hwRender->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("Render bind service failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    hwRender->devCtlHandle = (*pBindServiceRender)(CTRL_CMD);
    if (hwRender->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("Render bind service failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAdapterBindServiceRender(hwRender);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("AudioAdapterBindServiceRender fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

static void AudioCreateRenderRelease(struct AudioHwRender **hwRender)
{
    if (hwRender != NULL && *hwRender != NULL) {
        AudioMemFree((void **)&((*hwRender)->renderParam.frameRenderMode.buffer));
    }
    AudioMemFree((void **)hwRender);
    return;
}

int32_t AudioAdapterCreateRender(struct AudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
                                 const struct AudioSampleAttributes *attrs, struct AudioRender **render)
{
    int32_t ret = AudioCheckAdapterAddr((AudioHandle)adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid");
        return ret;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || desc == NULL || attrs == NULL || render == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter or desc or attrs or render is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwAdapter->adapterMgrRenderFlag > 0) {
        AUDIO_FUNC_LOGE("Create render repeatedly!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    BindServiceRenderSo *pBindServiceRender = AudioSoGetBindServiceRender();
    if (pBindServiceRender == NULL || *pBindServiceRender == NULL) {
        AUDIO_FUNC_LOGE("lib render func not exist");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioHwRender *hwRender = (struct AudioHwRender *)OsalMemCalloc(sizeof(*hwRender));
    if (hwRender == NULL) {
        AUDIO_FUNC_LOGE("hwRender is NULL!");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    ret = AudioAdapterCreateRenderPre(hwRender, desc, attrs, hwAdapter);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("AudioAdapterCreateRenderPre fail");
        AudioCreateRenderRelease(&hwRender);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioRenderBindService(hwRender, pBindServiceRender);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioRenderBindService fail ret = %{public}d", ret);
        AudioReleaseRenderHandle(hwRender);
        AudioCreateRenderRelease(&hwRender);
        return ret;
    }
    /* add for Fuzz */
    ret = AudioAddRenderAddrToList((AudioHandle)(&hwRender->common));
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The render address get is invalid ret = %{public}d", ret);
        AudioReleaseRenderHandle(hwRender);
        AudioCreateRenderRelease(&hwRender);
        return ret;
    }
    *render = &hwRender->common;
    hwAdapter->adapterMgrRenderFlag++;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioAdapterDestroyRender(struct AudioAdapter *adapter, struct AudioRender *render)
{
    int32_t ret = AudioCheckAdapterAddr((AudioHandle)adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid");
        return ret;
    }
    ret = AudioCheckRenderAddr((AudioHandle)render);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The render address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || render == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter or render is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwAdapter->adapterMgrRenderFlag > 0) {
        hwAdapter->adapterMgrRenderFlag--;
    }
    struct AudioHwRender *hwRender = (struct AudioHwRender *)render;
    if (!(hwRender->renderParam.renderMode.ctlParam.stop)) {
        ret = render->control.Stop((AudioHandle)render);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("render Stop failed ret = %{public}d", ret);
        }
    }
    InterfaceLibModeRenderSo *pInterfaceLibModeRender = AudioSoGetInterfaceLibModeRender();
    if (pInterfaceLibModeRender == NULL || *pInterfaceLibModeRender == NULL) {
        AUDIO_FUNC_LOGE("InterfaceLibModeRender not exist");
        return HDF_FAILURE;
    }
    ret = (*pInterfaceLibModeRender)(hwRender->devDataHandle, &hwRender->renderParam,
                                     AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Audio RENDER_CLOSE FAIL");
    }
    if (AudioDelRenderAddrFromList((AudioHandle)render)) {
        AUDIO_FUNC_LOGE("adapter or render not in MgrList");
    }
    AudioReleaseRenderHandle(hwRender);
    AudioMemFree((void **)&hwRender->renderParam.frameRenderMode.buffer);
    for (int i = 0; i < ERROR_LOG_MAX_NUM; i++) {
        AudioMemFree((void **)&hwRender->errorLog.errorDump[i].reason);
        AudioMemFree((void **)&hwRender->errorLog.errorDump[i].currentTime);
    }
    AudioMemFree((void **)&render);
    return AUDIO_HAL_SUCCESS;
}

int32_t GetAudioCaptureFunc(struct AudioHwCapture *hwCapture)
{
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("param hwCapture is null!");
        return HDF_FAILURE;
    }
    hwCapture->common.control.Start = AudioCaptureStart;
    hwCapture->common.control.Stop = AudioCaptureStop;
    hwCapture->common.control.Pause = AudioCapturePause;
    hwCapture->common.control.Resume = AudioCaptureResume;
    hwCapture->common.control.Flush = AudioCaptureFlush;
    hwCapture->common.control.TurnStandbyMode = AudioCaptureTurnStandbyMode;
    hwCapture->common.control.AudioDevDump = AudioCaptureAudioDevDump;
    hwCapture->common.attr.GetFrameSize = AudioCaptureGetFrameSize;
    hwCapture->common.attr.GetFrameCount = AudioCaptureGetFrameCount;
    hwCapture->common.attr.SetSampleAttributes = AudioCaptureSetSampleAttributes;
    hwCapture->common.attr.GetSampleAttributes = AudioCaptureGetSampleAttributes;
    hwCapture->common.attr.GetCurrentChannelId = AudioCaptureGetCurrentChannelId;
    hwCapture->common.attr.SetExtraParams = AudioCaptureSetExtraParams;
    hwCapture->common.attr.GetExtraParams = AudioCaptureGetExtraParams;
    hwCapture->common.attr.ReqMmapBuffer = AudioCaptureReqMmapBuffer;
    hwCapture->common.attr.GetMmapPosition = AudioCaptureGetMmapPosition;
    hwCapture->common.attr.AddAudioEffect = AudioCaptureAddEffect;
    hwCapture->common.attr.RemoveAudioEffect = AudioCaptureRemoveEffect;
    hwCapture->common.scene.CheckSceneCapability = AudioCaptureCheckSceneCapability;
    hwCapture->common.scene.SelectScene = AudioCaptureSelectScene;
    hwCapture->common.volume.SetMute = AudioCaptureSetMute;
    hwCapture->common.volume.GetMute = AudioCaptureGetMute;
    hwCapture->common.volume.SetVolume = AudioCaptureSetVolume;
    hwCapture->common.volume.GetVolume = AudioCaptureGetVolume;
    hwCapture->common.volume.GetGainThreshold = AudioCaptureGetGainThreshold;
    hwCapture->common.volume.GetGain = AudioCaptureGetGain;
    hwCapture->common.volume.SetGain = AudioCaptureSetGain;
    hwCapture->common.CaptureFrame = AudioCaptureCaptureFrame;
    hwCapture->common.GetCapturePosition = AudioCaptureGetCapturePosition;
    return HDF_SUCCESS;
}

int32_t InitHwCaptureParam(struct AudioHwCapture *hwCapture, const struct AudioDeviceDescriptor *desc,
                           const struct AudioSampleAttributes *attrs)
{
    if (hwCapture == NULL || desc == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("InitHwCaptureParam param Is NULL");
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
        AUDIO_FUNC_LOGE("attrs->channelCount is zero!");
        return HDF_FAILURE;
    }
    hwCapture->captureParam.captureMode.hwInfo.deviceDescript = *desc;
    hwCapture->captureParam.frameCaptureMode.attrs = *attrs;
    hwCapture->captureParam.captureMode.ctlParam.audioGain.gainMax = GAIN_MAX;  // init gainMax
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
        AUDIO_FUNC_LOGE("param hwCapture is null!");
        return;
    }
    CloseServiceCaptureSo *pCloseServiceCapture = AudioSoGetCloseServiceCapture();
    if (pCloseServiceCapture == NULL || (*pCloseServiceCapture) == NULL) {
        AUDIO_FUNC_LOGE("pCloseServiceCapture func not exist");
        return;
    }
    if (hwCapture->devDataHandle != NULL) {
        (*pCloseServiceCapture)(hwCapture->devDataHandle);
        hwCapture->devDataHandle = NULL;
    }
    if (hwCapture->devCtlHandle != NULL) {
        (*pCloseServiceCapture)(hwCapture->devCtlHandle);
        hwCapture->devCtlHandle = NULL;
    }
    return;
}

int32_t AudioAdapterCreateCapturePre(struct AudioHwCapture *hwCapture, const struct AudioDeviceDescriptor *desc,
                                     const struct AudioSampleAttributes *attrs, struct AudioHwAdapter *hwAdapter)
{
    if (hwCapture == NULL || desc == NULL || attrs == NULL || hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("Pointer Is Empty!");
        return HDF_FAILURE;
    }
#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    PathSelAnalysisJson *pPathSelAnalysisJson = AudioSoGetPathSelAnalysisJson();
    if (pPathSelAnalysisJson == NULL || *pPathSelAnalysisJson == NULL) {
        AUDIO_FUNC_LOGE("PathSelAnalysisJson not exist");
        return HDF_FAILURE;
    }
#endif
    if (GetAudioCaptureFunc(hwCapture) < 0) {
        AUDIO_FUNC_LOGE("GetAudioCaptureFunc failed!");
        return HDF_FAILURE;
    }
    if (InitHwCaptureParam(hwCapture, desc, attrs) < 0) {
        AUDIO_FUNC_LOGE("InitHwCaptureParam failed!");
        return HDF_FAILURE;
    }

    if (hwAdapter->adapterDescriptor.adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is NULL!");
        return HDF_FAILURE;
    }
    uint32_t adapterNameLen = strlen(hwAdapter->adapterDescriptor.adapterName);
    if (adapterNameLen == 0) {
        AUDIO_FUNC_LOGE("adapterNameLen is null!");
        return HDF_FAILURE;
    }
    /* Get Adapter name */
    int32_t ret = strncpy_s(hwCapture->captureParam.captureMode.hwInfo.adapterName, NAME_LEN,
                            hwAdapter->adapterDescriptor.adapterName, adapterNameLen);
    if (ret != EOK) {
        AUDIO_FUNC_LOGE("copy fail");
        return HDF_FAILURE;
    }
    uint32_t portId = hwCapture->captureParam.captureMode.hwInfo.deviceDescript.portId;
    ret = AudioMakeCardServiceName(hwCapture->captureParam.captureMode.hwInfo.cardServiceName,
                                   &hwAdapter->adapterDescriptor, portId);
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
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture)
{
    if (hwCapture == NULL || hwCapture->devDataHandle == NULL ||
        pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("Audio capture handle param not exist");
        return HDF_FAILURE;
    }
    int32_t ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                              AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Audio capture close fail, ret is %{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioAdapterInterfaceLibModeCapture(struct AudioHwCapture *hwCapture)
{
    if (hwCapture == NULL || hwCapture->devCtlHandle == NULL || hwCapture->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or hwCapture->devCtlHandle or hwCapture->devDataHandle is null!");
        return HDF_FAILURE;
    }
    InterfaceLibModeCaptureSo *libCap = AudioSoGetInterfaceLibModeCapture();
    if (libCap == NULL || *libCap == NULL) {
        AUDIO_FUNC_LOGE("lib capture func not exist");
        return HDF_FAILURE;
    }
    if ((*libCap)(hwCapture->devDataHandle, &hwCapture->captureParam, AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN) < 0) {
        AUDIO_FUNC_LOGE("CAPTURE_OPEN FAIL");
        return HDF_FAILURE;
    }

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
    if ((*libCap)(hwCapture->devCtlHandle, &hwCapture->captureParam, AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE) < 0) {
        AUDIO_FUNC_LOGE("SetParams FAIL!");
        (void)AudioCtrlCaptureClose(hwCapture, libCap);
        return HDF_FAILURE;
    }
#endif
    if ((*libCap)(hwCapture->devDataHandle, &hwCapture->captureParam, AUDIO_DRV_PCM_IOCTL_HW_PARAMS) < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureStart SetParams FAIL");
        (void)AudioCtrlCaptureClose(hwCapture, libCap);
        return HDF_FAILURE;
    }
    if ((*libCap)(hwCapture->devCtlHandle, &hwCapture->captureParam, AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE) < 0) {
        AUDIO_FUNC_LOGE("SetParams FAIL!");
        (void)AudioCtrlCaptureClose(hwCapture, libCap);
        return HDF_FAILURE;
    }
    if ((*libCap)(hwCapture->devDataHandle, &hwCapture->captureParam, AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE) < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureStart prepare FAIL");
        (void)AudioCtrlCaptureClose(hwCapture, libCap);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCaptureBindService(struct AudioHwCapture *hwCapture, BindServiceCaptureSo *pBindServiceCapture)
{
    if (hwCapture == NULL || pBindServiceCapture == NULL || *pBindServiceCapture == NULL) {
        AUDIO_FUNC_LOGE("hwCapture or pBindServiceCapture or *pBindServiceCapture is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    hwCapture->devDataHandle = (*pBindServiceCapture)(CAPTURE_CMD);
    if (hwCapture->devDataHandle == NULL) {
        AUDIO_FUNC_LOGE("Capture bind service failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    hwCapture->devCtlHandle = (*pBindServiceCapture)(CTRL_CMD);
    if (hwCapture->devCtlHandle == NULL) {
        AUDIO_FUNC_LOGE("Capture bind service failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAdapterInterfaceLibModeCapture(hwCapture);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("AudioAdapterInterfaceLibModeCapture failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioAdapterCreateCapture(struct AudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
                                  const struct AudioSampleAttributes *attrs, struct AudioCapture **capture)
{
    int32_t ret = AudioCheckAdapterAddr((AudioHandle)adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid");
        return ret;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || desc == NULL || attrs == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter or desc or attrs or capture is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwAdapter->adapterMgrCaptureFlag > 0) {
        AUDIO_FUNC_LOGE("Create capture repeatedly!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    BindServiceCaptureSo *pBindServiceCapture = AudioSoGetBindServiceCapture();
    if (pBindServiceCapture == NULL || *pBindServiceCapture == NULL) {
        AUDIO_FUNC_LOGE("lib capture func not exist");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)OsalMemCalloc(sizeof(*hwCapture));
    if (hwCapture == NULL) {
        AUDIO_FUNC_LOGE("alloc AudioHwCapture failed!");
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    ret = AudioAdapterCreateCapturePre(hwCapture, desc, attrs, hwAdapter);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("AudioAdapterCreateCapturePre fail");
        AudioMemFree((void **)&hwCapture);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioCaptureBindService(hwCapture, pBindServiceCapture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioCaptureBindService fail! ret = %{public}d", ret);
        AudioReleaseCaptureHandle(hwCapture);
        AudioMemFree((void **)&hwCapture);
        return ret;
    }
    ret = AudioAddCaptureAddrToList((AudioHandle)(&hwCapture->common));
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address get is invalid");
        AudioReleaseCaptureHandle(hwCapture);
        AudioMemFree((void **)&hwCapture);
        return ret;
    }
    *capture = &hwCapture->common;
    hwAdapter->adapterMgrCaptureFlag++;
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioAdapterDestroyCapture(struct AudioAdapter *adapter, struct AudioCapture *capture)
{
    int32_t ret = AudioCheckAdapterAddr((AudioHandle)adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid");
        return ret;
    }
    ret = AudioCheckCaptureAddr((AudioHandle)capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The capture address passed in is invalid! ret = %{public}d", ret);
        return ret;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter or capture is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (hwAdapter->adapterMgrCaptureFlag > 0) {
        hwAdapter->adapterMgrCaptureFlag--;
    }
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)capture;
    if (hwCapture->captureParam.frameCaptureMode.buffer != NULL) {
        ret = capture->control.Stop((AudioHandle)capture);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("capture Stop failed! ret = %{public}d", ret);
        }
    }
    InterfaceLibModeCaptureSo *pInterfaceLibModeCapture = AudioSoGetInterfaceLibModeCapture();
    if (pInterfaceLibModeCapture == NULL || *pInterfaceLibModeCapture == NULL) {
        AUDIO_FUNC_LOGE("lib capture func not exist");
        return HDF_FAILURE;
    }
    ret = (*pInterfaceLibModeCapture)(hwCapture->devDataHandle, &hwCapture->captureParam,
                                      AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CAPTURE_CLOSE FAIL");
    }
    if (AudioDelCaptureAddrFromList((AudioHandle)capture)) {
        AUDIO_FUNC_LOGE("adapter or capture not in MgrList");
    }
    AudioReleaseCaptureHandle(hwCapture);
    AudioMemFree((void **)&hwCapture->captureParam.frameCaptureMode.buffer);
    for (int i = 0; i < ERROR_LOG_MAX_NUM; i++) {
        AudioMemFree((void **)&hwCapture->errorLog.errorDump[i].reason);
        AudioMemFree((void **)&hwCapture->errorLog.errorDump[i].currentTime);
    }
    AudioMemFree((void **)&capture);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioAdapterGetPortCapability(struct AudioAdapter *adapter, const struct AudioPort *port,
                                      struct AudioPortCapability *capability)
{
    int32_t ret = AudioCheckAdapterAddr((AudioHandle)adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid");
        return ret;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter == NULL || port == NULL || port->portName == NULL || capability == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter or port or port->portName or capability is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioPortAndCapability *hwAdapterPortCapabilitys = hwAdapter->portCapabilitys;
    if (hwAdapterPortCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter portCapabilitys is NULL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    uint32_t portNum = hwAdapter->adapterDescriptor.portNum;
    while (hwAdapterPortCapabilitys != NULL && portNum) {
        if (hwAdapterPortCapabilitys->port.portId == port->portId) {
            *capability = hwAdapterPortCapabilitys->capability;
            return AUDIO_HAL_SUCCESS;
        }
        hwAdapterPortCapabilitys++;
        portNum--;
    }
    return AUDIO_HAL_ERR_INTERNAL;
}

int32_t AudioAdapterSetPassthroughModeExec(struct AudioHwAdapter *hwAdapter, uint32_t portId,
                                           enum AudioPortPassthroughMode mode)
{
    if (hwAdapter == NULL) {
        AUDIO_FUNC_LOGE("hwAdapter is null!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (hwAdapter->portCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("portCapabilitys is null!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioPortAndCapability *portCapabilityTemp = hwAdapter->portCapabilitys;
    struct AudioPortCapability *portCapability = NULL;
    uint32_t portNum = hwAdapter->adapterDescriptor.portNum;
    while (portCapabilityTemp != NULL && portNum > 0) {
        if (portCapabilityTemp->port.portId == portId) {
            portCapability = &portCapabilityTemp->capability;
            break;
        }
        portCapabilityTemp++;
        portNum--;
    }
    if (portCapability == NULL || portNum == 0) {
        AUDIO_FUNC_LOGE("hwAdapter portCapabilitys is Not Find!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioSubPortCapability *subPortCapability = portCapability->subPorts;
    if (subPortCapability == NULL) {
        AUDIO_FUNC_LOGE("portCapability->subPorts is NULL!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    uint32_t subPortNum = portCapability->subPortsNum;
    while (subPortCapability != NULL && subPortNum > 0) {
        if (subPortCapability->mask == mode) {
            portCapabilityTemp->mode = mode;
            break;
        }
        subPortCapability++;
        subPortNum--;
    }
    if (subPortNum > 0) {
        return AUDIO_HAL_SUCCESS;
    }
    return AUDIO_HAL_ERR_INTERNAL;
}

int32_t AudioAdapterSetPassthroughMode(struct AudioAdapter *adapter,
                                       const struct AudioPort *port, enum AudioPortPassthroughMode mode)
{
    int32_t ret = AudioCheckAdapterAddr(adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid");
        return ret;
    }
    if (adapter == NULL || port == NULL || port->portName == NULL) {
        AUDIO_FUNC_LOGE("adapter or format or port->portName is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (port->dir != PORT_OUT || port->portId < 0 || strcmp(port->portName, "AOP") != 0) {
        AUDIO_FUNC_LOGE("port->dir or port->portId or port->portName is invalid!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->portCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = AudioAdapterSetPassthroughModeExec(hwAdapter, port->portId, mode);
    return ret;
}

int32_t AudioAdapterGetPassthroughMode(struct AudioAdapter *adapter, const struct AudioPort *port,
                                       enum AudioPortPassthroughMode *mode)
{
    int32_t ret = AudioCheckAdapterAddr(adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The adapter address passed in is invalid");
        return ret;
    }
    if (adapter == NULL || port == NULL || port->portName == NULL || mode == NULL) {
        AUDIO_FUNC_LOGE("adapter or port or port->portName or mode is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (port->dir != PORT_OUT || port->portId < 0 || strcmp(port->portName, "AOP") != 0) {
        AUDIO_FUNC_LOGE("port->dir or port->portId or port->portName is invalid!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioHwAdapter *hwAdapter = (struct AudioHwAdapter *)adapter;
    if (hwAdapter->portCapabilitys == NULL) {
        AUDIO_FUNC_LOGE("portCapabilitys pointer is null!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    struct AudioPortAndCapability *portCapabilitys = hwAdapter->portCapabilitys;
    uint32_t portNum = hwAdapter->adapterDescriptor.portNum;
    while (portCapabilitys != NULL && portNum > 0) {
        if (portCapabilitys->port.portId == port->portId) {
            *mode = portCapabilitys->mode;
            return AUDIO_HAL_SUCCESS;
        }
        portCapabilitys++;
        portNum--;
    }
    return AUDIO_HAL_ERR_INTERNAL;
}

int32_t AudioAdapterSetMicMute(struct AudioAdapter *adapter, bool mute)
{
    (void)adapter;
    (void)mute;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioAdapterGetMicMute(struct AudioAdapter *adapter, bool *mute)
{
    (void)adapter;
    (void)mute;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioAdapterSetVoiceVolume(struct AudioAdapter *adapter, float volume)
{
    (void)adapter;
    (void)volume;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioAdapterUpdateAudioRoute(struct AudioAdapter *adapter, const struct AudioRoute *route, int32_t *routeHandle)
{
    if (route == NULL || routeHandle == NULL || route->sinks == NULL || route->sources == NULL) {
        AUDIO_FUNC_LOGE("some of the params in AudioAdapterUpdateAudioRoute null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    (void)adapter;
    (void)routeHandle;

    AUDIO_FUNC_LOGE("portId = %d", route->sinks[0].portId);
    AUDIO_FUNC_LOGE("sinks' device type = %d", route->sinks[0].ext.device.type);
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioAdapterReleaseAudioRoute(struct AudioAdapter *adapter, int32_t routeHandle)
{
    (void)adapter;
    (void)routeHandle;
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioAdapterSetExtraParams(struct AudioAdapter *adapter, enum AudioExtParamKey key,
                                   const char *condition, const char *value)
{
    (void)adapter;
    (void)key;
    (void)condition;
    (void)value;
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioAdapterGetExtraParams(struct AudioAdapter *adapter, enum AudioExtParamKey key,
                                   const char *condition, char *value, int32_t length)
{
    (void)adapter;
    (void)key;
    (void)condition;
    (void)value;
    (void)length;
    return HDF_ERR_NOT_SUPPORT;
}