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

#include "audio_interface_lib_capture.h"
#include <unistd.h>
#include "audio_common.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_LIB

/* virtual mixer device */
#define AUDIO_REPLY_EXTEND 64
#define AUDIO_SIZE_FRAME_16K (16 * 1024)
#define AUDIO_TRYNUM 2
#define AUDIO_US_TO_MS          1000
#define AUDIO_TRYNUM_TIME       ((AUDIO_US_TO_MS) * 3)
#define AUDIO_CAP_WAIT_DELAY    ((AUDIO_US_TO_MS) * 5)

/* Out Put Capture */
static struct AudioPcmHwParams g_hwParams;

int32_t SetHwParamsCapture(const struct AudioHwCaptureParam * const handleData)
{
    if (handleData == NULL) {
        AUDIO_FUNC_LOGE("handleData is NULL!");
        return HDF_FAILURE;
    }
    (void)memset_s(&g_hwParams, sizeof(struct AudioPcmHwParams), 0, sizeof(struct AudioPcmHwParams));
    g_hwParams.streamType = AUDIO_CAPTURE_STREAM;
    g_hwParams.channels = handleData->frameCaptureMode.attrs.channelCount;
    g_hwParams.rate = handleData->frameCaptureMode.attrs.sampleRate;
    g_hwParams.periodSize = handleData->frameCaptureMode.periodSize;
    g_hwParams.periodCount = handleData->frameCaptureMode.periodCount;
    g_hwParams.cardServiceName = (char*)handleData->captureMode.hwInfo.cardServiceName;
    g_hwParams.format = handleData->frameCaptureMode.attrs.format;
    g_hwParams.period = handleData->frameCaptureMode.attrs.period;
    g_hwParams.frameSize = handleData->frameCaptureMode.attrs.frameSize;
    g_hwParams.isBigEndian = handleData->frameCaptureMode.attrs.isBigEndian;
    g_hwParams.isSignedData = handleData->frameCaptureMode.attrs.isSignedData;
    g_hwParams.startThreshold = handleData->frameCaptureMode.attrs.startThreshold;
    g_hwParams.stopThreshold = handleData->frameCaptureMode.attrs.stopThreshold;
    g_hwParams.silenceThreshold = handleData->frameCaptureMode.attrs.silenceThreshold;
    return HDF_SUCCESS;
}

int32_t ParamsSbufWriteBuffer(struct HdfSBuf *sBuf)
{
    if (sBuf == NULL) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)g_hwParams.streamType)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.channels)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.rate)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.periodSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.periodCount)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.format))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, g_hwParams.cardServiceName)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.period)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.frameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.isBigEndian))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, (uint32_t)(g_hwParams.isSignedData))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.startThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.stopThreshold)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(sBuf, g_hwParams.silenceThreshold)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetPauseBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Main Playback Pause";
    elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.pause;

    return AudioSetElemValue(sBuf, &elemCaptureValue, true);
}

int32_t AudioCtlCaptureSetPauseStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetPauseStu paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetPauseStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, handleData->captureMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteString cardServiceName failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    int32_t ret = AudioCtlCaptureSetPauseBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Set Pause sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return ret;
    }

    cmdId = handleData->captureMode.ctlParam.pause ?
        AUDIO_DRV_PCM_IOCTRL_PAUSE_CAPTURE : AUDIO_DRV_PCM_IOCTRL_RESUME_CAPTURE;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, NULL);
        AUDIO_FUNC_LOGE("SetPauseStu Failed to send service call!");
        return ret;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return ret;
}

int32_t AudioCtlCaptureGetVolumeSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetVolumeSBuf  parameter is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Main Capture Volume";

    return AudioSetElemValue(sBuf, &elemCaptureValue, false);
}

int32_t AudioCtlCaptureGetVolume(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetVolume paras is NULL!");
        return HDF_FAILURE;
    }

    int32_t elemValue = 0;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;

    int32_t ret = AudioAllocHdfSBuf(&sBuf, &reply);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    ret = AudioCtlCaptureGetVolumeSBuf(sBuf, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to Get Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        AUDIO_FUNC_LOGE("GetVolume Dispatch Fail!");
        return ret;
    }

    if (!HdfSbufReadInt32(reply, &elemValue)) {
        AUDIO_FUNC_LOGE("Failed to Get Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->captureMode.ctlParam.volume = (float)elemValue;

    AudioFreeHdfSBuf(sBuf, reply);
    return ret;
}

int32_t AudioCtlCaptureSetVolumeSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetVolumeSBuf parameter is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Main Capture Volume";
    elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.volume;

    return AudioSetElemValue(sBuf, &elemCaptureValue, true);
}

int32_t AudioCtlCaptureSetVolume(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetVolume paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetVolume Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    int32_t ret = AudioCtlCaptureSetVolumeSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CaptureSetVolume Failed to Set Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return ret;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, NULL);
        AUDIO_FUNC_LOGE("CaptureSetVolume Service Failed!");
        return ret;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return ret;
}

int32_t AudioCtlCaptureSetMuteSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Capture Mute";
    elemCaptureValue.value[0] = (int32_t)handleData->captureMode.ctlParam.mute;

    return AudioSetElemValue(sBuf, &elemCaptureValue, true);
}

int32_t AudioCtlCaptureSetMuteStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetMuteStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    int32_t ret = AudioCtlCaptureSetMuteSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CaptureSetMuteStu Failed to Get Mute sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return ret;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, NULL);
        AUDIO_FUNC_LOGE("CaptureSetMuteStu Service is NULL!");
        return ret;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return ret;
}

int32_t AudioCtlCaptureGetMuteSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("The parameter is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Capture Mute";

    return AudioSetElemValue(sBuf, &elemCaptureValue, false);
}

int32_t AudioCtlCaptureGetMuteStu(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetMuteStu paras is NULL!");
        return HDF_FAILURE;
    }

    int32_t muteValueStu = 0;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;

    int32_t ret = AudioAllocHdfSBuf(&sBuf, &reply);
    if (ret != HDF_SUCCESS) {
        return HDF_FAILURE;
    }

    ret = AudioCtlCaptureGetMuteSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Get Mute sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureGetMuteStu Dispatch Fail!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadInt32(reply, &muteValueStu)) {
        AUDIO_FUNC_LOGE("CaptureGetMuteStu Failed to Get Volume sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->captureMode.ctlParam.mute = (bool)muteValueStu;

    AudioFreeHdfSBuf(sBuf, reply);
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureSetGainSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetGainSBuf( handleData or sBuf is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Mic Left Gain";
    elemCaptureValue.value[0] = handleData->captureMode.ctlParam.audioGain.gain;

    return AudioSetElemValue(sBuf, &elemCaptureValue, true);
}

int32_t AudioCtlCaptureSetGainStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    int32_t ret = AudioCtlCaptureSetGainSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu Failed to Get Gain sBuf!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return ret;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureSetGainStu Failed to send service call!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return ret;
}

int32_t AudioCtlCaptureGetGainSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainSBuf paras is NULL!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName = "Mic Left Gain";

    return AudioSetElemValue(sBuf, &elemCaptureValue, false);
}

int32_t AudioCtlCaptureGetGainStu(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainStu paras is NULL!");
        return HDF_FAILURE;
    }

    int32_t muteValueStu = 0;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();

    int32_t ret = AudioAllocHdfSBuf(&sBuf, &reply);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    ret = AudioCtlCaptureGetGainSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Get Gain sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE - CTRL_NUM;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("GetGainStu Dispatch Fail!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadInt32(reply, &muteValueStu)) {
        AUDIO_FUNC_LOGE("Failed to GetGain sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->captureMode.ctlParam.audioGain.gain = (float)muteValueStu;

    AudioFreeHdfSBuf(sBuf, reply);
    return ret;
}

int32_t AudioCtlCaptureSceneSelectSBuf(struct HdfSBuf *sBuf,
    const struct AudioHwCaptureParam *handleData, int32_t deviceIndex)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureSceneSelectSBuf handleData or sBufs is NULL!");
        return HDF_FAILURE;
    }
    if (deviceIndex < 0 || deviceIndex > PATHPLAN_COUNT - 1) {
        AUDIO_FUNC_LOGE("deviceIndex is Invalid!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureValue;
    elemCaptureValue.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureValue.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureValue.id.itemName =
        handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].deviceSwitch;
    elemCaptureValue.value[0] = handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceSwitchs[deviceIndex].value - '0';

    return AudioSetElemValue(sBuf, &elemCaptureValue, true);
}

int32_t AudioCtlCaptureSceneSelect(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    int32_t deviceNum;
    struct HdfSBuf *sBuf = NULL;
    int32_t index;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureSceneSelect parameter is empty!");
        return HDF_FAILURE;
    }

    if (strcmp(handleData->captureMode.hwInfo.adapterName, USB) == 0 ||
        strcmp(handleData->captureMode.hwInfo.adapterName, HDMI) == 0) {
        return HDF_SUCCESS;
    }

    sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    deviceNum = handleData->captureMode.hwInfo.pathSelect.deviceInfo.deviceNum;
    if (deviceNum < AUDIO_MIN_DEVICENUM) {
        AUDIO_FUNC_LOGE("AUDIO_MIN_ADAPTERNUM Failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE - CTRL_NUM;

    for (index = 0; index < deviceNum; index++) {
        HdfSbufFlush(sBuf);
        if (AudioCtlCaptureSceneSelectSBuf(sBuf, handleData, index) < 0) {
            AUDIO_FUNC_LOGE("AudioCtlCaptureSceneSelectSBuf Failed!");
            AudioFreeHdfSBuf(sBuf, NULL);
            return HDF_FAILURE;
        }

        if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) < 0) {
            AUDIO_FUNC_LOGE("Failed to call AudioServiceDispatch!");
            AudioFreeHdfSBuf(sBuf, NULL);
            return HDF_FAILURE;
        }
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioCtlCaptureGetGainThresholdSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainThresholdSBuf paras is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureInfo;
    elemCaptureInfo.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureInfo.id.itemName = "Mic Left Gain";

    return AudioSetElemValue(sBuf, &elemCaptureInfo, false);
}

int32_t AudioCtlCaptureGetGainThreshold(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = NULL;
    struct HdfSBuf *reply = NULL;
    struct AudioCtrlElemInfo gainThreshold;

    int32_t ret = AudioAllocHdfSBuf(&sBuf, &reply);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    ret = AudioCtlCaptureGetGainThresholdSBuf(sBuf, handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold Failed to Get Threshold sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO_CAPTURE - CTRL_NUM;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, reply);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    (void)memset_s(&gainThreshold, sizeof(struct AudioCtrlElemInfo), 0, sizeof(struct AudioCtrlElemInfo));

    if (!HdfSbufReadInt32(reply, &gainThreshold.type)) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold Failed to HdfSbufReadBuffer!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadInt32(reply, &gainThreshold.max)) {
        AUDIO_FUNC_LOGE("CaptureGetGainThreshold Failed to HdfSbufReadBuffer!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    handleData->captureMode.ctlParam.audioGain.gainMax = gainThreshold.max;
    handleData->captureMode.ctlParam.audioGain.gainMin = 0;

    AudioFreeHdfSBuf(sBuf, reply);
    return ret;
}

int32_t AudioCtlCaptureGetVolThresholdSBuf(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (handleData == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetVolThresholdSBuf paras is empty!");
        return HDF_FAILURE;
    }
    struct AudioCtlElemValue elemCaptureInfo;
    elemCaptureInfo.id.cardServiceName = handleData->captureMode.hwInfo.cardServiceName;
    elemCaptureInfo.id.iface = AUDIODRV_CTL_ELEM_IFACE_MIXER;
    elemCaptureInfo.id.itemName = "Main Capture Volume";

    return AudioSetElemValue(sBuf, &elemCaptureInfo, false);
}

int32_t AudioCtlCaptureGetVolThreshold(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }

    struct AudioCtrlElemInfo volThreshold;
    struct HdfSBuf *reply = NULL;
    struct HdfSBuf *sBuf = NULL;

    int32_t ret = AudioAllocHdfSBuf(&sBuf, &reply);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    ret = AudioCtlCaptureGetVolThresholdSBuf(sBuf, handleData);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Failed to Get Threshold sBuf!");
        AudioFreeHdfSBuf(sBuf, reply);
        return ret;
    }

    cmdId = AUDIODRV_CTL_IOCTL_ELEM_INFO_CAPTURE - CTRL_NUM;

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, reply);
    if (ret == HDF_ERR_NOT_SUPPORT) {
        AUDIO_FUNC_LOGW("This sound card does not have a volume control component!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_SUCCESS;
    } else if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioServiceDispatch failed!");
        AudioFreeHdfSBuf(sBuf, reply);
        return HDF_FAILURE;
    }

    ret = AudioGetElemValue(reply, &volThreshold);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioGetElemValue failed!");
        return HDF_FAILURE;
    }

    handleData->captureMode.ctlParam.volThreshold.volMax = volThreshold.max;
    handleData->captureMode.ctlParam.volThreshold.volMin = volThreshold.min;

    AudioFreeHdfSBuf(sBuf, reply);
    return ret;
}

int32_t AudioInterfaceLibCtlCapture(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }

    switch (cmdId) {
        /* setPara: */
        case AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE:
            return AudioCtlCaptureSetVolume(handle, cmdId, handleData);
        case AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE:
            return AudioCtlCaptureSetMuteStu(handle, cmdId, handleData);
        case AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE:
            return AudioCtlCaptureGetMuteStu(handle, cmdId, handleData);
        /* getPara: */
        case AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE:
            return AudioCtlCaptureGetVolume(handle, cmdId, handleData);
        case AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE:
            return AudioCtlCaptureSetGainStu(handle, cmdId, handleData);
        case AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE:
            return AudioCtlCaptureGetGainStu(handle, cmdId, handleData);
        case AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE:
            return AudioCtlCaptureSceneSelect(handle, cmdId, handleData);
        case AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE:
            return AudioCtlCaptureGetGainThreshold(handle, cmdId, handleData);
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE:
            return AudioCtlCaptureGetVolThreshold(handle, cmdId, handleData);
        default:
            AUDIO_FUNC_LOGE("Ctl Mode not support!");
            return HDF_FAILURE;
    }
}

int32_t AudioOutputCaptureHwParams(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Function parameter is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    int32_t ret = SetHwParamsCapture(handleData);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("SetHwParamsCapture Failed");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    ret = ParamsSbufWriteBuffer(sBuf);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("ParamsSbufWriteBuffer Failed");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioServiceDispatch failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureOpen(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("Function parameter is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, handleData->captureMode.hwInfo.cardServiceName)) {
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    int32_t ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureReadFrame(const struct DevHandle *handle, struct AudioHwCaptureParam *handleData,
    int cmdId, struct HdfSBuf *reply)
{
    int32_t buffStatus = 0;
    int32_t tryNumReply = 100; // try get reply count

    if (handle == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, handleData->captureMode.hwInfo.cardServiceName)) {
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    do {
        if (AudioServiceDispatch(handle->object, cmdId, sBuf, reply) != HDF_SUCCESS) {
            AUDIO_FUNC_LOGE("Failed to send service call!");
            AudioFreeHdfSBuf(sBuf, NULL);
            return HDF_FAILURE;
        }

        if (!HdfSbufReadInt32(reply, &buffStatus)) {
            AUDIO_FUNC_LOGE("Failed to Get buffStatus!");
            return HDF_FAILURE;
        }

        if (buffStatus == CIR_BUFF_EMPTY) {
            usleep(AUDIO_CAP_WAIT_DELAY + (tryNumReply % AUDIO_TRYNUM) * AUDIO_TRYNUM_TIME);
            AUDIO_FUNC_LOGD("Cir buff empty wait");
        } else if (buffStatus >= 0) {
            AUDIO_FUNC_LOGD("capture need wait for %{public}d ms!", buffStatus);
            usleep(buffStatus * AUDIO_US_TO_MS);
        } else {
            break;
        }

        tryNumReply--;
        HdfSbufFlush(reply);
    } while (tryNumReply > 0);

    if (tryNumReply <= 0) {
        AUDIO_FUNC_LOGE("Out of tryNumReply!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

#ifdef MONO_TO_STEREO
void CaptureChannelFixed(void *data, uint32_t len)
{
    int16_t *pcmLeft = (int16_t*)data;
    int16_t *pcmRight = pcmLeft + 1; // right channel offset + 1

    for (uint32_t index = 0; index < len; index += 2) { // 16bit, step = 2
        pcmRight[index] = pcmLeft[index];
    }
    return;
}
#endif

int32_t AudioInputCaptureReadInfoToHandleData(struct AudioHwCaptureParam *handleData,
    char *frame, uint32_t frameCount, uint32_t dataSize)
{
    int32_t ret = memcpy_s(handleData->frameCaptureMode.buffer, FRAME_DATA, frame, dataSize);
    if (ret != 0) {
        return HDF_FAILURE;
    }
#ifdef MONO_TO_STEREO
    if (g_hwParams.channels == 2) { // if rk3568 channel = 2, and 16bit
        CaptureChannelFixed(handleData->frameCaptureMode.buffer, dataSize / 2); // len = dataSize / 2
    }
#endif
    handleData->frameCaptureMode.bufferSize = dataSize;
    handleData->frameCaptureMode.bufferFrameSize = frameCount;
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureRead(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    uint32_t dataSize = 0;
    uint32_t frameCount = 0;
    char *frame = NULL;

    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = HdfSbufTypedObtainCapacity(SBUF_RAW, (AUDIO_SIZE_FRAME_16K + AUDIO_REPLY_EXTEND));
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufTypedObtainCapacity replySize failed!");
        return HDF_FAILURE;
    }

    int32_t ret = AudioOutputCaptureReadFrame(handle, handleData, cmdId, reply);
    if (ret != HDF_SUCCESS) {
        AudioFreeHdfSBuf(reply, NULL);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadBuffer(reply, (const void **)&frame, &dataSize)) {
        AUDIO_FUNC_LOGE("[HdfSbufReadBuffer]-[frame] failed!");
        AudioFreeHdfSBuf(reply, NULL);
        return HDF_FAILURE;
    }

    if (dataSize > FRAME_DATA || handleData->frameCaptureMode.buffer == NULL) {
        AUDIO_FUNC_LOGE("Buffer is NULL or DataSize overflow!");
        AudioFreeHdfSBuf(reply, NULL);
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(reply, &frameCount)) {
        AUDIO_FUNC_LOGE("Failed to Get buffStatus!");
        AudioFreeHdfSBuf(reply, NULL);
        return HDF_FAILURE;
    }

    ret = AudioInputCaptureReadInfoToHandleData(handleData, frame, frameCount, dataSize);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("AudioInputCaptureReadInfoToHandleData Failed!");
        AudioFreeHdfSBuf(reply, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(reply, NULL);
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureStartPrepare(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureStartPrepare Failed to send service call!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("StartPrepare Failed to obtain sBuf");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteString(sBuf, handleData->captureMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("[HdfSbufWriteString]-[cardServiceName] failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    int32_t ret = AudioServiceDispatch(handle->object, cmdId, sBuf, NULL);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Failed to send service call!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureStop(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("CaptureStop paras is NULL!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, handleData->captureMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("[HdfSbufWriteString]-[cardServiceName] failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(sBuf, AUDIO_TURN_STANDBY_LATER)) {
        AUDIO_FUNC_LOGE("write sBuf Failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, NULL);
        AUDIO_FUNC_LOGE("CaptureStop Failed to send service call!");
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t MmapDescWriteBufferCapture(struct HdfSBuf *sBuf, const struct AudioHwCaptureParam *handleData)
{
    if (sBuf == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("param sBuf or handleData is null!");
        return HDF_FAILURE;
    }

    uint64_t mmapAddr = (uint64_t)(uintptr_t)(handleData->frameCaptureMode.mmapBufDesc.memoryAddress);

    if (!HdfSbufWriteString(sBuf, handleData->captureMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("[HdfSbufWriteString]-[cardServiceName] failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint64(sBuf, mmapAddr)) {
        AUDIO_FUNC_LOGE("HdfSbufWriteUint64 memoryAddress failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(sBuf, handleData->frameCaptureMode.mmapBufDesc.memoryFd)) {
        AUDIO_FUNC_LOGE("write memoryFd failed!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(sBuf, handleData->frameCaptureMode.mmapBufDesc.totalBufferFrames)) {
        AUDIO_FUNC_LOGE("write totalBufferFrames failed!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(sBuf, handleData->frameCaptureMode.mmapBufDesc.transferFrameSize)) {
        AUDIO_FUNC_LOGE("write transferFrameSize failed!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteInt32(sBuf, handleData->frameCaptureMode.mmapBufDesc.isShareable)) {
        AUDIO_FUNC_LOGE("write isShareable failed!");
        return HDF_FAILURE;
    }

    if (!HdfSbufWriteUint32(sBuf, handleData->frameCaptureMode.mmapBufDesc.offset)) {
        AUDIO_FUNC_LOGE("write offset failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureReqMmapBuffer(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }

    if (MmapDescWriteBufferCapture(sBuf, handleData)) {
        AudioFreeHdfSBuf(sBuf, NULL);
        AUDIO_FUNC_LOGE("MmapDescWriteBufferCapture failed!");
        return HDF_FAILURE;
    }

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, NULL) != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, NULL);
        AUDIO_FUNC_LOGE("CaptureReqMmap Failed to send service call!");
        return HDF_FAILURE;
    }

    AudioFreeHdfSBuf(sBuf, NULL);
    return HDF_SUCCESS;
}

int32_t AudioOutputCaptureGetMmapPosition(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle or handle->object or handleData is null!");
        return HDF_FAILURE;
    }

    uint64_t frames = 0;
    struct HdfSBuf *sBuf = HdfSbufObtainDefaultSize();
    if (sBuf == NULL) {
        AUDIO_FUNC_LOGE("HdfSbufObtainDefaultSize failed!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteString(sBuf, handleData->captureMode.hwInfo.cardServiceName)) {
        AUDIO_FUNC_LOGE("[HdfSbufWriteString]-[cardServiceName] failed!");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    struct HdfSBuf *reply = HdfSbufObtainDefaultSize();
    if (reply == NULL) {
        AUDIO_FUNC_LOGE("CaptureGetMmapPosition Failed to obtain reply");
        AudioFreeHdfSBuf(sBuf, NULL);
        return HDF_FAILURE;
    }

    if (AudioServiceDispatch(handle->object, cmdId, sBuf, reply) != HDF_SUCCESS) {
        AudioFreeHdfSBuf(sBuf, reply);
        AUDIO_FUNC_LOGE("CaptureGetMmapPosition Failed to send service call!");
        return HDF_FAILURE;
    }
    AudioFreeHdfSBuf(sBuf, NULL);

    if (!HdfSbufReadUint64(reply, &frames)) {
        AudioFreeHdfSBuf(reply, NULL);
        AUDIO_FUNC_LOGE("Failed to Get frames sBuf");
        return HDF_FAILURE;
    }

    handleData->frameCaptureMode.frames = frames;
    AudioFreeHdfSBuf(reply, NULL);
    return HDF_SUCCESS;
}

int32_t AudioInterfaceLibOutputCapture(const struct DevHandle *handle, int cmdId,
    struct AudioHwCaptureParam *handleData)
{
    if (handle == NULL) {
        AUDIO_FUNC_LOGE("Input Capture handle is NULL!");
        return HDF_FAILURE;
    }
    if (handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("handle->object or handleData is null!");
        return HDF_FAILURE;
    }
    int32_t ret;
    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
            ret = AudioOutputCaptureHwParams(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_READ:
            ret = AudioOutputCaptureRead(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_START_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE:
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE:
            ret = AudioOutputCaptureStartPrepare(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN:
            ret = AudioOutputCaptureOpen(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE:
            ret = AudioOutputCaptureStop(handle, cmdId, handleData);
            break;
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE:
            ret = AudioCtlCaptureSetPauseStu(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE:
            ret = AudioOutputCaptureReqMmapBuffer(handle, cmdId, handleData);
            break;
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION_CAPTURE:
            ret = AudioOutputCaptureGetMmapPosition(handle, cmdId, handleData);
            break;
        default:
            AUDIO_FUNC_LOGE("Output Mode not support!");
            ret = HDF_FAILURE;
            break;
    }
    return ret;
}

int32_t AudioInterfaceLibModeCapture(const struct DevHandle *handle,
    struct AudioHwCaptureParam *handleData, int cmdId)
{
    if (handle == NULL || handle->object == NULL || handleData == NULL) {
        AUDIO_FUNC_LOGE("paras is NULL!");
        return HDF_FAILURE;
    }
    switch (cmdId) {
        case AUDIO_DRV_PCM_IOCTL_HW_PARAMS:
        case AUDIO_DRV_PCM_IOCTL_READ:
        case AUDIO_DRV_PCM_IOCTRL_START_CAPTURE:
        case AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE:
        case AUDIO_DRV_PCM_IOCTL_MMAP_POSITION_CAPTURE:
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN:
        case AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE:
            return (AudioInterfaceLibOutputCapture(handle, cmdId, handleData));
        case AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE:
        case AUDIODRV_CTL_IOCTL_ELEM_LIST_CAPTURE:
        case AUDIODRV_CTL_IOCTL_ELEM_CARD_CAPTURE:
        case AUDIODRV_CTL_IOCTL_ELEM_HDMI_CAPTURE:
        case AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE:
        case AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE:
        case AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE:
        case AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE:
        case AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE:
        case AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE:
            return (AudioInterfaceLibCtlCapture(handle, cmdId, handleData));
        default:
            AUDIO_FUNC_LOGE("Mode Error!");
            break;
    }
    return HDF_ERR_NOT_SUPPORT;
}
