/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hdf_audio_server_capture.h"
#include "osal_mem.h"
#include "audio_uhdf_log.h"
#include "hdf_audio_server_common.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_STUB
#define INTERNEL_INPUT_STEAM_ID 1

static int32_t GetInitCaptureParaAttrs(struct HdfSBuf *data, struct AudioSampleAttributes *attrs)
{
    if (data == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempCapturePara = 0;
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        AUDIO_FUNC_LOGE("Capture read tempCapturePara fail");
        return HDF_FAILURE;
    }
    attrs->type = (enum AudioCategory)tempCapturePara;
    if (!HdfSbufReadUint32(data, &attrs->period)) {
        AUDIO_FUNC_LOGE("Capture read period fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->frameSize)) {
        AUDIO_FUNC_LOGE("Capture read frameSize fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->startThreshold)) {
        AUDIO_FUNC_LOGE("Capture read startThreshold fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->stopThreshold)) {
        AUDIO_FUNC_LOGE("Capture read stopThreshold fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->silenceThreshold)) {
        AUDIO_FUNC_LOGE("Capture read silenceThreshold fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        AUDIO_FUNC_LOGE("Failed to Get Speed sBuf!");
        return HDF_FAILURE;
    }
    attrs->isBigEndian = (bool)tempCapturePara;
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        AUDIO_FUNC_LOGE("Failed to Get Speed sBuf!");
        return HDF_FAILURE;
    }
    attrs->isSignedData = (bool)tempCapturePara;
    return HDF_SUCCESS;
}

static int32_t GetInitCapturePara(struct HdfSBuf *data, struct AudioDeviceDescriptor *devDesc,
    struct AudioSampleAttributes *attrs)
{
    if (data == NULL || devDesc == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempCapturePara = 0;
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        AUDIO_FUNC_LOGE("Failed to Get Speed sBuf!");
        return HDF_FAILURE;
    }
    attrs->format = (enum AudioFormat)tempCapturePara;
    if (!HdfSbufReadUint32(data, &attrs->channelCount)) {
        AUDIO_FUNC_LOGE("read channelCount fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->sampleRate)) {
        AUDIO_FUNC_LOGE("read sampleRate fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        AUDIO_FUNC_LOGE("Failed to Get Speed sBuf!");
        return HDF_FAILURE;
    }
    attrs->interleaved = (bool)tempCapturePara;
    if (GetInitCaptureParaAttrs(data, attrs) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &devDesc->portId)) {
        AUDIO_FUNC_LOGE("read portId fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        AUDIO_FUNC_LOGE("read tempCapturePara fail");
        return HDF_FAILURE;
    }
    devDesc->pins = (enum AudioPortPin)tempCapturePara;
    devDesc->desc = NULL;
    return HDF_SUCCESS;
}

int32_t HdiServiceCreatCapture(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioAdapter *adapter = NULL;
    struct AudioDeviceDescriptor devDesc;
    struct AudioSampleAttributes attrs;
    struct AudioCapture *capture = NULL;
    const char *adapterName = NULL;
    uint32_t capturePid = 0;
    if ((adapterName = HdfSbufReadString(data)) == NULL) {
        AUDIO_FUNC_LOGE("adapterNameCase Is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &capturePid)) {
        AUDIO_FUNC_LOGE("read capturePid fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AUDIO_FUNC_LOGD("capturePid = %{public}u", capturePid);
    int32_t ret = GetInitCapturePara(data, &devDesc, &attrs);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioAdapterListGetAdapter(adapterName, &adapter) < 0) {
        AUDIO_FUNC_LOGE("AudioAdapterListGetAdapter fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("adapter is empty!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    const int32_t priority = attrs.type;
    ret = AudioCreatCaptureCheck(adapterName, priority);
    if (ret < 0) {
        return ret;
    }

    attrs.streamId = INTERNEL_INPUT_STEAM_ID;
    if (adapter->CreateCapture == NULL) {
        AUDIO_FUNC_LOGE("CreateCapture is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    if (capture == NULL || ret < 0) {
        AUDIO_FUNC_LOGE("Failed to CreateCapture");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioAddCaptureInfoInAdapter(adapterName, capture, adapter, priority, capturePid)) {
        AUDIO_FUNC_LOGE("AudioAddRenderInfoInAdapter");
        adapter->DestroyCapture(adapter, capture);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureDestory(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioAdapter *adapter = NULL;
    struct AudioCapture *capture = NULL;
    const char *adapterName = NULL;
    uint32_t pid = 0;
    if (HdiServiceRenderCaptureReadData(data, &adapterName, &pid) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAdapterListGetCapture(adapterName, &capture, pid);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioAdapterListGetCapture failed ret = %{public}d", ret);
        return ret;
    }
    ret = AudioAdapterListGetAdapterCapture(adapterName, &adapter, &capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioAdapterListGetAdapterCapture failed ret = %{public}d", ret);
        return ret;
    }
    if (adapter == NULL || adapter->DestroyCapture == NULL) {
        AUDIO_FUNC_LOGE("adapter or DestroyCapture is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = adapter->DestroyCapture(adapter, capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("DestroyCapture failed!");
        return ret;
    }
    if (AudioDestroyCaptureInfoInAdapter(adapterName) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureStart(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or repoly is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioAdapterListCheckAndGetCapture failed ret = %{public}d", ret);
        return ret;
    }
    if (capture == NULL || capture->control.Start == NULL) {
        AUDIO_FUNC_LOGE("capture or Start is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->control.Start((AudioHandle)capture);
}

int32_t HdiServiceCaptureStop(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->control.Stop == NULL) {
        AUDIO_FUNC_LOGE("capture or Stop is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->control.Stop((AudioHandle)capture);
}

int32_t HdiServiceCapturePause(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->control.Pause == NULL) {
        AUDIO_FUNC_LOGE("capture or Pause is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->control.Pause((AudioHandle)capture);
}

int32_t HdiServiceCaptureResume(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->control.Resume == NULL) {
        AUDIO_FUNC_LOGE("capture or Resume is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->control.Resume((AudioHandle)capture);
}

int32_t HdiServiceCaptureFlush(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->control.Flush == NULL) {
        AUDIO_FUNC_LOGE("capture or Flush is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->control.Flush((AudioHandle)capture);
}

int32_t HdiServiceCaptureGetFrameSize(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint64_t size;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->attr.GetFrameSize == NULL) {
        AUDIO_FUNC_LOGE("capture or GetFrameSize is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (capture->attr.GetFrameSize((AudioHandle)capture, &size)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteUint64(reply, size)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureGetFrameCount(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint64_t count;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->attr.GetFrameCount == NULL) {
        AUDIO_FUNC_LOGE("capture or GetFrameCount is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (capture->attr.GetFrameCount((AudioHandle)capture, &count)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteUint64(reply, count)) {
        AUDIO_FUNC_LOGE("write count failed!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureSetSampleAttr(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int ret;
    struct AudioSampleAttributes attrs;
    struct AudioCapture *capture = NULL;
    ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (ReadAudioSapmleAttrbutes(data, &attrs) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (capture == NULL || capture->attr.SetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("capture or SetSampleAttributes is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->attr.SetSampleAttributes((AudioHandle)capture, &attrs);
}

int32_t HdiServiceCaptureGetSampleAttr(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioSampleAttributes attrs;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->attr.GetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("capture or GetSampleAttributes is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->attr.GetSampleAttributes((AudioHandle)capture, &attrs);
    if (ret < 0) {
        return ret;
    }
    if (WriteAudioSampleAttributes(reply, &attrs) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureGetCurChannelId(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t channelId;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->attr.GetCurrentChannelId == NULL) {
        AUDIO_FUNC_LOGE("capture or GetCurrentChannelId is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->attr.GetCurrentChannelId((AudioHandle)capture, &channelId);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufWriteUint32(reply, channelId)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureCheckSceneCapability(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioSceneDescriptor scene;
    bool supported = false;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &scene.scene.id)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    uint32_t interimPins = 0;
    if (!HdfSbufReadUint32(data, &interimPins)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    scene.desc.pins = (enum AudioPortPin) interimPins;
    if (capture == NULL || capture->scene.CheckSceneCapability == NULL) {
        AUDIO_FUNC_LOGE("capture or CheckSceneCapability is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->scene.CheckSceneCapability((AudioHandle)capture, &scene, &supported);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempSupported = (uint32_t)supported;
    if (!HdfSbufWriteUint32(reply, tempSupported)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureSelectScene(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioSceneDescriptor scene;
    struct AudioCapture *capture = NULL;
    uint32_t tempPins = 0;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &scene.scene.id)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufReadUint32(data, &tempPins)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    scene.desc.pins = (enum AudioPortPin) tempPins;
    if (capture == NULL || capture->scene.SelectScene == NULL) {
        AUDIO_FUNC_LOGE("capture or SelectScene is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->scene.SelectScene((AudioHandle)capture, &scene);
}

int32_t HdiServiceCaptureGetMute(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret;
    bool mute = false;
    struct AudioCapture *capture = NULL;
    ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->volume.GetMute == NULL) {
        AUDIO_FUNC_LOGE("capture or GetMute is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->volume.GetMute((AudioHandle)capture, &mute);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("getmute failed! ret = %{public}d", ret);
        return ret;
    }
    uint32_t tempMute = (uint32_t)mute;
    if (!HdfSbufWriteUint32(reply, tempMute)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureSetMute(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    bool mute = false;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMute = 0;
    if (!HdfSbufReadUint32(data, &tempMute)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    mute = (bool)tempMute;
    if (capture == NULL || capture->volume.SetMute == NULL) {
        AUDIO_FUNC_LOGE("capture or SetMute is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->volume.SetMute((AudioHandle)capture, mute);
}

int32_t HdiServiceCaptureSetVolume(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t volume = 0;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &volume)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    float setVolume = (float)volume / VOLUME_CHANGE;
    if (capture == NULL || capture->volume.SetVolume == NULL) {
        AUDIO_FUNC_LOGE("capture or SetVolume is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->volume.SetVolume((AudioHandle)capture, setVolume);
}

int32_t HdiServiceCaptureGetVolume(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    float volume;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->volume.GetVolume == NULL) {
        AUDIO_FUNC_LOGE("capture or GetVolume is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->volume.GetVolume((AudioHandle)capture, &volume);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempVolume = (uint32_t)(volume * VOLUME_CHANGE);
    if (!HdfSbufWriteUint32(reply, tempVolume)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureGetGainThreshold(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is null!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    float min, max;
    uint32_t tempMin;
    uint32_t tempMax;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->volume.GetGainThreshold == NULL) {
        AUDIO_FUNC_LOGE("capture or GetGainThreshold is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->volume.GetGainThreshold((AudioHandle)capture, &min, &max);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetGainThreshold failed! ret = %{public}d", ret);
        return ret;
    }
    tempMin = (uint32_t)min;
    if (!HdfSbufWriteUint32(reply, tempMin)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    tempMax = (uint32_t)max;
    if (!HdfSbufWriteUint32(reply, tempMax)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureGetGain(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    float gain;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->volume.GetGain == NULL) {
        AUDIO_FUNC_LOGE("capture or GetGain is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->volume.GetGain((AudioHandle)capture, &gain);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetGain failed! ret = %{public}d", ret);
        return ret;
    }
    uint32_t tempGain = (uint32_t)gain;
    if (!HdfSbufWriteUint32(reply, tempGain)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureSetGain(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t gain = 0;
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &gain)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (capture == NULL || capture->volume.SetGain == NULL) {
        AUDIO_FUNC_LOGE("capture or SetGain is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->volume.SetGain((AudioHandle)capture, (float)gain);
}

int32_t HdiServiceCaptureCaptureFrame(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    char *frame = NULL;
    uint64_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioCapture *capture = NULL;
    const char *adapterName = NULL;
    uint32_t pid = 0;
    uint32_t index = 0;
    if (HdiServiceRenderCaptureReadData(data, &adapterName, &pid) < 0) {
        AUDIO_FUNC_LOGE("HdiServiceRenderRenderFrame:HdiServiceRenderCaptureReadData fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAdapterFrameGetCapture(adapterName, &capture, pid, &index);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioAdapterListGetRender fail");
        return ret;
    }
    if (!HdfSbufReadUint64(data, &requestBytes)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    frame = (char *)OsalMemCalloc(FRAME_DATA);
    if (frame == NULL) {
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    AudioSetCaptureBusy(index, true);
    if (capture == NULL || capture->CaptureFrame == NULL) {
        AUDIO_FUNC_LOGE("capture or CaptureFrame is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->CaptureFrame((AudioHandle)capture, (void *)frame, requestBytes, &replyBytes);
    AudioSetCaptureBusy(index, false);
    if (ret < 0) {
        AudioMemFree((void **)&frame);
        return ret;
    }
    if (!HdfSbufWriteBuffer(reply, (const void *)frame, (uint32_t)requestBytes)) {
        AudioMemFree((void **)&frame);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteUint64(reply, replyBytes)) {
        AudioMemFree((void **)&frame);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioMemFree((void **)&frame);
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureGetCapturePosition(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioTimeStamp time;
    uint64_t frames;
    struct AudioCapture *capture = NULL;
    int32_t ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->GetCapturePosition == NULL) {
        AUDIO_FUNC_LOGE("capture or GetCapturePosition is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->GetCapturePosition((AudioHandle)capture, &frames, &time);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetCapturePosition fail");
        return ret;
    }
    if (HdiServicePositionWrite(reply, frames, time) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureSetExtraParams(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    const char *keyValueList = NULL;
    if ((keyValueList = HdfSbufReadString(data)) == NULL) {
        AUDIO_FUNC_LOGE("keyValueList Is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (capture == NULL || capture->attr.SetExtraParams == NULL) {
        AUDIO_FUNC_LOGE("capture or SetExtraParams is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->attr.SetExtraParams((AudioHandle)capture, keyValueList);
}

int32_t HdiServiceCaptureGetExtraParams(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    int32_t ret;
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    int32_t listLenth = 0;
    if (!HdfSbufReadInt32(data, &listLenth)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (listLenth <= 0 || listLenth > STR_MAX - 1) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    char keyValueList[STR_MAX] = { 0 };
    if (capture == NULL || capture->attr.GetExtraParams == NULL) {
        AUDIO_FUNC_LOGE("capture or GetExtraParams is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->attr.GetExtraParams((AudioHandle)capture, keyValueList, listLenth);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetExtraParams failed! ret = %{public}d", ret);
        return ret;
    }
    char *keyList = keyValueList;
    if (!HdfSbufWriteString(reply, keyList)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureReqMmapBuffer(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int32_t ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }

    struct AudioMmapBufferDescripter desc;
    int32_t reqSize = 0;
    if (!HdfSbufReadInt32(data, &reqSize)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (HdiServiceReqMmapBuffer(&desc, data) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (capture == NULL || capture->attr.ReqMmapBuffer == NULL) {
        AUDIO_FUNC_LOGE("capture or ReqMmapBuffer is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->attr.ReqMmapBuffer((AudioHandle)capture, reqSize, &desc);
}

int32_t HdiServiceCaptureGetMmapPosition(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint64_t frames;
    struct AudioTimeStamp time;
    struct AudioCapture *capture = NULL;
    int32_t ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }

    if (capture == NULL || capture->attr.GetMmapPosition == NULL) {
        AUDIO_FUNC_LOGE("capture or GetMmapPosition is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->attr.GetMmapPosition((AudioHandle)capture, &frames, &time);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetMmapPosition failed! ret = %{public}d", ret);
        return ret;
    }
    if (HdiServicePositionWrite(reply, frames, time) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureAddEffect(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)reply;
    uint64_t effectid = 0;
    struct AudioCapture *capture = NULL;
    if (data == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    int32_t ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0 || capture == NULL) {
        AUDIO_FUNC_LOGE("capture is null or ret = %{public}d", ret);
        return ret;
    }

    if (!HdfSbufReadUint64(data, &effectid)) {
        AUDIO_FUNC_LOGE("SbufReadUint64 failed ");
        return HDF_FAILURE;
    }

    if (capture->attr.AddAudioEffect == NULL) {
        AUDIO_FUNC_LOGE("capture or GetMmapPosition is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->attr.AddAudioEffect((AudioHandle)capture, effectid);
}

int32_t HdiServiceCaptureRemoveEffect(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)reply;
    uint64_t effectid = 0;
    if (data == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    struct AudioCapture *capture = NULL;
    int32_t ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0 || capture == NULL) {
        AUDIO_FUNC_LOGE("capture is NULL or ret = %{public}d", ret);
        return ret;
    }

    if (!HdfSbufReadUint64(data, &effectid)) {
        AUDIO_FUNC_LOGE("HdfSbufReadUint64 failed.");
        return HDF_FAILURE;
    }

    if (capture->attr.RemoveAudioEffect == NULL) {
        AUDIO_FUNC_LOGE("capture or GetMmapPosition is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->attr.RemoveAudioEffect((AudioHandle)capture, effectid);
}

int32_t HdiServiceCaptureTurnStandbyMode(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    if (capture == NULL || capture->control.Stop == NULL) {
        AUDIO_FUNC_LOGE("capture or Stop is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->control.Stop((AudioHandle)capture);
}

int32_t HdiServiceCaptureDevDump(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("parameter Is NULL");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = NULL;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    int32_t range = 0;
    if (!HdfSbufReadInt32(data, &range)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = HdfSbufReadFileDescriptor(data);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t fd = ret;
    if (capture == NULL || capture->control.AudioDevDump == NULL) {
        AUDIO_FUNC_LOGE("capture or AudioDevDump is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return capture->control.AudioDevDump((AudioHandle)capture, range, fd);
}

