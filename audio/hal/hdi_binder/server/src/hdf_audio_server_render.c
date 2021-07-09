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
#include "hdf_audio_server_render.h"

int32_t GetInitRenderParaAttrs(struct HdfSBuf *data, struct AudioSampleAttributes *attrs)
{
    if (data == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempRenderPara = 0;
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    attrs->type = (enum AudioCategory)tempRenderPara;
    if (!HdfSbufReadUint32(data, &attrs->period)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->frameSize)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->startThreshold)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->stopThreshold)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->silenceThreshold)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        LOG_FUN_ERR("Failed to Get Speed sBuf!");
        return HDF_FAILURE;
    }
    attrs->isBigEndian = (bool)tempRenderPara;
    return HDF_SUCCESS;
}

int32_t GetInitRenderPara(struct HdfSBuf *data, struct AudioDeviceDescriptor *devDesc,
    struct AudioSampleAttributes *attrs)
{
    if (data == NULL || devDesc == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempRenderPara = 0;
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        LOG_FUN_ERR("Failed to Get Speed sBuf!");
        return HDF_FAILURE;
    }
    attrs->format = (enum AudioFormat)tempRenderPara;
    if (!HdfSbufReadUint32(data, &attrs->channelCount)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->sampleRate)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        LOG_FUN_ERR("Failed to Get Speed sBuf!");
        return HDF_FAILURE;
    }
    attrs->interleaved = (bool)tempRenderPara;
    if (GetInitRenderParaAttrs(data, attrs) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        LOG_FUN_ERR("Failed to Get Speed sBuf!");
        return HDF_FAILURE;
    }
    attrs->isSignedData = (bool)tempRenderPara;
    if (!HdfSbufReadUint32(data, &devDesc->portId)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        HDF_LOGE("%{public}s", " read buf fail");
        return HDF_FAILURE;
    }
    devDesc->pins = (enum AudioPortPin)tempRenderPara;
    devDesc->desc = NULL;
    return HDF_SUCCESS;
}

int32_t HdiServiceCreatRender(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioAdapter *adapter = NULL;
    struct AudioDeviceDescriptor devDesc;
    struct AudioSampleAttributes attrs;
    struct AudioRender *render = NULL;
    const char *adapterName = NULL;
    uint32_t renderPid;
    if ((adapterName = HdfSbufReadString(data)) == NULL) {
        HDF_LOGE("%{public}s", "adapterNameCase Is NULL");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &renderPid)) {
        return HDF_FAILURE;
    }
    HDF_LOGE("%{public}s, renderPid = %{public}u", "HdiServiceCreatRender:", renderPid);
    int32_t ret = GetInitRenderPara(data, &devDesc, &attrs);
    if (ret < 0) {
        HDF_LOGE("%{public}s", " GetInitRenderPara fail");
        return HDF_FAILURE;
    }
    if (AudioAdapterListGetAdapter(adapterName, &adapter)) {
        HDF_LOGE("%{public}s", "AudioAdapterListGetAdapter fail");
        return HDF_FAILURE;
    }
    if (adapter == NULL) {
        HDF_LOGE("%{public}s", "HdiServiceCreatRender adapter is NULL!");
        return HDF_FAILURE;
    }
    const int32_t priority = attrs.type;
    ret = AudioCreatRenderCheck(adapterName, priority);
    if (ret < 0) {
        HDF_LOGE("%{public}s", "AudioCreatRenderCheck: Render is working can not replace!");
        return ret;
    }
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    if (render == NULL || ret < 0) {
        HDF_LOGE("%{public}s", "Failed to CreateRender");
        return HDF_FAILURE;
    }
    if (AudioAddRenderInfoInAdapter(adapterName, render, adapter, priority, renderPid)) {
        HDF_LOGE("%{public}s", "AudioAddRenderInfoInAdapter");
        adapter->DestroyRender(adapter, render);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderDestory(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioAdapter *adapter = NULL;
    struct AudioRender *render = NULL;
    const char *adapterName = NULL;
    uint32_t pid;
    if (HdiServiceRenderCaptureReadData(data, &adapterName, &pid) < 0) {
        return HDF_FAILURE;
    }
    int32_t ret = AudioAdapterListGetRender(adapterName, &render, pid);
    if (ret < 0) {
        return ret;
    }
    ret = AudioAdapterListGetAdapterRender(adapterName, &adapter, &render);
    if (ret < 0) {
        return ret;
    }
    if (adapter == NULL || render == NULL) {
        return HDF_FAILURE;
    }
    ret = adapter->DestroyRender(adapter, render);
    if (ret < 0) {
        HDF_LOGE("%{public}s", "DestroyRender failed!");
        return ret;
    }
    if (AudioDestroyRenderInfoInAdapter(adapterName)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderStart(struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    return render->control.Start((AudioHandle)render);
}

int32_t HdiServiceRenderStop(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    return render->control.Stop((AudioHandle)render);
}

int32_t HdiServiceRenderPause(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    HDF_LOGE("%{public}s", "enter to HdiServiceRenderPause ");
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    return render->control.Pause((AudioHandle)render);
}

int32_t HdiServiceRenderResume(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    return render->control.Resume((AudioHandle)render);
}

int32_t HdiServiceRenderFlush(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    return render->control.Flush((AudioHandle)render);
}

int32_t HdiServiceRenderGetFrameSize(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint64_t size;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render->attr.GetFrameSize((AudioHandle)render, &size)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint64(reply, size)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderGetFrameCount(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint64_t count;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render->attr.GetFrameCount((AudioHandle)render, &count)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint64(reply, count)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderSetSampleAttr(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioSampleAttributes attrs;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (ReadAudioSapmleAttrbutes(data, &attrs) < 0) {
        return HDF_FAILURE;
    }
    return render->attr.SetSampleAttributes((AudioHandle)render, &attrs);
}

int32_t HdiServiceRenderGetSampleAttr(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioSampleAttributes attrs;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->attr.GetSampleAttributes((AudioHandle)render, &attrs);
    if (ret < 0) {
        return ret;
    }
    if (WriteAudioSampleAttributes(reply, &attrs) < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderGetCurChannelId(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint32_t channelId;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->attr.GetCurrentChannelId((AudioHandle)render, &channelId);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufWriteUint32(reply, channelId)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderCheckSceneCapability(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioSceneDescriptor scene;
    bool supported = false;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &scene.scene.id)) {
        return HDF_FAILURE;
    }
    uint32_t tempPins = 0;
    if (!HdfSbufReadUint32(data, &tempPins)) {
        return HDF_FAILURE;
    }
    scene.desc.pins = (enum AudioPortPin)tempPins;
    ret = render->scene.CheckSceneCapability((AudioHandle)render, &scene, &supported);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempSupported = (uint32_t)supported;
    if (!HdfSbufWriteUint32(reply, tempSupported)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderSelectScene(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    struct AudioSceneDescriptor scene;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &scene.scene.id)) {
        return HDF_FAILURE;
    }
    uint32_t tempPins = 0;
    if (!HdfSbufReadUint32(data, &tempPins)) {
        return HDF_FAILURE;
    }
    scene.desc.pins = (enum AudioPortPin)tempPins;
    return render->scene.SelectScene((AudioHandle)render, &scene);
}

int32_t HdiServiceRenderGetMute(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    bool mute = false;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->volume.GetMute((AudioHandle)render, &mute);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMute = (uint32_t)mute;
    if (!HdfSbufWriteUint32(reply, tempMute)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderSetMute(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    bool mute = false;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMute = 0;
    if (!HdfSbufReadUint32(data, &tempMute)) {
        return HDF_FAILURE;
    }
    mute = (bool)tempMute;
    return render->volume.SetMute((AudioHandle)render, mute);
}

int32_t HdiServiceRenderSetVolume(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint32_t volume;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &volume)) {
        return HDF_FAILURE;
    }
    float setVolume = (float)volume / VOLUME_CHANGE;
    return render->volume.SetVolume((AudioHandle)render, setVolume);
}

int32_t HdiServiceRenderGetVolume(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    float volume;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->volume.GetVolume((AudioHandle)render, &volume);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempVolume = (uint32_t)(volume * VOLUME_CHANGE);
    if (!HdfSbufWriteUint32(reply, tempVolume)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderGetGainThreshold(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    float min, max;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->volume.GetGainThreshold((AudioHandle)render, &min, &max);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMin = (uint32_t)min;
    if (!HdfSbufWriteUint32(reply, tempMin)) {
        return HDF_FAILURE;
    }
    uint32_t tempMax = (uint32_t)max;
    if (!HdfSbufWriteUint32(reply, tempMax)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderGetGain(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    float gain;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->volume.GetGain((AudioHandle)render, &gain);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempGain = (uint32_t)gain;
    if (!HdfSbufWriteUint32(reply, tempGain)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderSetGain(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempGain;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &tempGain)) {
        return HDF_FAILURE;
    }
    return render->volume.SetGain((AudioHandle)render, (float)tempGain);
}

int32_t HdiServiceRenderGetLatency(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint32_t ms;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->GetLatency((AudioHandle)render, &ms);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufWriteUint32(reply, ms)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderRenderFrame(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s", "HdiServiceRenderRenderFrame entry!");
    char *frame = NULL;
    uint32_t requestBytes;
    uint64_t replyBytes;
    struct AudioRender *render = NULL;
    const char *adapterName = NULL;
    uint32_t pid;
    if (HdiServiceRenderCaptureReadData(data, &adapterName, &pid) < 0) {
        HDF_LOGE("%{public}s", "HdiServiceRenderRenderFrame:HdiServiceRenderCaptureReadData fail!");
        return HDF_FAILURE;
    }
    int32_t ret = AudioAdapterListGetRender(adapterName, &render, pid);
    if (ret < 0) {
        HDF_LOGE("%{public}s", "HdiServiceRenderRenderFrame:AudioAdapterListGetRender fail");
        return ret;
    }
    ret = AudioGetRenderStatus(adapterName);
    if (ret < 0) {
        HDF_LOGE("%{public}s", "HdiServiceRenderRenderFrame:AudioGetRenderStatus fail");
        return ret;
    }
    if (!HdfSbufReadBuffer(data, (const void **)&frame, &requestBytes)) {
        HDF_LOGE("%{public}s", "AudioAdapterListGetRender:HdfSbufReadBuffer fail");
        return HDF_FAILURE;
    }
    AudioSetRenderStatus(adapterName, true);
    ret = render->RenderFrame((AudioHandle)render, (const void *)frame, (uint64_t)requestBytes, &replyBytes);
    AudioSetRenderStatus(adapterName, false);
    HDF_LOGE("%{public}s,%{public}u,%{public}llu", "HdiServiceRenderRenderFrame", requestBytes, replyBytes);
    if (ret < 0) {
        HDF_LOGE("%{public}s ", "HdiServiceRenderRenderFrame:HdiServiceRenderRenderFrame");
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderGetRenderPosition(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint64_t frames;
    struct AudioTimeStamp time;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->GetRenderPosition((AudioHandle)render, &frames, &time);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufWriteUint64(reply, frames)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt64(reply, time.tvSec)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt64(reply, time.tvNSec)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderGetSpeed(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    float speed;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->GetRenderSpeed((AudioHandle)render, &speed);
    if (ret < 0) {
        return ret;
    }
    uint64_t tempSpeed = (uint64_t)speed;
    if (!HdfSbufWriteUint64(reply, tempSpeed)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t HdiServiceRenderSetSpeed(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint64_t speed;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint64(data, &speed)) {
        return HDF_FAILURE;
    }
    return render->SetRenderSpeed((AudioHandle)render, (float)speed);
}

int32_t HdiServiceRenderSetChannelMode(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    enum AudioChannelMode mode;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMode = 0;
    if (!HdfSbufReadUint32(data, &tempMode)) {
        return HDF_FAILURE;
    }
    mode = (enum AudioChannelMode)tempMode;
    return render->SetChannelMode((AudioHandle)render, mode);
}

int32_t HdiServiceRenderGetChannelMode(struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    HDF_LOGE("%{public}s", "HdiServiceRenderGetChannelMode in");
    if (client == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    enum AudioChannelMode mode;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    ret = render->GetChannelMode((AudioHandle)render, &mode);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMode = (uint32_t)mode;
    if (!HdfSbufWriteUint32(reply, tempMode)) {
        return HDF_FAILURE;
    }
    HDF_LOGE("%{public}s", "HdiServiceRenderGetChannelMode out");
    return HDF_SUCCESS;
}

