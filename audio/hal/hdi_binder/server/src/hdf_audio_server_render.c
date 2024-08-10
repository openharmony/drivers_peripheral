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
#include "hdf_audio_server_render.h"
#include "audio_uhdf_log.h"
#include "hdf_audio_server_common.h"
#include "hdf_audio_server_manager.h"
#include "osal_mutex.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_STUB
#define IF_TRUE_PRINT_LOG_RETURN_ERROR(cond, log, err) \
    if (cond) { \
        AUDIO_FUNC_LOGE(log); \
        return err; \
    }
struct OsalMutex g_renderLock;

static int32_t GetInitRenderParaAttrs(struct HdfSBuf *data, struct AudioSampleAttributes *attrs)
{
    if (data == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempRenderPara = 0;
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        AUDIO_FUNC_LOGE("read tempRenderPara fail");
        return HDF_FAILURE;
    }
    attrs->type = (enum AudioCategory)tempRenderPara;
    if (!HdfSbufReadUint32(data, &attrs->period)) {
        AUDIO_FUNC_LOGE("read period fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->frameSize)) {
        AUDIO_FUNC_LOGE("read frameSize fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->startThreshold)) {
        AUDIO_FUNC_LOGE("read startThreshold fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->stopThreshold)) {
        AUDIO_FUNC_LOGE("read stopThreshold fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->silenceThreshold)) {
        AUDIO_FUNC_LOGE("read silenceThreshold fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        AUDIO_FUNC_LOGE("read bool isBigEndian fail");
        return HDF_FAILURE;
    }
    attrs->isBigEndian = (bool)tempRenderPara;

    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        AUDIO_FUNC_LOGE("read attrs isSignedData fail");
        return HDF_FAILURE;
    }
    attrs->isSignedData = (bool)tempRenderPara;

    if (!HdfSbufReadInt32(data, &attrs->streamId)) {
        AUDIO_FUNC_LOGE("read streamId fail");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t GetInitRenderPara(struct HdfSBuf *data, struct AudioDeviceDescriptor *devDesc,
    struct AudioSampleAttributes *attrs)
{
    if (data == NULL || devDesc == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    uint32_t tempRenderPara = 0;
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        AUDIO_FUNC_LOGE("read attrs format fail");
        return HDF_FAILURE;
    }
    attrs->format = (enum AudioFormat)tempRenderPara;
    if (!HdfSbufReadUint32(data, &attrs->channelCount)) {
        AUDIO_FUNC_LOGE("read channelCount fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->sampleRate)) {
        AUDIO_FUNC_LOGE("read sampleRate fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        AUDIO_FUNC_LOGE("read attrs interleaved fail");
        return HDF_FAILURE;
    }
    attrs->interleaved = (bool)tempRenderPara;

    if (GetInitRenderParaAttrs(data, attrs) < 0) {
        return HDF_FAILURE;
    }

    if (!HdfSbufReadUint32(data, &devDesc->portId)) {
        AUDIO_FUNC_LOGE("read portId fail");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempRenderPara)) {
        AUDIO_FUNC_LOGE("read tempRenderPara fail");
        return HDF_FAILURE;
    }
    devDesc->pins = (enum AudioPortPin)tempRenderPara;
    devDesc->desc = NULL;
    return HDF_SUCCESS;
}

int32_t HdiServiceCreatRender(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    IF_TRUE_PRINT_LOG_RETURN_ERROR((client == NULL || data == NULL || reply == NULL),
        "client or data or reply is null!", AUDIO_HAL_ERR_INVALID_PARAM);
    struct AudioAdapter *adapter = NULL;
    struct AudioDeviceDescriptor devDesc;
    struct AudioSampleAttributes attrs;
    struct AudioRender *render = NULL;
    const char *adapterName = NULL;
    uint32_t renderPid = 0;
    IF_TRUE_PRINT_LOG_RETURN_ERROR(((adapterName = HdfSbufReadString(data)) == NULL),
        "adapterNameCase Is NULL", AUDIO_HAL_ERR_INVALID_PARAM);
    IF_TRUE_PRINT_LOG_RETURN_ERROR((!HdfSbufReadUint32(data, &renderPid)),
        "read renderPid fail", AUDIO_HAL_ERR_INTERNAL);
    int32_t ret = GetInitRenderPara(data, &devDesc, &attrs);
    IF_TRUE_PRINT_LOG_RETURN_ERROR((ret < 0), "GetInitRenderPara fail", AUDIO_HAL_ERR_INTERNAL);
    ret = AudioAdapterListGetAdapter(adapterName, &adapter);
    IF_TRUE_PRINT_LOG_RETURN_ERROR((ret < 0), "AudioAdapterListGetAdapter fail", AUDIO_HAL_ERR_INTERNAL);
    IF_TRUE_PRINT_LOG_RETURN_ERROR((adapter == NULL), "adapter is NULL!", AUDIO_HAL_ERR_INVALID_PARAM);
    const int32_t priority = attrs.type;
    ret = AudioCreatRenderCheck(adapterName, priority);
    IF_TRUE_PRINT_LOG_RETURN_ERROR((ret < 0), "AudioCreatRenderCheck: Render is working can not replace!", ret);
    IF_TRUE_PRINT_LOG_RETURN_ERROR((adapter->CreateRender == NULL), "CreateRender is NULL", AUDIO_HAL_ERR_INTERNAL);
    ret = adapter->CreateRender(adapter, &devDesc, &attrs, &render);
    IF_TRUE_PRINT_LOG_RETURN_ERROR((render == NULL || ret < 0), "Failed to CreateRender", AUDIO_HAL_ERR_INTERNAL);
    if (AudioAddRenderInfoInAdapter(adapterName, render, adapter, priority, renderPid)) {
        AUDIO_FUNC_LOGE("AudioAddRenderInfoInAdapter");
        adapter->DestroyRender(adapter, render);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    OsalMutexInit(&g_renderLock);
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderDestory(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioAdapter *adapter = NULL;
    struct AudioRender *render = NULL;
    const char *adapterName = NULL;
    uint32_t pid = 0;

    OsalMutexDestroy(&g_renderLock);
    if (HdiServiceRenderCaptureReadData(data, &adapterName, &pid) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
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
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (adapter->DestroyRender == NULL) {
        AUDIO_FUNC_LOGE("DestroyRender is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = adapter->DestroyRender(adapter, render);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("DestroyRender failed!");
        return ret;
    }
    if (AudioDestroyRenderInfoInAdapter(adapterName) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderStart(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->control.Start == NULL) {
        AUDIO_FUNC_LOGE("render or Start is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->control.Start((AudioHandle)render);
}

int32_t HdiServiceRenderStop(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->control.Stop == NULL) {
        AUDIO_FUNC_LOGE("render or Stop is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->control.Stop((AudioHandle)render);
}

int32_t HdiServiceRenderPause(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->control.Pause == NULL) {
        AUDIO_FUNC_LOGE("render or Pause is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->control.Pause((AudioHandle)render);
}

int32_t HdiServiceRenderResume(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->control.Resume == NULL) {
        AUDIO_FUNC_LOGE("render or Resume is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->control.Resume((AudioHandle)render);
}

int32_t HdiServiceRenderFlush(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("The parameter is empty");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->control.Flush == NULL) {
        AUDIO_FUNC_LOGE("render or Flush is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->control.Flush((AudioHandle)render);
}

int32_t HdiServiceRenderGetFrameSize(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint64_t size;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->attr.GetFrameSize == NULL) {
        AUDIO_FUNC_LOGE("render or GetFrameSize is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (render->attr.GetFrameSize((AudioHandle)render, &size)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteUint64(reply, size)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderGetFrameCount(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("client or data or reply is NULL!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint64_t count;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->attr.GetFrameCount == NULL) {
        AUDIO_FUNC_LOGE("render or GetFrameCount is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (render->attr.GetFrameCount((AudioHandle)render, &count)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteUint64(reply, count)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderSetSampleAttr(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int ret;
    struct AudioSampleAttributes attrs;
    struct AudioRender *render = NULL;
    ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (ReadAudioSapmleAttrbutes(data, &attrs) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (render == NULL || render->attr.SetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("render or SetSampleAttributes is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->attr.SetSampleAttributes((AudioHandle)render, &attrs);
}

int32_t HdiServiceRenderGetSampleAttr(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioSampleAttributes attrs;
    struct AudioRender *render = NULL;
    int32_t ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->attr.GetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("render or GetSampleAttributes is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->attr.GetSampleAttributes((AudioHandle)render, &attrs);
    if (ret < 0) {
        return ret;
    }
    if (WriteAudioSampleAttributes(reply, &attrs) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderGetCurChannelId(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t channelId;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->attr.GetCurrentChannelId == NULL) {
        AUDIO_FUNC_LOGE("render or GetCurrentChannelId is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->attr.GetCurrentChannelId((AudioHandle)render, &channelId);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufWriteUint32(reply, channelId)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderCheckSceneCapability(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t temporaryPins = 0;
    struct AudioSceneDescriptor scene;
    bool supported = false;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &scene.scene.id)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufReadUint32(data, &temporaryPins)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    scene.desc.pins = (enum AudioPortPin)temporaryPins;
    if (render == NULL || render->scene.CheckSceneCapability == NULL) {
        AUDIO_FUNC_LOGE("render or CheckSceneCapability is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->scene.CheckSceneCapability((AudioHandle)render, &scene, &supported);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempSupported = (uint32_t)supported;
    if (!HdfSbufWriteUint32(reply, tempSupported)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderSelectScene(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t tempPins = 0;
    struct AudioSceneDescriptor scene;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &scene.scene.id)) {
        AUDIO_FUNC_LOGI("Read id Fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufReadUint32(data, &tempPins)) {
        AUDIO_FUNC_LOGI("Read tempPins Fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    scene.desc.pins = (enum AudioPortPin)tempPins;
    if (render == NULL || render->scene.SelectScene == NULL) {
        AUDIO_FUNC_LOGE("render or SelectScene is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->scene.SelectScene((AudioHandle)render, &scene);
}

int32_t HdiServiceRenderGetMute(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGI("parameter is empty");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    bool mute = false;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->volume.GetMute == NULL) {
        AUDIO_FUNC_LOGE("render or GetMute is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->volume.GetMute((AudioHandle)render, &mute);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMute = (uint32_t)mute;
    if (!HdfSbufWriteUint32(reply, tempMute)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderSetMute(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    bool mute = false;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMute = 0;
    if (!HdfSbufReadUint32(data, &tempMute)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    mute = (bool)tempMute;
    if (render == NULL || render->volume.SetMute == NULL) {
        AUDIO_FUNC_LOGE("render or SetMute is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->volume.SetMute((AudioHandle)render, mute);
}

int32_t HdiServiceRenderSetVolume(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t volume = 0;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &volume)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    float setVolume = (float)volume / VOLUME_CHANGE;
    if (render == NULL || render->volume.SetVolume == NULL) {
        AUDIO_FUNC_LOGE("render or SetVolume is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->volume.SetVolume((AudioHandle)render, setVolume);
}

int32_t HdiServiceRenderGetVolume(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    float volume;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->volume.GetVolume == NULL) {
        AUDIO_FUNC_LOGE("render or GetVolume is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->volume.GetVolume((AudioHandle)render, &volume);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempVolume = (uint32_t)(volume * VOLUME_CHANGE);
    if (!HdfSbufWriteUint32(reply, tempVolume)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderGetGainThreshold(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    float min, max;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->volume.GetGainThreshold == NULL) {
        AUDIO_FUNC_LOGE("render or GetGainThreshold is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->volume.GetGainThreshold((AudioHandle)render, &min, &max);
    if (ret < 0) {
        return ret;
    }
    uint32_t temporaryMin = (uint32_t)min;
    if (!HdfSbufWriteUint32(reply, temporaryMin)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    uint32_t temporaryMax = (uint32_t)max;
    if (!HdfSbufWriteUint32(reply, temporaryMax)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderGetGain(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    float gain;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->volume.GetGain == NULL) {
        AUDIO_FUNC_LOGE("render or GetGain is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->volume.GetGain((AudioHandle)render, &gain);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempGain = (uint32_t)gain;
    if (!HdfSbufWriteUint32(reply, tempGain)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderSetGain(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t tempGain = 0;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint32(data, &tempGain)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (render == NULL || render->volume.SetGain == NULL) {
        AUDIO_FUNC_LOGE("render or SetGain is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->volume.SetGain((AudioHandle)render, (float)tempGain);
}

int32_t HdiServiceRenderGetLatency(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint32_t ms;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->GetLatency == NULL) {
        AUDIO_FUNC_LOGE("render or GetLatency is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->GetLatency((AudioHandle)render, &ms);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufWriteUint32(reply, ms)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderRenderFrame(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    char *frame = NULL;
    uint32_t requestBytes = 0;
    uint64_t replyBytes = 0;
    struct AudioRender *render = NULL;
    const char *adapterName = NULL;
    uint32_t pid = 0;
    if (HdiServiceRenderCaptureReadData(data, &adapterName, &pid) < 0) {
        AUDIO_FUNC_LOGE("HdiServiceRenderCaptureReadData fail!");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAdapterListGetRender(adapterName, &render, pid);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioAdapterListGetRender fail");
        return ret;
    }
    ret = AudioGetRenderStatus(adapterName);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioGetRenderStatus fail");
        return ret;
    }
    if (!HdfSbufReadBuffer(data, (const void **)&frame, &requestBytes)) {
        AUDIO_FUNC_LOGE("AudioAdapterListGetRender:HdfSbufReadBuffer fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioSetRenderStatus(adapterName, true);
    (void)OsalMutexLock(&g_renderLock);
    if (render == NULL || render->RenderFrame == NULL) {
        AUDIO_FUNC_LOGE("render or RenderFrame is NULL");
        (void)OsalMutexUnlock(&g_renderLock);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->RenderFrame((AudioHandle)render, (const void *)frame, (uint64_t)requestBytes, &replyBytes);
    (void)OsalMutexUnlock(&g_renderLock);
    AudioSetRenderStatus(adapterName, false);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("HdiServiceRenderRenderFrame fail");
        return ret;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderGetRenderPosition(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioTimeStamp time;
    struct AudioRender *render = NULL;
    uint64_t frames;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    (void)OsalMutexLock(&g_renderLock);
    if (render == NULL || render->GetRenderPosition == NULL) {
        AUDIO_FUNC_LOGE("render or GetRenderPosition is NULL");
        (void)OsalMutexUnlock(&g_renderLock);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->GetRenderPosition((AudioHandle)render, &frames, &time);
    (void)OsalMutexUnlock(&g_renderLock);
    if (ret < 0) {
        return ret;
    }
    ret = HdiServicePositionWrite(reply, frames, time);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderGetSpeed(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    float speed;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->GetRenderSpeed == NULL) {
        AUDIO_FUNC_LOGE("render or GetRenderSpeed is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->GetRenderSpeed((AudioHandle)render, &speed);
    if (ret < 0) {
        return ret;
    }
    uint64_t tempSpeed = (uint64_t)speed;
    if (!HdfSbufWriteUint64(reply, tempSpeed)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderSetSpeed(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint64_t speed = 0;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadUint64(data, &speed)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (render == NULL || render->SetRenderSpeed == NULL) {
        AUDIO_FUNC_LOGE("render or SetRenderSpeed is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->SetRenderSpeed((AudioHandle)render, (float)speed);
}

int32_t HdiServiceRenderSetChannelMode(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    enum AudioChannelMode mode;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("AudioAdapterListCheckAndGetRender failed.");
        return ret;
    }
    uint32_t tempMode = 0;
    if (!HdfSbufReadUint32(data, &tempMode)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    mode = (enum AudioChannelMode)tempMode;
    if (render == NULL || render->SetChannelMode == NULL) {
        AUDIO_FUNC_LOGE("render or SetChannelMode is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->SetChannelMode((AudioHandle)render, mode);
}

int32_t HdiServiceRenderGetChannelMode(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    enum AudioChannelMode mode;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CheckAndGetRender failed.");
        return ret;
    }
    if (render == NULL || render->GetChannelMode == NULL) {
        AUDIO_FUNC_LOGE("render or GetChannelMode is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->GetChannelMode((AudioHandle)render, &mode);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMode = (uint32_t)mode;
    if (!HdfSbufWriteUint32(reply, tempMode)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderSetExtraParams(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int32_t ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    const char *keyValueList = NULL;
    if ((keyValueList = HdfSbufReadString(data)) == NULL) {
        AUDIO_FUNC_LOGE("keyValueList Is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (render == NULL || render->attr.SetExtraParams == NULL) {
        AUDIO_FUNC_LOGE("render or SetExtraParams is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->attr.SetExtraParams((AudioHandle)render, keyValueList);
}

int32_t HdiServiceRenderGetExtraParams(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t listLenth = 0;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadInt32(data, &listLenth)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (listLenth <= 0 || listLenth > STR_MAX - 1) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    char keyValueList[STR_MAX] = { 0 };
    if (render == NULL || render->attr.GetExtraParams == NULL) {
        AUDIO_FUNC_LOGE("render or GetExtraParams is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->attr.GetExtraParams((AudioHandle)render, keyValueList, listLenth);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufWriteString(reply, keyValueList)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderReqMmapBuffer(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioMmapBufferDescriptor desc;
    int32_t reqSize = 0;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadInt32(data, &reqSize)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (HdiServiceReqMmapBuffer(&desc, data) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (render == NULL || render->attr.ReqMmapBuffer == NULL) {
        AUDIO_FUNC_LOGE("render or ReqMmapBuffer is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->attr.ReqMmapBuffer((AudioHandle)render, reqSize, &desc);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("ReqMmapBuffer fail");
        return ret;
    }

    if (!HdfSbufWriteFileDescriptor(reply, desc.memoryFd)) {
        AUDIO_FUNC_LOGE("memoryFd write fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteInt32(reply, desc.totalBufferFrames)) {
        AUDIO_FUNC_LOGE("totalBufferFrames write fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteInt32(reply, desc.transferFrameSize)) {
        AUDIO_FUNC_LOGE("transferFrameSize write fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteInt32(reply, desc.isShareable)) {
        AUDIO_FUNC_LOGE("isShareable write fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }

    if (!HdfSbufWriteUint32(reply, desc.offset)) {
        AUDIO_FUNC_LOGE("offset write fail");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderGetMmapPosition(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    AUDIO_FUNC_LOGD("enter");
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    uint64_t frames;
    struct AudioTimeStamp time;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->attr.GetMmapPosition == NULL) {
        AUDIO_FUNC_LOGE("render or GetMmapPosition is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = render->attr.GetMmapPosition((AudioHandle)render, &frames, &time);
    if (ret < 0) {
        return ret;
    }
    if (HdiServicePositionWrite(reply, frames, time) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AUDIO_FUNC_LOGD("out");
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceRenderAddEffect(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)reply;
    uint64_t effectid = 0;
    struct AudioRender *render = NULL;
    if (data == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    int32_t ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0 || render == NULL) {
        AUDIO_FUNC_LOGE("render is null or ret = %{public}d", ret);
        return ret;
    }

    if (!HdfSbufReadUint64(data, &effectid)) {
        AUDIO_FUNC_LOGE("HdfSbufReadUint64 failed.");
        return HDF_FAILURE;
    }

    if (render->attr.AddAudioEffect == NULL) {
        AUDIO_FUNC_LOGE("AddAudioEffect is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->attr.AddAudioEffect((AudioHandle)render, effectid);
}

int32_t HdiServiceRenderRemoveEffect(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    (void)client;
    (void)reply;
    uint64_t effectid = 0;
    if (data == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }

    struct AudioRender *render = NULL;
    int32_t ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0 || render == NULL) {
        AUDIO_FUNC_LOGE("render is NULL or ret = %{public}d", ret);
        return ret;
    }

    if (!HdfSbufReadUint64(data, &effectid)) {
        AUDIO_FUNC_LOGE("read buf fail ");
        return HDF_FAILURE;
    }

    if (render->attr.RemoveAudioEffect == NULL) {
        AUDIO_FUNC_LOGE("RemoveAudioEffect is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->attr.RemoveAudioEffect((AudioHandle)render, effectid);
}

int32_t HdiServiceRenderTurnStandbyMode(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (render == NULL || render->control.Stop == NULL) {
        AUDIO_FUNC_LOGE("render or Stop is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->control.Stop((AudioHandle)render);
}

int32_t HdiServiceRenderDevDump(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t range = 0;
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    if (!HdfSbufReadInt32(data, &range)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = HdfSbufReadFileDescriptor(data);
    if (ret < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t fd = ret;
    if (render == NULL || render->control.AudioDevDump == NULL) {
        AUDIO_FUNC_LOGE("render or AudioDevDump is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->control.AudioDevDump((AudioHandle)render, range, fd);
}

int32_t HdiServiceRenderRegCallback(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    void *cookie;
    RenderCallback pCallback;
    uint64_t tempAddr = 0;
    if (!HdfSbufReadUint64(data, &tempAddr)) {
        AUDIO_FUNC_LOGE("read cookie Is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    cookie = (void *)(uintptr_t)tempAddr;
    if (!HdfSbufReadUint64(data, &tempAddr)) {
        AUDIO_FUNC_LOGE("read callback pointer Is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    pCallback = (RenderCallback)(uintptr_t)tempAddr;
    if (render == NULL || render->RegCallback == NULL) {
        AUDIO_FUNC_LOGE("render or RegCallback is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->RegCallback((AudioHandle)render, pCallback, cookie);
}

int32_t HdiServiceRenderDrainBuffer(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == NULL || data == NULL || reply == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioRender *render = NULL;
    int ret = AudioAdapterListCheckAndGetRender(&render, data);
    if (ret < 0) {
        return ret;
    }
    enum AudioDrainNotifyType type;
    uint32_t tempType = 0;
    if (!HdfSbufReadUint32(data, &tempType)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    type = (enum AudioDrainNotifyType)tempType;
    if (render == NULL || render->DrainBuffer == NULL) {
        AUDIO_FUNC_LOGE("render or DrainBuffer is NULL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return render->DrainBuffer((AudioHandle)render, &type);
}

