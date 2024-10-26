/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "hdf_audio_server_common.h"
#include "osal_mem.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif

#define LOG_DOMAIN 0xD000105

namespace OHOS::HDI::Audio_Bluetooth {
int32_t GetInitCaptureParaAttrs(struct HdfSBuf *data, struct AudioSampleAttributes *attrs)
{
    if (data == nullptr || attrs == nullptr) {
        return HDF_FAILURE;
    }
    uint32_t tempCapturePara = 0;
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        HDF_LOGE("%{public}s: read tempCapturePara fail", __func__);
        return HDF_FAILURE;
    }
    attrs->type = (AudioCategory)tempCapturePara;
    if (!HdfSbufReadUint32(data, &attrs->period)) {
        HDF_LOGE("%{public}s: read period fail", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->frameSize)) {
        HDF_LOGE("%{public}s: read frameSize fail", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->startThreshold)) {
        HDF_LOGE("%{public}s: read startThreshold fail", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->stopThreshold)) {
        HDF_LOGE("%{public}s: read stopThreshold fail", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->silenceThreshold)) {
        HDF_LOGE("%{public}s: read silenceThreshold fail", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        HDF_LOGE("%{public}s: read bool isBigEndian fail", __func__);
        return HDF_FAILURE;
    }
    attrs->isBigEndian = (bool)tempCapturePara;
    return HDF_SUCCESS;
}

int32_t GetInitCapturePara(struct HdfSBuf *data, struct AudioDeviceDescriptor *devDesc,
    struct AudioSampleAttributes *attrs)
{
    if (data == nullptr || devDesc == nullptr || attrs == nullptr) {
        return HDF_FAILURE;
    }
    uint32_t tempCapturePara = 0;
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        HDF_LOGE("%{public}s: read attrs format fail", __func__);
        return HDF_FAILURE;
    }
    attrs->format = (AudioFormat)tempCapturePara;
    if (!HdfSbufReadUint32(data, &attrs->channelCount)) {
        HDF_LOGE("%{public}s: read channelCount fail", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &attrs->sampleRate)) {
        HDF_LOGE("%{public}s: read sampleRate fail", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        HDF_LOGE("%{public}s: read attrs interleaved fail", __func__);
        return HDF_FAILURE;
    }
    attrs->interleaved = (bool)tempCapturePara;
    if (GetInitCaptureParaAttrs(data, attrs) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        HDF_LOGE("%{public}s: read attrs isSignedData fail", __func__);
        return HDF_FAILURE;
    }
    attrs->isSignedData = (bool)tempCapturePara;
    if (!HdfSbufReadUint32(data, &devDesc->portId)) {
        HDF_LOGE("%{public}s: read portId fail", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &tempCapturePara)) {
        HDF_LOGE("%{public}s: read tempRenderPara fail", __func__);
        return HDF_FAILURE;
    }
    devDesc->pins = (AudioPortPin)tempCapturePara;
    devDesc->desc = nullptr;
    return HDF_SUCCESS;
}

int32_t HdiServiceCreateCapture(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioAdapter *adapter = nullptr;
    struct AudioDeviceDescriptor devDesc;
    struct AudioSampleAttributes attrs;
    struct AudioCapture *capture = nullptr;
    const char *adapterName = nullptr;
    uint32_t capturePid = 0;
    if ((adapterName = HdfSbufReadString(data)) == nullptr) {
        HDF_LOGE("%{public}s: adapterNameCase Is NULL", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(data, &capturePid)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    HDF_LOGE("HdiServiceCreatRender: capturePid = %{public}u", capturePid);
    int32_t ret = GetInitCapturePara(data, &devDesc, &attrs);
    if (ret < 0) {
        HDF_LOGE("%{public}s: GetInitCapturePara fail", __func__);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioAdapterListGetAdapter(adapterName, &adapter)) {
        HDF_LOGE("%{public}s: fail", __func__);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (adapter == nullptr) {
        HDF_LOGE("%{public}s: adapter is NULL!", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    const int32_t priority = attrs.type;
    ret = AudioCreateCaptureCheck(adapterName, priority);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AudioCreateCaptureCheck: Capture is working can not replace!", __func__);
        return ret;
    }
    ret = adapter->CreateCapture(adapter, &devDesc, &attrs, &capture);
    if (capture == nullptr || ret < 0) {
        HDF_LOGE("%{public}s: Failed to CreateCapture", __func__);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (AudioAddCaptureInfoInAdapter(adapterName, capture, adapter, priority, capturePid)) {
        HDF_LOGE("%{public}s: AudioAddCaptureInfoInAdapter", __func__);
        adapter->DestroyCapture(adapter, capture);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureDestory(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    const char *adapterName = nullptr;
    uint32_t pid = 0;
    if (HdiServiceRenderCaptureReadData(data, &adapterName, &pid) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAdapterListGetCapture(adapterName, &capture, pid);
    if (ret < 0) {
        return ret;
    }
    ret = AudioAdapterListGetAdapterCapture(adapterName, &adapter, &capture);
    if (ret < 0) {
        return ret;
    }
    if (adapter == nullptr || capture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    HDF_LOGI("%{public}s: DestroyCapture.", __func__);
    ret = adapter->DestroyCapture(adapter, capture);
    if (ret < 0) {
        HDF_LOGE("%{public}s: DestroyCapture failed!", __func__);
        return ret;
    }
    if (AudioDestroyCaptureInfoInAdapter(adapterName)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    return AUDIO_HAL_SUCCESS;
}

int32_t HdiServiceCaptureStart(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = nullptr;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    return capture->control.Start((AudioHandle)capture);
}

int32_t HdiServiceCaptureStop(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = nullptr;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    return capture->control.Stop((AudioHandle)capture);
}

int32_t HdiServiceCapturePause(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    HDF_LOGE("%{public}s: enter", __func__);
    struct AudioCapture *capture = nullptr;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    return capture->control.Pause((AudioHandle)capture);
}

int32_t HdiServiceCaptureResume(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = nullptr;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    return capture->control.Resume((AudioHandle)capture);
}

int32_t HdiServiceCaptureFlush(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        HDF_LOGI("%{public}s: The parameter is empty", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct AudioCapture *capture = nullptr;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    return capture->control.Flush((AudioHandle)capture);
}

int32_t HdiServiceCaptureGetMute(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        HDF_LOGI("%{public}s: parameter is empty", __func__);
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    bool mute = false;
    struct AudioCapture *capture = nullptr;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    ret = capture->volume.GetMute((AudioHandle)capture, &mute);
    if (ret < 0) {
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
    if (client == nullptr || data == nullptr || reply == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    bool mute = false;
    struct AudioCapture *capture = nullptr;
    int ret = AudioAdapterListCheckAndGetCapture(&capture, data);
    if (ret < 0) {
        return ret;
    }
    uint32_t tempMute = 0;
    if (!HdfSbufReadUint32(data, &tempMute)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    mute = (bool)tempMute;
    return capture->volume.SetMute((AudioHandle)capture, mute);
}

int32_t HdiServiceCaptureCaptureFrame(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (client == nullptr || data == nullptr || reply == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    char *frame = nullptr;
    uint64_t requestBytes;
    uint64_t replyBytes;
    struct AudioCapture *capture = nullptr;
    const char *adapterName = nullptr;
    uint32_t pid;
    uint32_t index = 0;
    if (HdiServiceRenderCaptureReadData(data, &adapterName, &pid) < 0) {
        HDF_LOGE("%{public}s: HdiServiceRenderCaptureReadData fail!", __func__);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioAdapterFrameGetCapture(adapterName, &capture, pid, &index);
    if (ret < 0) {
        HDF_LOGE("%{public}s: AudioAdapterFrameGetCapture fail", __func__);
        return ret;
    }
    if (!HdfSbufReadUint64(data, &requestBytes)) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    frame = (char *)OsalMemCalloc(FRAME_DATA);
    if (frame == nullptr) {
        return AUDIO_HAL_ERR_MALLOC_FAIL;
    }
    AudioSetCaptureBusy(index, true);
    if (capture == nullptr || capture->CaptureFrame == nullptr) {
        HDF_LOGE("capture or capureFrame in NULL");
        AudioMemFree((void **)&frame);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    ret = capture->CaptureFrame(capture, (void *)frame, requestBytes, &replyBytes);
    AudioSetCaptureBusy(index, false);
    if (ret < 0) {
        AudioMemFree((void **)&frame);
        return ret;
    }
    if (!HdfSbufWriteUint64(reply, replyBytes)) {
        AudioMemFree((void **)&frame);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteBuffer(reply, (const void *)frame, replyBytes)) {
        AudioMemFree((void **)&frame);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioMemFree(reinterpret_cast<void **>(&frame));
    return AUDIO_HAL_SUCCESS;
}

}