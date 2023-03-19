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

#include "audio_capture_vendor.h"

#include <hdf_base.h>
#include <limits.h>
#include "audio_common_vendor.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

struct AudioCaptureInfo {
    struct AudioDeviceDescriptor desc;
    enum AudioCategory streamType;
    struct IAudioCapture *capture;
    struct AudioHwiCapture *hwiCapture;
};

struct AudioHwiCapturePriv {
    struct AudioCaptureInfo *captureInfos[AUDIO_HW_ADAPTER_NUM_MAX];
    uint32_t captureCnt;
};

static struct AudioHwiCapturePriv g_audioHwiCapturePriv;

static struct AudioHwiCapturePriv *AudioHwiCaptureGetPriv(void)
{
    return &g_audioHwiCapturePriv;
}

struct AudioHwiCapture *AudioHwiGetHwiCapture(struct IAudioCapture *capture)
{
    if (capture == NULL) {
        AUDIO_FUNC_LOGE("audio HwiCapture get HwiCapture fail, capture null");
        return NULL;
    }

    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();

    for (uint32_t i = 0; i < AUDIO_HW_ADAPTER_NUM_MAX; i++) {
        if (priv->captureInfos[i] == NULL) {
            continue;
        }
        for (uint32_t j = 0; j < AUDIO_HW_STREAM_NUM_MAX; j++) {
            if (capture == priv->captureInfos[i][j].capture) {
                return priv->captureInfos[i][j].hwiCapture;
            }
        }
    }

    AUDIO_FUNC_LOGE("audio get capture fail");
    return NULL;
}

struct AudioHwiCapture *AudioHwiGetHwiCaptureById(uint32_t captureId)
{
    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();
    if (priv->captureInfos[captureId] == NULL) {
        AUDIO_FUNC_LOGE("not match capture");
        return NULL;
    }

    return priv->captureInfos[captureId]->hwiCapture;
}

int32_t AudioHwiCaptureFrame(struct IAudioCapture *capture, int8_t *frame, uint32_t *frameLen, uint64_t *replyBytes)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frame, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frameLen, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(replyBytes, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->CaptureFrame, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->CaptureFrame(hwiCapture, frame, *frameLen, replyBytes);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture frame fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiGetCapturePosition(struct IAudioCapture *capture, uint64_t *frames, struct AudioTimeStamp *time)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->GetCapturePosition, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->GetCapturePosition(hwiCapture, frames, (struct AudioHwiTimeStamp *)time);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture get position fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureCheckSceneCapability(struct IAudioCapture *capture, const struct AudioSceneDescriptor* scene,
    bool* supported)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supported, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->scene.CheckSceneCapability, HDF_ERR_INVALID_PARAM);

    struct AudioHwiSceneDescriptor hwiScene;
    (void)memset_s((void *)&hwiScene, sizeof(hwiScene), 0, sizeof(hwiScene));
    int32_t ret = AudioHwiCommonSceneToHwiScene(scene, &hwiScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture scene To hwiScene fail");
        return HDF_FAILURE;
    }

    ret = hwiCapture->scene.CheckSceneCapability(hwiCapture, &hwiScene, supported);
    OsalMemFree((void *)hwiScene.desc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture CheckSceneCapability fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureSelectScene(struct IAudioCapture *capture, const struct AudioSceneDescriptor* scene)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->scene.SelectScene, HDF_ERR_INVALID_PARAM);

    struct AudioHwiSceneDescriptor hwiScene;
    (void)memset_s((void *)&hwiScene, sizeof(hwiScene), 0, sizeof(hwiScene));
    int32_t ret = AudioHwiCommonSceneToHwiScene(scene, &hwiScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter scene To hwiScene fail");
        return HDF_FAILURE;
    }

    ret = hwiCapture->scene.SelectScene(hwiCapture, &hwiScene);
    OsalMemFree((void *)hwiScene.desc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture select scene fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureSetMute(struct IAudioCapture *capture, bool mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->volume.SetMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->volume.SetMute(hwiCapture, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetMute fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetMute(struct IAudioCapture *capture, bool *mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(mute, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->volume.GetMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->volume.GetMute(hwiCapture, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetMute fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureSetVolume(struct IAudioCapture *capture, float volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->volume.SetVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->volume.SetVolume(hwiCapture, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetVolume fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetVolume(struct IAudioCapture *capture, float *volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(volume, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->volume.GetVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->volume.GetVolume(hwiCapture, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetVolume fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetGainThreshold(struct IAudioCapture *capture, float *min, float *max)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(min, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(max, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->volume.GetGainThreshold, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->volume.GetGainThreshold(hwiCapture, min, max);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetGainThreshold fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetGain(struct IAudioCapture *capture, float *gain)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(gain, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->volume.GetGain, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->volume.GetGain(hwiCapture, gain);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetGain fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureSetGain(struct IAudioCapture *capture, float gain)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->volume.SetGain, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->volume.SetGain(hwiCapture, gain);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetGain fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetFrameSize(struct IAudioCapture *capture, uint64_t *size)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(size, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.GetFrameSize, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.GetFrameSize(hwiCapture, size);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetFrameSize fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetFrameCount(struct IAudioCapture *capture, uint64_t *count)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(count, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.GetFrameCount, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.GetFrameCount(hwiCapture, count);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetFrameCount fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureSetSampleAttributes(struct IAudioCapture *capture, const struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.SetSampleAttributes, HDF_ERR_INVALID_PARAM);

    struct AudioHwiSampleAttributes hwiAttrs;
    (void)memset_s((void *)&hwiAttrs, sizeof(hwiAttrs), 0, sizeof(hwiAttrs));
    int32_t ret = AudioHwiCommonSampleAttrToHwiSampleAttr(attrs, &hwiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SampleAttr to hwisampleAttr fail, ret=%{pubilc}d", ret);
        return ret;
    }

    ret = hwiCapture->attr.SetSampleAttributes(hwiCapture, &hwiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetSampleAttributes fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetSampleAttributes(struct IAudioCapture *capture, struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.GetSampleAttributes, HDF_ERR_INVALID_PARAM);

    struct AudioHwiSampleAttributes hwiAttrs;
    (void)memset_s((void *)&hwiAttrs, sizeof(hwiAttrs), 0, sizeof(hwiAttrs));
    int32_t ret = hwiCapture->attr.GetSampleAttributes(hwiCapture, &hwiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetSampleAttributes fail, ret=%{pubilc}d", ret);
        return ret;
    }

    ret = AudioHwiCommonHwiSampleAttrToSampleAttr(&hwiAttrs, attrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture hwiSampleAttr to SampleAttr fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetCurrentChannelId(struct IAudioCapture *capture, uint32_t *channelId)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(channelId, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.GetCurrentChannelId, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.GetCurrentChannelId(hwiCapture, channelId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetCurrentChannelId fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureSetExtraParams(struct IAudioCapture *capture, const char *keyValueList)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(keyValueList, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.SetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.SetExtraParams(hwiCapture, keyValueList);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture SetExtraParams fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetExtraParams(struct IAudioCapture *capture, char *keyValueList, uint32_t keyValueListLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(keyValueList, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.GetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.GetExtraParams(hwiCapture, keyValueList, keyValueListLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetExtraParams fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureReqMmapBuffer(struct IAudioCapture *capture, int32_t reqSize,
    struct AudioMmapBufferDescriptor *desc)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioHwiCaptureGetMmapPosition(struct IAudioCapture *capture, uint64_t *frames, struct AudioTimeStamp *time)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    struct AudioHwiTimeStamp hwiTime;
    hwiTime.tvSec = 0;
    hwiTime.tvNSec = 0;

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.GetMmapPosition, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.GetMmapPosition(hwiCapture, frames, &hwiTime);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetMmapPosition fail, ret=%{pubilc}d", ret);
        return ret;
    }

    time->tvSec = hwiTime.tvSec;
    time->tvNSec = hwiTime.tvNSec;

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureAddAudioEffect(struct IAudioCapture *capture, uint64_t effectid)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.AddAudioEffect, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.AddAudioEffect(hwiCapture, effectid);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture AddAudioEffect fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureRemoveAudioEffect(struct IAudioCapture *capture, uint64_t effectid)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.RemoveAudioEffect, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.RemoveAudioEffect(hwiCapture, effectid);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture RemoveAudioEffect fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetFrameBufferSize(struct IAudioCapture *capture, uint64_t *bufferSize)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(bufferSize, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->attr.GetFrameBufferSize, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->attr.GetFrameBufferSize(hwiCapture, bufferSize);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture GetFrameBufferSize fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureStart(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->control.Start, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->control.Start(hwiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Start fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureStop(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->control.Stop, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->control.Stop(hwiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Stop fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCapturePause(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->control.Pause, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->control.Pause(hwiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Pause fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureResume(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->control.Resume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->control.Resume(hwiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Resume fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureFlush(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->control.Flush, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->control.Flush(hwiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture Flush fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureTurnStandbyMode(struct IAudioCapture *capture)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->control.TurnStandbyMode, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->control.TurnStandbyMode(hwiCapture);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture TurnStandbyMode fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureAudioDevDump(struct IAudioCapture *capture, int32_t range, int32_t fd)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->control.AudioDevDump, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->control.AudioDevDump(hwiCapture, range, fd);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture AudioDevDump fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureIsSupportsPauseAndResume(struct IAudioCapture *capture, bool *supportPause, bool *supportResume)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supportPause, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supportResume, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->control.IsSupportsPauseAndResume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->control.IsSupportsPauseAndResume(hwiCapture, supportPause, supportResume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture IsSupportsPauseAndResume fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetVersion(struct IAudioCapture *capture, uint32_t *majorVer, uint32_t *minorVer)
{
    (void)capture;
    CHECK_NULL_PTR_RETURN_VALUE(majorVer, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(minorVer, HDF_ERR_INVALID_PARAM);

    *majorVer = IAUDIO_CAPTURE_MAJOR_VERSION;
    *minorVer = IAUDIO_CAPTURE_MINOR_VERSION;

    return HDF_SUCCESS;
}

static void AudioHwiInitCaptureInstance(struct IAudioCapture *capture)
{
    capture->CaptureFrame = AudioHwiCaptureFrame;
    capture->GetCapturePosition = AudioHwiGetCapturePosition;
    capture->CheckSceneCapability = AudioHwiCaptureCheckSceneCapability;
    capture->SelectScene = AudioHwiCaptureSelectScene;
    capture->SetMute = AudioHwiCaptureSetMute;
    capture->GetMute = AudioHwiCaptureGetMute;
    capture->SetVolume = AudioHwiCaptureSetVolume;
    capture->GetVolume = AudioHwiCaptureGetVolume;
    capture->GetGainThreshold = AudioHwiCaptureGetGainThreshold;
    capture->GetGain = AudioHwiCaptureGetGain;
    capture->SetGain = AudioHwiCaptureSetGain;
    capture->GetFrameSize = AudioHwiCaptureGetFrameSize;
    capture->GetFrameCount = AudioHwiCaptureGetFrameCount;
    capture->SetSampleAttributes = AudioHwiCaptureSetSampleAttributes;
    capture->GetSampleAttributes = AudioHwiCaptureGetSampleAttributes;
    capture->GetCurrentChannelId = AudioHwiCaptureGetCurrentChannelId;
    capture->SetExtraParams = AudioHwiCaptureSetExtraParams;
    capture->GetExtraParams = AudioHwiCaptureGetExtraParams;
    capture->ReqMmapBuffer = AudioHwiCaptureReqMmapBuffer;
    capture->GetMmapPosition = AudioHwiCaptureGetMmapPosition;
    capture->AddAudioEffect = AudioHwiCaptureAddAudioEffect;
    capture->RemoveAudioEffect = AudioHwiCaptureRemoveAudioEffect;
    capture->GetFrameBufferSize = AudioHwiCaptureGetFrameBufferSize;
    capture->Start = AudioHwiCaptureStart;
    capture->Stop = AudioHwiCaptureStop;
    capture->Pause = AudioHwiCapturePause;
    capture->Resume = AudioHwiCaptureResume;
    capture->Flush = AudioHwiCaptureFlush;
    capture->TurnStandbyMode = AudioHwiCaptureTurnStandbyMode;
    capture->AudioDevDump = AudioHwiCaptureAudioDevDump;
    capture->IsSupportsPauseAndResume = AudioHwiCaptureIsSupportsPauseAndResume;
    capture->GetVersion = AudioHwiCaptureGetVersion;
}

static struct IAudioCapture *FindCaptureCreated(struct AudioHwiCapturePriv *capturePriv, enum AudioPortPin pin,
                                               enum AudioCategory streamType)
{
    uint32_t index = 0;
    if (capturePriv == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return NULL;
    }

    if (capturePriv->captureCnt == 0) {
        AUDIO_FUNC_LOGI("no capture created");
        return NULL;
    }

    for (index = 0; index < AUDIO_HW_STREAM_NUM_MAX; index++) {
        if ((capturePriv->captureInfos[index] != NULL) &&
            (capturePriv->captureInfos[index]->desc.pins == pin) &&
            (capturePriv->captureInfos[index]->streamType == streamType)) {
            return capturePriv->captureInfos[index]->capture;
        }
    }

    return NULL;
}

static uint32_t GetAvailableCaptureId(struct AudioHwiCapturePriv *capturePriv)
{
    uint32_t captureId = AUDIO_HW_STREAM_NUM_MAX;
    uint32_t index = 0;
    if (capturePriv == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return captureId;
    }

    if (capturePriv->captureCnt < AUDIO_HW_STREAM_NUM_MAX) {
        captureId = capturePriv->captureCnt;
        capturePriv->captureCnt++;
    } else {
        for (index = 0; index < AUDIO_HW_STREAM_NUM_MAX; index++) {
            if (capturePriv->captureInfos[index] == NULL) {
                captureId = index;
                break;
            }
        }
    }

    return captureId;
}

struct IAudioCapture *AudioHwiCreateCaptureById(enum AudioCategory streamType, uint32_t *captureId,
    struct AudioHwiCapture *hwiCapture, const struct AudioDeviceDescriptor *desc)
{
    if (captureId == NULL || hwiCapture == NULL || desc == NULL) {
        AUDIO_FUNC_LOGE("audio capture is null");
        return NULL;
    }

    *captureId = AUDIO_HW_STREAM_NUM_MAX;
    struct IAudioCapture *capture = NULL;
    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();
    
    capture = FindCaptureCreated(priv, desc->pins, streamType);
    if (capture != NULL) {
        AUDIO_FUNC_LOGE("already created");
        return capture;
    }

    *captureId = GetAvailableCaptureId(priv);
    if (*captureId >= AUDIO_HW_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwicapture capture capture index fail, captureId=%{public}d", *captureId);
        return NULL;
    }

    priv->captureInfos[*captureId] = (struct AudioCaptureInfo *)OsalMemCalloc(sizeof(struct AudioCaptureInfo));
    if (priv->captureInfos[*captureId] == NULL) {
        AUDIO_FUNC_LOGE("audio Hwicapture malloc captureInfos fail");
        return NULL;
    }

    capture = (struct IAudioCapture *)OsalMemCalloc(sizeof(struct IAudioCapture));
    if (capture == NULL) {
        AUDIO_FUNC_LOGE("audio hwiCapture capture malloc fail");
        return NULL;
    }
    priv->captureInfos[*captureId]->capture = capture;
    priv->captureInfos[*captureId]->hwiCapture = hwiCapture;
    priv->captureInfos[*captureId]->streamType = streamType;
    priv->captureInfos[*captureId]->desc.portId = desc->portId;
    priv->captureInfos[*captureId]->desc.pins = desc->pins;
    priv->captureInfos[*captureId]->desc.desc = strdup(desc->desc);
    AudioHwiInitCaptureInstance(capture);

    AUDIO_FUNC_LOGI("audio captureId capture success");
    return capture;
};

void AudioHwiDestroyCaptureById(uint32_t captureId)
{
    if (captureId >= AUDIO_HW_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiCapture destroy capture index fail, captureId=%{public}d", captureId);
        return;
    }
    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();    
    if (priv->captureInfos[captureId] == NULL) {
        AUDIO_FUNC_LOGE("audio hwiCapture destroy capture index fail, captureId=%{public}d", captureId);
        return;
    }

    OsalMemFree((void *)priv->captureInfos[captureId]->capture);
    OsalMemFree((void *)priv->captureInfos[captureId]->desc.desc);
    priv->captureInfos[captureId]->capture = NULL;
    priv->captureInfos[captureId]->hwiCapture = NULL;
    priv->captureInfos[captureId]->desc.desc = NULL;
    priv->captureInfos[captureId]->desc.portId = UINT_MAX;
    priv->captureInfos[captureId]->desc.pins = PIN_NONE;

    OsalMemFree(priv->captureInfos[captureId]);
    priv->captureInfos[captureId] = NULL;
}