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

#include "audio_render_vendor.h"

#include <hdf_base.h>
#include <limits.h>
#include "audio_common_vendor.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

struct AudioRenderInfo {
    struct AudioDeviceDescriptor desc;
    struct IAudioRender *render;
    struct AudioHwiRender *hwiRender;
};

struct AudioHwiRenderPriv {
    struct AudioRenderInfo *renderInfos[AUDIO_HW_ADAPTER_NUM_MAX];
    struct IAudioCallback *callback;
    bool isRegCb;
};

static struct AudioHwiRenderPriv g_audioHwiRenderPriv;

static struct AudioHwiRenderPriv *AudioHwiRenderGetPriv(void)
{
    return &g_audioHwiRenderPriv;
}

struct AudioHwiRender *AudioHwiGetHwiRender(const struct IAudioRender *render)
{
    if (render == NULL) {
        AUDIO_FUNC_LOGE("audio render desc null");
        return NULL;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    for (uint32_t i = 0; i < AUDIO_HW_ADAPTER_NUM_MAX; i++) {
        if (priv->renderInfos[i] == NULL) {
            continue;
        }
        for (uint32_t j = 0; j < AUDIO_HW_STREAM_NUM_MAX; j++) {
            if (render == priv->renderInfos[i][j].render) {
                return priv->renderInfos[i][j].hwiRender;
            }
        }
    }

    AUDIO_FUNC_LOGE("audio get render fail");
    return NULL;
}

struct AudioHwiRender *AudioHwiGetHwiRenderByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc)
{
    if (desc == NULL) {
        AUDIO_FUNC_LOGE("audio render get hwiRender fail, desc null");
        return NULL;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX || priv->renderInfos[descIndex] == NULL) {
        AUDIO_FUNC_LOGE("audio render get hwiRender fail, descIndex=%{public}d", descIndex);
        return NULL;
    }

    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((desc->portId == priv->renderInfos[descIndex][i].desc.portId) &&
            (desc->pins == priv->renderInfos[descIndex][i].desc.pins) &&
            (strcmp(desc->desc, priv->renderInfos[descIndex][i].desc.desc) == 0)) {
            return priv->renderInfos[descIndex][i].hwiRender;
        }
    }

    AUDIO_FUNC_LOGE("audio get hwiRender fail");
    return NULL;
}

int32_t AudioHwiGetLatency(struct IAudioRender *render, uint32_t *ms)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(ms, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->GetLatency, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->GetLatency(hwiRender, ms);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio GetLatency fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderFrame(struct IAudioRender *render, const int8_t *frame, uint32_t frameLen, uint64_t *replyBytes)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frame, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(replyBytes, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->RenderFrame, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->RenderFrame(hwiRender, frame, frameLen, replyBytes);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render frame fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiGetRenderPosition(struct IAudioRender *render, uint64_t *frames, struct AudioTimeStamp *time)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->GetRenderPosition, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->GetRenderPosition(hwiRender, frames, (struct AudioHwiTimeStamp *)time);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render, get position fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiSetRenderSpeed(struct IAudioRender *render, float speed)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->SetRenderSpeed, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->SetRenderSpeed(hwiRender, speed);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetRenderSpeed fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiGetRenderSpeed(struct IAudioRender *render, float *speed)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(speed, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->GetRenderSpeed, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->GetRenderSpeed(hwiRender, speed);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetRenderSpeed fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderSetChannelMode(struct IAudioRender *render, enum AudioChannelMode mode)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->SetChannelMode, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->SetChannelMode(hwiRender, (enum AudioHwiChannelMode)mode);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio SetChannelMode fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetChannelMode(struct IAudioRender *render, enum AudioChannelMode *mode)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(mode, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->GetChannelMode, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->GetChannelMode(hwiRender, (enum AudioHwiChannelMode *)mode);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetChannelMode fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t AudioHwiRenderHwiCallback(enum AudioHwiCallbackType type, void *reserved, void *cookie)
{
    CHECK_NULL_PTR_RETURN_VALUE(reserved, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(cookie, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    struct IAudioCallback *cb = priv->callback;
    int32_t ret = cb->RenderCallback(cb, (enum AudioCallbackType)type, reserved, cookie);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render call RenderCallback fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderRegCallback(struct IAudioRender *render, struct IAudioCallback *audioCallback, int8_t cookie)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(audioCallback, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    if (priv->isRegCb) {
        AUDIO_FUNC_LOGI("audio render call RegCallback have registered");
        return HDF_SUCCESS;
    }

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->RegCallback, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->RegCallback(hwiRender, AudioHwiRenderHwiCallback, &cookie);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render call RegCallback fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    priv->callback = audioCallback;
    priv->isRegCb = true;

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderDrainBuffer(struct IAudioRender *render, enum AudioDrainNotifyType *type)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(type, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->DrainBuffer, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->DrainBuffer(hwiRender, (enum AudioHwiDrainNotifyType *)type);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render DrainBuffer fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderIsSupportsDrain(struct IAudioRender *render, bool *support)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(support, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->IsSupportsDrain, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->IsSupportsDrain(hwiRender, support);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render IsSupportsDrain fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderCheckSceneCapability(struct IAudioRender *render, const struct AudioSceneDescriptor *scene,
    bool *supported)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supported, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->scene.CheckSceneCapability, HDF_ERR_INVALID_PARAM);

    struct AudioHwiSceneDescriptor hwiScene;
    (void)memset_s((void *)&hwiScene, sizeof(hwiScene), 0, sizeof(hwiScene));
    int32_t ret = AudioHwiCommonSceneToHwiScene(scene, &hwiScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render scene To hwiScene fail");
        return HDF_FAILURE;
    }

    ret = hwiRender->scene.CheckSceneCapability(hwiRender, &hwiScene, supported);
    OsalMemFree((void *)hwiScene.desc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render CheckSceneCapability fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderSelectScene(struct IAudioRender *render, const struct AudioSceneDescriptor *scene)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->scene.SelectScene, HDF_ERR_INVALID_PARAM);

    struct AudioHwiSceneDescriptor hwiScene;
    (void)memset_s((void *)&hwiScene, sizeof(hwiScene), 0, sizeof(hwiScene));
    int32_t ret = AudioHwiCommonSceneToHwiScene(scene, &hwiScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render scene To hwiScene fail");
        return HDF_FAILURE;
    }

    ret = hwiRender->scene.SelectScene(hwiRender, &hwiScene);
    OsalMemFree((void *)hwiScene.desc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render select scene fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderSetMute(struct IAudioRender *render, bool mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->volume.SetMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->volume.SetMute(hwiRender, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetMute fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetMute(struct IAudioRender *render, bool *mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(mute, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->volume.GetMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->volume.GetMute(hwiRender, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetMute fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderSetVolume(struct IAudioRender *render, float volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->volume.SetVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->volume.SetVolume(hwiRender, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetVolume fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetVolume(struct IAudioRender *render, float *volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(volume, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->volume.GetVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->volume.GetVolume(hwiRender, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetVolume fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetGainThreshold(struct IAudioRender *render, float *min, float *max)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(min, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(max, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->volume.GetGainThreshold, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->volume.GetGainThreshold(hwiRender, min, max);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetGainThreshold fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetGain(struct IAudioRender *render, float *gain)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(gain, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->volume.GetGain, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->volume.GetGain(hwiRender, gain);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetGain fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderSetGain(struct IAudioRender *render, float gain)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->volume.SetGain, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->volume.SetGain(hwiRender, gain);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetGain fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetFrameSize(struct IAudioRender *render, uint64_t *size)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(size, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.GetFrameSize, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.GetFrameSize(hwiRender, size);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetFrameSize fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetFrameCount(struct IAudioRender *render, uint64_t *count)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(count, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.GetFrameCount, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.GetFrameCount(hwiRender, count);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetFrameCount fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderSetSampleAttributes(struct IAudioRender *render, const struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.SetSampleAttributes, HDF_ERR_INVALID_PARAM);

    struct AudioHwiSampleAttributes hwiAttrs;
    (void)memset_s((void *)&hwiAttrs, sizeof(hwiAttrs), 0, sizeof(hwiAttrs));
    int32_t ret = AudioHwiCommonSampleAttrToHwiSampleAttr(attrs, &hwiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SampleAttr to hwisampleAttr fail, ret=%{pubilc}d", ret);
        return ret;
    }

    ret = hwiRender->attr.SetSampleAttributes(hwiRender, &hwiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetSampleAttributes fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetSampleAttributes(struct IAudioRender *render, struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.GetSampleAttributes, HDF_ERR_INVALID_PARAM);

    struct AudioHwiSampleAttributes hwiAttrs;
    (void)memset_s((void *)&hwiAttrs, sizeof(hwiAttrs), 0, sizeof(hwiAttrs));
    int32_t ret = hwiRender->attr.GetSampleAttributes(hwiRender, &hwiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetSampleAttributes fail, ret=%{pubilc}d", ret);
        return ret;
    }

    ret = AudioHwiCommonHwiSampleAttrToSampleAttr(&hwiAttrs, attrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render hwiSampleAttr to SampleAttr fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetCurrentChannelId(struct IAudioRender *render, uint32_t *channelId)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(channelId, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.GetCurrentChannelId, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.GetCurrentChannelId(hwiRender, channelId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetCurrentChannelId fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderSetExtraParams(struct IAudioRender *render, const char *keyValueList)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(keyValueList, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.SetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.SetExtraParams(hwiRender, keyValueList);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetExtraParams fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetExtraParams(struct IAudioRender *render, char *keyValueList, uint32_t keyValueListLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(keyValueList, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.GetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.GetExtraParams(hwiRender, keyValueList, keyValueListLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetExtraParams fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderReqMmapBuffer(struct IAudioRender *render, int32_t reqSize,
    struct AudioMmapBufferDescriptor *desc)
{
    return HDF_ERR_NOT_SUPPORT;
}

int32_t AudioHwiRenderGetMmapPosition(struct IAudioRender *render, uint64_t *frames, struct AudioTimeStamp *time)
{
    struct AudioHwiTimeStamp hwiTime;
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    hwiTime.tvSec = 0;
    hwiTime.tvNSec = 0;

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.GetMmapPosition, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.GetMmapPosition(hwiRender, frames, &hwiTime);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetMmapPosition fail, ret=%{pubilc}d", ret);
        return ret;
    }

    time->tvSec = hwiTime.tvSec;
    time->tvNSec = hwiTime.tvNSec;

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderAddAudioEffect(struct IAudioRender *render, uint64_t effectid)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.AddAudioEffect, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.AddAudioEffect(hwiRender, effectid);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render AddAudioEffect fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderRemoveAudioEffect(struct IAudioRender *render, uint64_t effectid)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.RemoveAudioEffect, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.RemoveAudioEffect(hwiRender, effectid);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render RemoveAudioEffect fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetFrameBufferSize(struct IAudioRender *render, uint64_t *bufferSize)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(bufferSize, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->attr.GetFrameBufferSize, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->attr.GetFrameBufferSize(hwiRender, bufferSize);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetFrameBufferSize fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderStart(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->control.Start, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->control.Start(hwiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Start fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderStop(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->control.Stop, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->control.Stop(hwiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Stop fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderPause(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->control.Pause, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->control.Pause(hwiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Pause fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderResume(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->control.Resume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->control.Resume(hwiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Resume fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderFlush(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->control.Flush, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->control.Flush(hwiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Flush fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderTurnStandbyMode(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->control.TurnStandbyMode, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->control.TurnStandbyMode(hwiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render TurnStandbyMode fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderAudioDevDump(struct IAudioRender *render, int32_t range, int32_t fd)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->control.AudioDevDump, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->control.AudioDevDump(hwiRender, range, fd);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render AudioDevDump fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderIsSupportsPauseAndResume(struct IAudioRender *render, bool *supportPause, bool *supportResume)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supportPause, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supportResume, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->control.IsSupportsPauseAndResume, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->control.IsSupportsPauseAndResume(hwiRender, supportPause, supportResume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render IsSupportsPauseAndResume fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetVersion(struct IAudioRender *render, uint32_t *majorVer, uint32_t *minorVer)
{
    (void)render;
    CHECK_NULL_PTR_RETURN_VALUE(majorVer, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(minorVer, HDF_ERR_INVALID_PARAM);

    *majorVer = IAUDIO_RENDER_MAJOR_VERSION;
    *minorVer = IAUDIO_RENDER_MINOR_VERSION;

    return HDF_SUCCESS;
}

static void AudioHwiInitRenderInstance(struct IAudioRender *render)
{
    render->GetLatency = AudioHwiGetLatency;
    render->RenderFrame = AudioHwiRenderFrame;
    render->GetRenderPosition = AudioHwiGetRenderPosition;
    render->SetRenderSpeed = AudioHwiSetRenderSpeed;
    render->GetRenderSpeed = AudioHwiGetRenderSpeed;
    render->SetChannelMode = AudioHwiRenderSetChannelMode;
    render->GetChannelMode = AudioHwiRenderGetChannelMode;
    render->RegCallback = AudioHwiRenderRegCallback;
    render->DrainBuffer = AudioHwiRenderDrainBuffer;
    render->IsSupportsDrain = AudioHwiRenderIsSupportsDrain;
    render->CheckSceneCapability = AudioHwiRenderCheckSceneCapability;
    render->SetMute = AudioHwiRenderSetMute;
    render->GetMute = AudioHwiRenderGetMute;
    render->SetVolume = AudioHwiRenderSetVolume;
    render->GetVolume = AudioHwiRenderGetVolume;
    render->GetGainThreshold = AudioHwiRenderGetGainThreshold;
    render->GetGain = AudioHwiRenderGetGain;
    render->SetGain = AudioHwiRenderSetGain;
    render->GetFrameSize = AudioHwiRenderGetFrameSize;
    render->GetFrameCount = AudioHwiRenderGetFrameCount;
    render->SetSampleAttributes = AudioHwiRenderSetSampleAttributes;
    render->GetSampleAttributes = AudioHwiRenderGetSampleAttributes;
    render->GetCurrentChannelId = AudioHwiRenderGetCurrentChannelId;
    render->SetExtraParams = AudioHwiRenderSetExtraParams;
    render->GetExtraParams = AudioHwiRenderGetExtraParams;
    render->ReqMmapBuffer = AudioHwiRenderReqMmapBuffer;
    render->GetMmapPosition = AudioHwiRenderGetMmapPosition;
    render->AddAudioEffect = AudioHwiRenderAddAudioEffect;
    render->RemoveAudioEffect = AudioHwiRenderRemoveAudioEffect;
    render->GetFrameBufferSize = AudioHwiRenderGetFrameBufferSize;
    render->Start = AudioHwiRenderStart;
    render->Stop = AudioHwiRenderStop;
    render->Pause = AudioHwiRenderPause;
    render->Resume = AudioHwiRenderResume;
    render->Flush = AudioHwiRenderFlush;
    render->TurnStandbyMode = AudioHwiRenderTurnStandbyMode;
    render->AudioDevDump = AudioHwiRenderAudioDevDump;
    render->IsSupportsPauseAndResume = AudioHwiRenderIsSupportsPauseAndResume;
    render->GetVersion = AudioHwiRenderGetVersion;
}

int32_t AudioHwiRenderInit(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender init fail, descIndex=%{public}d", descIndex);
        return HDF_ERR_INVALID_PARAM;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    if (priv->renderInfos[descIndex] != NULL) {
        AUDIO_FUNC_LOGW("audio HwiRender renderInfos already init");
        return HDF_SUCCESS;
    }

    priv->renderInfos[descIndex] =
        (struct AudioRenderInfo *)OsalMemCalloc(sizeof(struct AudioRenderInfo) * AUDIO_HW_STREAM_NUM_MAX);
    if (priv->renderInfos[descIndex] == NULL) {
        AUDIO_FUNC_LOGE("audio HwiRender malloc renderInfos fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    return HDF_SUCCESS;
}

void AudioHwiRenderDeinit(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender deinit fail, descIndex=%{public}d", descIndex);
        return;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();

    OsalMemFree((void *)priv->renderInfos[descIndex]);
    priv->renderInfos[descIndex] = NULL;
    priv->isRegCb = false;
    priv->callback = NULL;
}

struct IAudioRender *AudioHwiCreateRenderByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc,
    struct AudioHwiRender *hwiRender)
{
    if (desc == NULL || hwiRender == NULL) {
        AUDIO_FUNC_LOGE("audio render is null");
        return NULL;
    }

    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender create render index fail, descIndex=%{public}d", descIndex);
        return NULL;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    struct AudioRenderInfo *infos = priv->renderInfos[descIndex];
    if (infos == NULL) {
        AUDIO_FUNC_LOGE("audio hwiRender render not init");
        return NULL;
    }

    uint32_t nullRenderIndex = AUDIO_HW_STREAM_NUM_MAX;
    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((infos[i].render != NULL) && (desc->portId == infos[i].desc.portId) && (desc->pins == infos[i].desc.pins) &&
            (strcmp(desc->desc, infos[i].desc.desc) == 0)) {
            return infos[i].render;
        }

        if ((infos[i].render == NULL) && (nullRenderIndex == AUDIO_HW_STREAM_NUM_MAX)) {
            nullRenderIndex = i;
        }
    }

    if (nullRenderIndex == AUDIO_HW_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender render not space");
        return NULL;
    }

    struct IAudioRender *render = (struct IAudioRender *)OsalMemCalloc(sizeof(struct IAudioRender));
    if (render == NULL) {
        AUDIO_FUNC_LOGE("audio hwiRender render malloc fail");
        return NULL;
    }
    infos[nullRenderIndex].render = render;
    infos[nullRenderIndex].hwiRender = hwiRender;
    infos[nullRenderIndex].desc.portId = desc->portId;
    infos[nullRenderIndex].desc.pins = desc->pins;
    infos[nullRenderIndex].desc.desc = strdup(desc->desc);
    AudioHwiInitRenderInstance(render);

    AUDIO_FUNC_LOGI("audio create adapter success");
    return render;
};

void AudioHwiDestroyRenderByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc)
{
    CHECK_NULL_PTR_RETURN(desc);

    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender destroy render index fail, descIndex=%{public}d", descIndex);
        return;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    struct AudioRenderInfo *infos = priv->renderInfos[descIndex];
    CHECK_NULL_PTR_RETURN(infos);

    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((infos[i].render != NULL) && (desc->portId == infos[i].desc.portId) && (desc->pins == infos[i].desc.pins) &&
            (strcmp(desc->desc, infos[i].desc.desc) == 0)) {
            OsalMemFree((void *)infos[i].render);
            OsalMemFree((void *)infos[i].desc.desc);
            infos[i].render = NULL;
            infos[i].hwiRender = NULL;
            infos[i].desc.desc = NULL;
            infos[i].desc.portId = UINT_MAX;
            infos[i].desc.pins = PIN_NONE;
            return;
        }
    }
    AUDIO_FUNC_LOGE("audio hwiRender not destroy render by desc");
}
