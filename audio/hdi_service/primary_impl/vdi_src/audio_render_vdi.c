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

#include "audio_render_vdi.h"

#include <limits.h>
#include <hdf_base.h>
#include "audio_uhdf_log.h"
#include "osal_mem.h"
#include "securec.h"
#include "audio_common_vdi.h"
#include "audio_trace_vdi.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

struct AudioRenderInfo {
    struct IAudioRender render;
    struct AudioDeviceDescriptor desc;
    enum AudioCategory streamType;
    unsigned int sampleRate;
    unsigned int channelCount;
    struct IAudioRenderVdi *vdiRender;
    uint32_t renderId;
    unsigned int usrCount;
    struct IAudioCallback *callback;
    bool isRegCb;
};

struct AudioRenderPrivVdi {
    struct AudioRenderInfo *renderInfos[AUDIO_VDI_STREAM_NUM_MAX];
    uint32_t renderCnt;
};

static struct AudioRenderPrivVdi g_audioRenderPrivVdi;

static struct AudioRenderPrivVdi *AudioRenderGetPrivVdi(void)
{
    return &g_audioRenderPrivVdi;
}

struct IAudioRenderVdi *AudioGetVdiRenderByIdVdi(uint32_t renderId)
{
    struct AudioRenderPrivVdi *priv = AudioRenderGetPrivVdi();
    if (priv->renderInfos[renderId] == NULL) {
        AUDIO_FUNC_LOGE("not match render");
        return NULL;
    }

    return priv->renderInfos[renderId]->vdiRender;
}

int32_t AudioGetLatencyVdi(struct IAudioRender *render, uint32_t *ms)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(ms, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetLatency, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetLatency(vdiRender, ms);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio GetLatency fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderFrameVdi(struct IAudioRender *render, const int8_t *frame, uint32_t frameLen, uint64_t *replyBytes)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frame, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(replyBytes, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->RenderFrame, HDF_ERR_INVALID_PARAM);

    HdfAudioStartTrace("Hdi:AudioRenderFrameVdi", 0);
    int32_t ret = vdiRender->RenderFrame(vdiRender, frame, frameLen, replyBytes);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render frame fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioGetRenderPositionVdi(struct IAudioRender *render, uint64_t *frames, struct AudioTimeStamp *time)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetRenderPosition, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetRenderPosition(vdiRender, frames, (struct AudioTimeStampVdi *)time);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render, get position fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioSetRenderSpeedVdi(struct IAudioRender *render, float speed)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->SetRenderSpeed, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->SetRenderSpeed(vdiRender, speed);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetRenderSpeed fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioGetRenderSpeedVdi(struct IAudioRender *render, float *speed)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(speed, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetRenderSpeed, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetRenderSpeed(vdiRender, speed);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetRenderSpeed fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

static int32_t AudioRenderCallbackVdi(enum  AudioCallbackTypeVdi type, void *reserved, void *cookie)
{
    CHECK_NULL_PTR_RETURN_VALUE(cookie, HDF_ERR_INVALID_PARAM);
    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)cookie;
    struct IAudioCallback *cb = renderInfo->callback;
    CHECK_NULL_PTR_RETURN_VALUE(cb, HDF_ERR_INVALID_PARAM);
    int8_t newCookie = 0;
    int8_t newReserved = 0;
    int32_t ret = cb->RenderCallback(cb, (enum AudioCallbackType)type, &newReserved, &newCookie);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render AudioRenderCallbackVdi fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioRenderRegCallbackVdi(struct IAudioRender *render, struct IAudioCallback *audioCallback, int8_t cookie)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(audioCallback, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->RegCallback, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->RegCallback(vdiRender, AudioRenderCallbackVdi, (void *)renderInfo);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render regCallback fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }
    renderInfo->callback = audioCallback;
    renderInfo->isRegCb = true;
    return HDF_SUCCESS;
}

int32_t AudioRenderSetChannelModeVdi(struct IAudioRender *render, enum AudioChannelMode mode)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->SetChannelMode, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->SetChannelMode(vdiRender, (enum AudioChannelModeVdi)mode);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio SetChannelMode fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetChannelModeVdi(struct IAudioRender *render, enum AudioChannelMode *mode)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(mode, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetChannelMode, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetChannelMode(vdiRender, (enum AudioChannelModeVdi *)mode);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetChannelMode fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderDrainBufferVdi(struct IAudioRender *render, enum AudioDrainNotifyType *type)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(type, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->DrainBuffer, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->DrainBuffer(vdiRender, (enum AudioDrainNotifyTypeVdi *)type);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render DrainBuffer fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderIsSupportsDrainVdi(struct IAudioRender *render, bool *support)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(support, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->IsSupportsDrain, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->IsSupportsDrain(vdiRender, support);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render IsSupportsDrain fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderCheckSceneCapabilityVdi(struct IAudioRender *render, const struct AudioSceneDescriptor *scene,
    bool *supported)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supported, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->CheckSceneCapability, HDF_ERR_INVALID_PARAM);

    struct AudioSceneDescriptorVdi vdiScene;
    (void)memset_s((void *)&vdiScene, sizeof(vdiScene), 0, sizeof(vdiScene));
    int32_t ret = AudioCommonSceneToVdiSceneVdi(scene, &vdiScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render scene To vdiScene fail");
        return HDF_FAILURE;
    }

    ret = vdiRender->CheckSceneCapability(vdiRender, &vdiScene, supported);
    OsalMemFree((void *)vdiScene.desc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render CheckSceneCapability fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderSelectSceneVdi(struct IAudioRender *render, const struct AudioSceneDescriptor *scene)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(scene, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->SelectScene, HDF_ERR_INVALID_PARAM);

    struct AudioSceneDescriptorVdi vdiScene;
    (void)memset_s((void *)&vdiScene, sizeof(vdiScene), 0, sizeof(vdiScene));
    int32_t ret = AudioCommonSceneToVdiSceneVdi(scene, &vdiScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render scene To vdiScene fail");
        return HDF_FAILURE;
    }

    ret = vdiRender->SelectScene(vdiRender, &vdiScene);
    OsalMemFree((void *)vdiScene.desc.desc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render select scene fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderSetMuteVdi(struct IAudioRender *render, bool mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->SetMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->SetMute(vdiRender, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetMute fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetMuteVdi(struct IAudioRender *render, bool *mute)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(mute, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetMute, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetMute(vdiRender, mute);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetMute fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderSetVolumeVdi(struct IAudioRender *render, float volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->SetVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->SetVolume(vdiRender, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetVolume fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetVolumeVdi(struct IAudioRender *render, float *volume)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(volume, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetVolume, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetVolume(vdiRender, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetVolume fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetGainThresholdVdi(struct IAudioRender *render, float *min, float *max)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(min, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(max, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetGainThreshold, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetGainThreshold(vdiRender, min, max);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetGainThreshold fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetGainVdi(struct IAudioRender *render, float *gain)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(gain, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetGain, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetGain(vdiRender, gain);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetGain fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderSetGainVdi(struct IAudioRender *render, float gain)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->SetGain, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->SetGain(vdiRender, gain);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetGain fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetFrameSizeVdi(struct IAudioRender *render, uint64_t *size)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(size, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetFrameSize, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetFrameSize(vdiRender, size);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetFrameSize fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetFrameCountVdi(struct IAudioRender *render, uint64_t *count)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(count, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetFrameCount, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetFrameCount(vdiRender, count);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetFrameCount fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderSetSampleAttributesVdi(struct IAudioRender *render, const struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->SetSampleAttributes, HDF_ERR_INVALID_PARAM);

    struct AudioSampleAttributesVdi vdiAttrs;
    (void)memset_s((void *)&vdiAttrs, sizeof(vdiAttrs), 0, sizeof(vdiAttrs));
    int32_t ret = AudioCommonSampleAttrToVdiSampleAttrVdi(attrs, &vdiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SampleAttr to vdisampleAttr fail, ret=%{public}d", ret);
        return ret;
    }

    ret = vdiRender->SetSampleAttributes(vdiRender, &vdiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetSampleAttributes fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetSampleAttributesVdi(struct IAudioRender *render, struct AudioSampleAttributes *attrs)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(attrs, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetSampleAttributes, HDF_ERR_INVALID_PARAM);

    struct AudioSampleAttributesVdi vdiAttrs;
    (void)memset_s((void *)&vdiAttrs, sizeof(vdiAttrs), 0, sizeof(vdiAttrs));
    int32_t ret = vdiRender->GetSampleAttributes(vdiRender, &vdiAttrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetSampleAttributes fail, ret=%{public}d", ret);
        return ret;
    }

    ret = AudioCommonVdiSampleAttrToSampleAttrVdi(&vdiAttrs, attrs);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render vdiSampleAttr to SampleAttr fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetCurrentChannelIdVdi(struct IAudioRender *render, uint32_t *channelId)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(channelId, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetCurrentChannelId, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetCurrentChannelId(vdiRender, channelId);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetCurrentChannelId fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderSetExtraParamsVdi(struct IAudioRender *render, const char *keyValueList)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(keyValueList, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->SetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->SetExtraParams(vdiRender, keyValueList);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render SetExtraParams fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderGetExtraParamsVdi(struct IAudioRender *render, char *keyValueList, uint32_t keyValueListLen)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(keyValueList, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetExtraParams, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetExtraParams(vdiRender, keyValueList, keyValueListLen);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetExtraParams fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderReqMmapBufferVdi(struct IAudioRender *render, int32_t reqSize,
    struct AudioMmapBufferDescriptor *desc)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(desc, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->ReqMmapBuffer, HDF_ERR_INVALID_PARAM);

    struct AudioMmapBufferDescriptorVdi vdiDesc = {0};
    int32_t ret = vdiRender->ReqMmapBuffer(vdiRender, reqSize, &vdiDesc);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render ReqMmapBuffer fail, ret=%{public}d", ret);
        return ret;
    }

    desc->memoryAddress = NULL;
    desc->memoryFd = vdiDesc.memoryFd;
    desc->totalBufferFrames = vdiDesc.totalBufferFrames;
    desc->transferFrameSize = vdiDesc.transferFrameSize;
    desc->isShareable = vdiDesc.isShareable;
    desc->offset = vdiDesc.offset;
    desc->filePath = strdup("");
    if (desc->filePath == NULL) {
        AUDIO_FUNC_LOGE("strdup fail");
        return HDF_FAILURE;
    }

    AUDIO_FUNC_LOGD("%{public}s success", __func__);
    return HDF_SUCCESS;
}

int32_t AudioRenderGetMmapPositionVdi(struct IAudioRender *render, uint64_t *frames, struct AudioTimeStamp *time)
{
    struct AudioTimeStampVdi vdiTime;
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    vdiTime.tvSec = 0;
    vdiTime.tvNSec = 0;

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetMmapPosition, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->GetMmapPosition(vdiRender, frames, &vdiTime);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render GetMmapPosition fail, ret=%{public}d", ret);
        return ret;
    }

    time->tvSec = vdiTime.tvSec;
    time->tvNSec = vdiTime.tvNSec;
    return HDF_SUCCESS;
}

int32_t AudioRenderAddAudioEffectVdi(struct IAudioRender *render, uint64_t effectid)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->AddAudioEffect, HDF_ERR_INVALID_PARAM);

    return vdiRender->AddAudioEffect(vdiRender, effectid);
}

int32_t AudioRenderRemoveAudioEffectVdi(struct IAudioRender *render, uint64_t effectid)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->RemoveAudioEffect, HDF_ERR_INVALID_PARAM);

    return vdiRender->RemoveAudioEffect(vdiRender, effectid);
}

int32_t AudioRenderGetFrameBufferSizeVdi(struct IAudioRender *render, uint64_t *bufferSize)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(bufferSize, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->GetFrameBufferSize, HDF_ERR_INVALID_PARAM);

    return vdiRender->GetFrameBufferSize(vdiRender, bufferSize);
}

int32_t AudioRenderStartVdi(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->Start, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->Start(vdiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Start fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderStopVdi(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->Stop, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->Stop(vdiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Stop fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderPauseVdi(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->Pause, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->Pause(vdiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Pause fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderResumeVdi(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->Resume, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->Resume(vdiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Resume fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderFlushVdi(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->Flush, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->Flush(vdiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render Flush fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderTurnStandbyModeVdi(struct IAudioRender *render)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->TurnStandbyMode, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->TurnStandbyMode(vdiRender);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render TurnStandbyMode fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderAudioDevDumpVdi(struct IAudioRender *render, int32_t range, int32_t fd)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->AudioDevDump, HDF_ERR_INVALID_PARAM);

    int32_t ret = vdiRender->AudioDevDump(vdiRender, range, fd);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render AudioDevDump fail, ret=%{public}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioRenderIsSupportsPauseAndResumeVdi(struct IAudioRender *render, bool *supportPause, bool *supportResume)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supportPause, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(supportResume, HDF_ERR_INVALID_PARAM);

    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender->IsSupportsPauseAndResume, HDF_ERR_INVALID_PARAM);

    return vdiRender->IsSupportsPauseAndResume(vdiRender, supportPause, supportResume);
}

int32_t AudioRenderSetbufferSize(struct IAudioRender *render, uint32_t size)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    struct AudioRenderInfo *renderInfo = (struct AudioRenderInfo *)render;
    struct IAudioRenderVdi *vdiRender = renderInfo->vdiRender;
    CHECK_NULL_PTR_RETURN_VALUE(vdiRender, HDF_ERR_INVALID_PARAM);
    return vdiRender->SetBufferSize(vdiRender, size);
}

static void AudioInitRenderInstanceVdi(struct IAudioRender *render)
{
    render->GetLatency = AudioGetLatencyVdi;
    render->RenderFrame = AudioRenderFrameVdi;
    render->GetRenderPosition = AudioGetRenderPositionVdi;
    render->SetRenderSpeed = AudioSetRenderSpeedVdi;
    render->GetRenderSpeed = AudioGetRenderSpeedVdi;
    render->RegCallback = AudioRenderRegCallbackVdi;
    render->SetChannelMode = AudioRenderSetChannelModeVdi;
    render->GetChannelMode = AudioRenderGetChannelModeVdi;
    render->DrainBuffer = AudioRenderDrainBufferVdi;
    render->IsSupportsDrain = AudioRenderIsSupportsDrainVdi;
    render->CheckSceneCapability = AudioRenderCheckSceneCapabilityVdi;
    render->SelectScene = AudioRenderSelectSceneVdi;
    render->SetMute = AudioRenderSetMuteVdi;
    render->GetMute = AudioRenderGetMuteVdi;
    render->SetVolume = AudioRenderSetVolumeVdi;
    render->GetVolume = AudioRenderGetVolumeVdi;
    render->GetGainThreshold = AudioRenderGetGainThresholdVdi;
    render->GetGain = AudioRenderGetGainVdi;
    render->SetGain = AudioRenderSetGainVdi;
    render->GetFrameSize = AudioRenderGetFrameSizeVdi;
    render->GetFrameCount = AudioRenderGetFrameCountVdi;
    render->SetSampleAttributes = AudioRenderSetSampleAttributesVdi;
    render->GetSampleAttributes = AudioRenderGetSampleAttributesVdi;
    render->GetCurrentChannelId = AudioRenderGetCurrentChannelIdVdi;
    render->SetExtraParams = AudioRenderSetExtraParamsVdi;
    render->GetExtraParams = AudioRenderGetExtraParamsVdi;
    render->ReqMmapBuffer = AudioRenderReqMmapBufferVdi;
    render->GetMmapPosition = AudioRenderGetMmapPositionVdi;
    render->AddAudioEffect = AudioRenderAddAudioEffectVdi;
    render->RemoveAudioEffect = AudioRenderRemoveAudioEffectVdi;
    render->GetFrameBufferSize = AudioRenderGetFrameBufferSizeVdi;
    render->Start = AudioRenderStartVdi;
    render->Stop = AudioRenderStopVdi;
    render->Pause = AudioRenderPauseVdi;
    render->Resume = AudioRenderResumeVdi;
    render->Flush = AudioRenderFlushVdi;
    render->TurnStandbyMode = AudioRenderTurnStandbyModeVdi;
    render->AudioDevDump = AudioRenderAudioDevDumpVdi;
    render->IsSupportsPauseAndResume = AudioRenderIsSupportsPauseAndResumeVdi;
    render->SetBufferSize = AudioRenderSetbufferSize;
}

struct IAudioRender *FindRenderCreated(enum AudioPortPin pin, const struct AudioSampleAttributes *attrs,
    uint32_t *rendrId)
{
    if (attrs->type == AUDIO_MMAP_NOIRQ) {
        AUDIO_FUNC_LOGI("render type is mmap");
        return NULL;
    }
    uint32_t index = 0;
    struct AudioRenderPrivVdi *renderPriv = AudioRenderGetPrivVdi();
    if (renderPriv == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return NULL;
    }

    if (renderPriv->renderCnt == 0) {
        AUDIO_FUNC_LOGI("no render created");
        return NULL;
    }

    for (index = 0; index < AUDIO_VDI_STREAM_NUM_MAX; index++) {
        if ((renderPriv->renderInfos[index] != NULL) &&
            (renderPriv->renderInfos[index]->streamType == attrs->type)) {
            *rendrId = renderPriv->renderInfos[index]->renderId;
            renderPriv->renderInfos[index]->usrCount++;
            return &renderPriv->renderInfos[index]->render;
        }
    }

    return NULL;
}

static uint32_t GetAvailableRenderId(struct AudioRenderPrivVdi *renderPriv)
{
    uint32_t renderId = AUDIO_VDI_STREAM_NUM_MAX;
    if (renderPriv == NULL) {
        AUDIO_FUNC_LOGE("Parameter error!");
        return renderId;
    }

    if (renderPriv->renderCnt < AUDIO_VDI_STREAM_NUM_MAX) {
        renderId = renderPriv->renderCnt;
        renderPriv->renderCnt++;
    } else {
        for (uint32_t index = 0; index < AUDIO_VDI_STREAM_NUM_MAX; index++) {
            if (renderPriv->renderInfos[index] == NULL) {
                renderId = index;
                break;
            }
        }
    }

    return renderId;
}

struct IAudioRender *AudioCreateRenderByIdVdi(const struct AudioSampleAttributes *attrs, uint32_t *renderId,
    struct IAudioRenderVdi *vdiRender, const struct AudioDeviceDescriptor *desc)
{
    struct IAudioRender *render = NULL;
    if (attrs == NULL || renderId == NULL || vdiRender == NULL || desc == NULL) {
        AUDIO_FUNC_LOGE("audio render is null");
        return NULL;
    }

    *renderId = AUDIO_VDI_STREAM_NUM_MAX;
    struct AudioRenderPrivVdi *priv = AudioRenderGetPrivVdi();

    *renderId = GetAvailableRenderId(priv);
    if (*renderId >= AUDIO_VDI_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiRender create render index fail, renderId=%{public}d", *renderId);
        return NULL;
    }

    priv->renderInfos[*renderId] = (struct AudioRenderInfo *)OsalMemCalloc(sizeof(struct AudioRenderInfo));
    if (priv->renderInfos[*renderId] == NULL) {
        AUDIO_FUNC_LOGE("audio VdiRender malloc renderInfos fail");
        return NULL;
    }

    priv->renderInfos[*renderId]->vdiRender = vdiRender;
    priv->renderInfos[*renderId]->streamType = attrs->type;
    priv->renderInfos[*renderId]->sampleRate = attrs->sampleRate;
    priv->renderInfos[*renderId]->channelCount = attrs->channelCount;
    priv->renderInfos[*renderId]->desc.portId = desc->portId;
    priv->renderInfos[*renderId]->desc.pins = desc->pins;
    priv->renderInfos[*renderId]->desc.desc = strdup(desc->desc);
    if (priv->renderInfos[*renderId]->desc.desc == NULL) {
        AUDIO_FUNC_LOGE("strdup fail, desc->desc = %{public}s", desc->desc);
        OsalMemFree(priv->renderInfos[*renderId]);
        priv->renderInfos[*renderId] = NULL;
        return NULL;
    }
    priv->renderInfos[*renderId]->renderId = *renderId;
    priv->renderInfos[*renderId]->usrCount = 1;
    priv->renderInfos[*renderId]->callback = NULL;
    priv->renderInfos[*renderId]->isRegCb = false;
    render = &(priv->renderInfos[*renderId]->render);
    AudioInitRenderInstanceVdi(render);

    AUDIO_FUNC_LOGD("audio create render success");
    return render;
}

uint32_t DecreaseRenderUsrCount(uint32_t renderId)
{
    uint32_t usrCnt = 0;
    if (renderId >= AUDIO_VDI_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio check render index fail, descIndex=%{public}d", renderId);
        return usrCnt;
    }
    struct AudioRenderPrivVdi *priv = AudioRenderGetPrivVdi();
    if (priv->renderInfos[renderId] == NULL) {
        AUDIO_FUNC_LOGE("audio check render index fail, descIndex=%{public}d", renderId);
        return usrCnt;
    }

    priv->renderInfos[renderId]->usrCount--;
    usrCnt = priv->renderInfos[renderId]->usrCount;
    return usrCnt;
}

void AudioDestroyRenderByIdVdi(uint32_t renderId)
{
    if (renderId >= AUDIO_VDI_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio vdiRender destroy render index fail, descIndex=%{public}d", renderId);
        return;
    }
    struct AudioRenderPrivVdi *priv = AudioRenderGetPrivVdi();
    if (priv->renderInfos[renderId] == NULL) {
        AUDIO_FUNC_LOGE("audio vdiRender destroy render index fail, descIndex=%{public}d", renderId);
        return;
    }

    OsalMemFree((void *)priv->renderInfos[renderId]->desc.desc);
    priv->renderInfos[renderId]->vdiRender = NULL;
    priv->renderInfos[renderId]->desc.desc = NULL;
    priv->renderInfos[renderId]->desc.portId = UINT_MAX;
    priv->renderInfos[renderId]->desc.pins = PIN_NONE;
    priv->renderInfos[renderId]->callback = NULL;
    priv->renderInfos[renderId]->isRegCb = false;
    OsalMemFree(priv->renderInfos[renderId]);
    priv->renderInfos[renderId] = NULL;
}
