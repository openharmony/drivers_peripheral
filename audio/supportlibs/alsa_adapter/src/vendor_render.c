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

#include "alsa_snd_render.h"
#include "common.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_RENDER

struct RenderData {
    struct AlsaMixerCtlElement ctrlLeftVolume;
    struct AlsaMixerCtlElement ctrlRightVolume;
    long tempVolume;
};

static int32_t RenderInitImpl(struct AlsaRender *renderIns)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    if (renderIns->priData != NULL) {
        return HDF_SUCCESS;
    }

    RenderData *priData = (RenderData *)OsalMemCalloc(sizeof(RenderData));
    if (priData == NULL) {
        AUDIO_FUNC_LOGE("Failed to allocate memory!");
        return HDF_FAILURE;
    }

    SndElementItemInit(&priData->ctrlLeftVolume);
    SndElementItemInit(&priData->ctrlRightVolume);
    priData->ctrlLeftVolume.numid = SND_NUMID_DACL_PLAYBACK_VOL;
    priData->ctrlLeftVolume.name = SND_ELEM_DACL_PLAYBACK_VOL;
    priData->ctrlRightVolume.numid = SND_NUMID_DACR_PLAYBACK_VOL;
    priData->ctrlRightVolume.name = SND_ELEM_DACR_PLAYBACK_VOL;
    RenderSetPriData(renderIns, (RenderPriData)priData);

    return HDF_SUCCESS;
}

static int32_t RenderSelectSceneImpl(struct AlsaRender *renderIns, enum AudioPortPin descPins,
    const struct PathDeviceInfo *deviceInfo)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    renderIns->descPins = descPins;
    return HDF_SUCCESS;
}

static int32_t RenderGetVolThresholdImpl(struct AlsaRender *renderIns, long *volMin, long *volMax)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(volMin);
    CHECK_NULL_PTR_RETURN_DEFAULT(volMax);
    int32_t ret = HDF_SUCCESS;
    long volMinTmp = 0;
    long volMaxTmp = 0;
    struct AlsaSoundCard *cardIns = (struct AlsaSoundCard *)renderIns;
    RenderData *priData = RenderGetPriData(renderIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(cardIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(priData);

    ret = SndElementReadRange(cardIns, &priData->ctrlLeftVolume, &volMinTmp, &volMaxTmp);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("SndElementReadRange fail!");
        return HDF_FAILURE;
    }
    *volMin = volMinTmp;
    *volMax = volMaxTmp;
    
    return HDF_SUCCESS;
}

static int32_t RenderGetVolumeImpl(struct AlsaRender *renderIns, long *volume)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(volume);
    int32_t ret = HDF_SUCCESS;
    long volLeft = 0;
    long volRight = 0;
    struct AlsaSoundCard *cardIns = (struct AlsaSoundCard *)renderIns;
    RenderData *priData = RenderGetPriData(renderIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(cardIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(priData);

    ret = SndElementReadInt(cardIns, &priData->ctrlLeftVolume, &volLeft);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Read left volume fail!");
        return HDF_FAILURE;
    }
    ret = SndElementReadInt(cardIns, &priData->ctrlRightVolume, &volRight);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Read right volume fail!");
        return HDF_FAILURE;
    }
    *volume = (volLeft + volRight) >> 1;

    return HDF_SUCCESS;
}

static int32_t RenderSetVolumeImpl(struct AlsaRender *renderIns, long volume)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    int32_t ret = HDF_SUCCESS;
    struct AlsaSoundCard *cardIns = (struct AlsaSoundCard *)renderIns;
    RenderData *priData = RenderGetPriData(renderIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(cardIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(priData);

    ret = SndElementWriteInt(cardIns, &priData->ctrlLeftVolume, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Write left volume fail!");
        return HDF_FAILURE;
    }
    ret = SndElementWriteInt(cardIns, &priData->ctrlRightVolume, volume);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Write right volume fail!");
        return HDF_FAILURE;
    }
    
    return HDF_SUCCESS;
}

static bool RenderGetMuteImpl(struct AlsaRender *renderIns)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    return renderIns->muteState;
}

static int32_t RenderSetMuteImpl(struct AlsaRender *renderIns, bool muteFlag)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    int32_t ret = HDF_SUCCESS;
    long vol = 0;
    long setVol = 0;
    RenderData *priData = RenderGetPriData(renderIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    CHECK_NULL_PTR_RETURN_DEFAULT(priData);

    ret = renderIns->GetVolume(renderIns, &vol);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("GetVolume failed!");
        return HDF_FAILURE;
    }
    
    if (muteFlag) {
        priData->tempVolume = vol;
        setVol = 0;
    } else {
        setVol = priData->tempVolume;
    }
    
    renderIns->SetVolume(renderIns, setVol);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("SetVolume failed!");
        return HDF_FAILURE;
    }
    renderIns->muteState = muteFlag;
    
    return HDF_SUCCESS;
}

static int32_t RenderStartImpl(struct AlsaRender *renderIns)
{
    return HDF_SUCCESS;
}

static int32_t RenderStopImpl(struct AlsaRender *renderIns)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    snd_pcm_drain(renderIns->soundCard.pcmHandle);
    return HDF_SUCCESS;
}

static int32_t RenderGetGainThresholdImpl(struct AlsaRender *renderIns, float *gainMin, float *gainMax)
{
    AUDIO_FUNC_LOGI("emulator not support gain operation");
    return HDF_SUCCESS;
}

static int32_t RenderGetGainImpl(struct AlsaRender *renderIns, float *volume)
{
    AUDIO_FUNC_LOGI("emulator not support gain operation");
    return HDF_SUCCESS;
}

static int32_t RenderSetGainImpl(struct AlsaRender *renderIns, float volume)
{
    AUDIO_FUNC_LOGI("emulator not support gain operation");
    return HDF_SUCCESS;
}

static int32_t RenderGetChannelModeImpl(struct AlsaRender *renderIns, enum AudioChannelMode *mode)
{
    return HDF_SUCCESS;
}

static int32_t RenderSetChannelModeImpl(struct AlsaRender *renderIns, enum AudioChannelMode mode)
{
    return HDF_SUCCESS;
}

int32_t RenderOverrideFunc(struct AlsaRender *renderIns)
{
    CHECK_NULL_PTR_RETURN_DEFAULT(renderIns);
    struct AlsaSoundCard *cardIns = (struct AlsaSoundCard *)renderIns;

    if (cardIns->cardType == SND_CARD_PRIMARY) {
        renderIns->Init = RenderInitImpl;
        renderIns->SelectScene = RenderSelectSceneImpl;
        renderIns->Start = RenderStartImpl;
        renderIns->Stop = RenderStopImpl;
        renderIns->GetVolThreshold = RenderGetVolThresholdImpl;
        renderIns->GetVolume = RenderGetVolumeImpl;
        renderIns->SetVolume = RenderSetVolumeImpl;
        renderIns->GetGainThreshold = RenderGetGainThresholdImpl;
        renderIns->GetGain = RenderGetGainImpl;
        renderIns->SetGain = RenderSetGainImpl;
        renderIns->GetMute = RenderGetMuteImpl;
        renderIns->SetMute = RenderSetMuteImpl;
        renderIns->GetChannelMode = RenderGetChannelModeImpl;
        renderIns->SetChannelMode = RenderSetChannelModeImpl;
    }

    return HDF_SUCCESS;
}
