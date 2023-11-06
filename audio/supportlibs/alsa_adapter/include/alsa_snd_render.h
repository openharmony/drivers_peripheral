/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ALSA_SND_RENDER_H
#define ALSA_SND_RENDER_H

#include "alsa_soundcard.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void* RenderPriData;

struct AlsaRender {
    struct AlsaSoundCard soundCard;
    enum AudioPortPin descPins;
    bool muteState;
    bool periodEvent; /* produce poll event after each period */
    snd_pcm_sframes_t bufferSize;
    snd_pcm_sframes_t periodSize;
    unsigned int bufferTime;    /* (0.5s): ring buffer length in us */
    unsigned int periodTime;    /* (0.1s): period time in us */
    int resample;
    RenderPriData priData;

    /* render scene */
    int32_t (*Init)(struct AlsaRender*);
    int32_t (*SelectScene)(struct AlsaRender *, enum AudioPortPin, const struct PathDeviceInfo *);
    int32_t (*Open)(struct AlsaRender *);
    int32_t (*Start)(struct AlsaRender *);
    int32_t (*Stop)(struct AlsaRender *);
    int32_t (*Close)(struct AlsaRender *);
    int32_t (*Write)(struct AlsaRender *, const struct AudioHwRenderParam *);
    int32_t (*GetMmapPosition)(struct AlsaRender *);
    int32_t (*MmapWrite)(struct AlsaRender *, const struct AudioHwRenderParam *);

    /* volume operation */
    int32_t (*GetVolThreshold)(struct AlsaRender *, long *, long *);
    int32_t (*GetVolume)(struct AlsaRender *, long *);
    int32_t (*SetVolume)(struct AlsaRender *, long);

    /* gain operation */
    int32_t (*GetGainThreshold)(struct AlsaRender *, float *, float *);
    int32_t (*GetGain)(struct AlsaRender *, float *);
    int32_t (*SetGain)(struct AlsaRender *, float);

    /* mute operation */
    bool  (*GetMute)(struct AlsaRender *);
    int32_t (*SetMute)(struct AlsaRender *, bool);

    /* channel mode operation */
    int32_t (*GetChannelMode)(struct AlsaRender *, enum AudioChannelMode *);
    int32_t (*SetChannelMode)(struct AlsaRender *, enum AudioChannelMode);

    /* set pause or resume state */
    int32_t (*SetPauseState)(struct AlsaRender *, bool);
};

struct AlsaRender *RenderCreateInstance(const char* adapterName);
struct AlsaRender *RenderGetInstance(const char *adapterName);
int32_t RenderSetParams(struct AlsaRender *renderIns, const struct AudioHwRenderParam *handleData);
void  RenderSetPriData(struct AlsaRender *renderIns, RenderPriData data);
RenderPriData RenderGetPriData(struct AlsaRender *renderIns);

/*
    Different platforms implement this function rewriting render implementation
 */
int32_t RenderOverrideFunc(struct AlsaRender *renderIns);

#ifdef __cplusplus
}
#endif

#endif /* ALSA_SND_RENDER_H */