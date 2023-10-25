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

#ifndef ALSA_SND_CAPTURE_H
#define ALSA_SND_CAPTURE_H

#include "alsa_soundcard.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void* CapturePriData;

struct AlsaCapture {
    struct AlsaSoundCard soundCard;
    enum AudioPortPin descPins;
    bool muteState;
    bool periodEvent; /* produce poll event after each period */
    snd_pcm_sframes_t bufferSize;
    snd_pcm_sframes_t periodSize;
    unsigned int bufferTime;    /* (0.5s): ring buffer length in us */
    unsigned int periodTime;    /* (0.1s): period time in us */
    int resample;    /* enable alsa-lib resampling */
    CapturePriData priData;

    /* Capture scene */
    int32_t (*Init)(struct AlsaCapture*);
    int32_t (*Open)(struct AlsaCapture *);
    int32_t (*SelectScene)(struct AlsaCapture *, enum AudioPortPin, const struct PathDeviceInfo *);
    int32_t (*Start)(struct AlsaCapture *);
    int32_t (*Stop)(struct AlsaCapture *);
    int32_t (*Close)(struct AlsaCapture *);
    int32_t (*Read)(struct AlsaCapture *, struct AudioHwCaptureParam *);
    int32_t (*GetMmapPosition)(struct AlsaCapture *);
    int32_t (*MmapRead)(struct AlsaCapture *, const struct AudioHwCaptureParam *);

    /* volume operation */
    int32_t (*GetVolThreshold)(struct AlsaCapture *, long *, long *);
    int32_t (*GetVolume)(struct AlsaCapture *, long *);
    int32_t (*SetVolume)(struct AlsaCapture *, long);

    /* gain operation */
    int32_t (*GetGainThreshold)(struct AlsaCapture *, float *, float *);
    int32_t (*GetGain)(struct AlsaCapture *, float *);
    int32_t (*SetGain)(struct AlsaCapture *, float);

    /* mute operation */
    bool  (*GetMute)(struct AlsaCapture *);
    int32_t (*SetMute)(struct AlsaCapture *, bool);

    /* set pause or resume state */
    int32_t (*SetPauseState)(struct AlsaCapture *, bool);
};

struct AlsaCapture *CaptureCreateInstance(const char* adapterName);
struct AlsaCapture *CaptureGetInstance(const char *adapterName);
int32_t CaptureSetParams(struct AlsaCapture *captureIns, const struct AudioHwCaptureParam *handleData);
void  CaptureSetPriData(struct AlsaCapture *captureIns, CapturePriData data);
CapturePriData CaptureGetPriData(struct AlsaCapture *captureIns);

/*
    Different platforms implement this function rewriting capture implementation
 */
int32_t CaptureOverrideFunc(struct AlsaCapture *captureIns);

#ifdef __cplusplus
}
#endif

#endif /* ALSA_SND_CAPTURE_H */