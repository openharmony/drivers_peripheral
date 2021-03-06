/*
 * Copyright (c) 2021 Rockchip Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ALSA_AUDIO_H_
#define ALSA_AUDIO_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sound/asound.h>
#include <tinyalsa/asoundlib.h>
#include <linux/ioctl.h>
#include "audio_hal_log.h"

#define SNDRV_CARDS 8
#define SNDRV_DEVICES 8

enum snd_out_sound_cards {
    SND_OUT_SOUND_CARD_UNKNOWN = -1,
    SND_OUT_SOUND_CARD_SPEAKER = 0,
    SND_OUT_SOUND_CARD_HDMI,
    SND_OUT_SOUND_CARD_SPDIF,
    SND_OUT_SOUND_CARD_BT,
    SND_OUT_SOUND_CARD_MAX,
};

enum snd_in_sound_cards {
    SND_IN_SOUND_CARD_UNKNOWN = -1,
    SND_IN_SOUND_CARD_MIC = 0,
    SND_IN_SOUND_CARD_BT,
    SND_IN_SOUND_CARD_HDMI,
    SND_IN_SOUND_CARD_MAX,
};

enum RenderPcmPara {
    TINYALSAPCM_8_BIT  = 8,
    TINYALSAPCM_16_BIT = 16,
    TINYALSAPCM_24_BIT = 24,
    TINYALSAPCM_32_BIT = 32,
};

enum AudioRoute {
    // out devices route define
    DEV_OUT_SPEAKER_NORMAL_ROUTE = 0,
    DEV_OUT_HEADPHONE_NORMAL_ROUTE,
    DEV_OUT_SPEAKER_HEADPHONE_NORMAL_ROUTE,
    DEV_OUT_HDMI_NORMAL_ROUTE,
    // in devices route define
    DEV_IN_MAIN_MIC_CAPTURE_ROUTE,
    DEV_IN_HANDS_FREE_MIC_CAPTURE_ROUTE,
    // close devices route define
    DEV_OFF_PLAYBACK_OFF_ROUTE,
    DEV_OFF_CAPTURE_OFF_ROUTE,

    MAX_ROUTE,
};

struct DevInfo {
    const char *id;
    int card;
    int device;
};

struct DevProcInfo {
    const char *cid; /* cardX/id match */
    const char *did; /* dai id match */
};

struct mixer_ctl {
    struct mixer *mixer;
    struct snd_ctl_elem_info *info;
    struct snd_ctl_tlv *tlv;
    char **ename;
};

struct mixer {
    int fd;
    struct snd_ctl_elem_info *info;
    struct mixer_ctl *ctl;
    unsigned count;
};

struct sndrv_ctl_tlv {
    unsigned int numid;     /* control element numeric identification */
    unsigned int length;    /* in bytes aligned to 4 */
    unsigned int tlv[0];    /* first TLV */
};

struct PcmRenderParam {
    unsigned int card;
    unsigned int device;
    unsigned int channels;
    unsigned int rate;
    unsigned int bits;
    unsigned int periodSize;
    unsigned int periodCount;
};

struct PcmCaptureParam {
    unsigned int card;
    unsigned int device;
    unsigned int channels;
    unsigned int rate;
    enum pcm_format format;
    unsigned int periodSize;
    unsigned int periodCount;
};


int RouteSetVoiceVolume(float volume);
int RouteSetCaptureVoiceVolume(float volume);
int RouteGetVoiceVolume(char *ctlName);
int RouteGetVoiceMinMaxStep(long long *volMin, long long *volMax, char *ctlName, bool isPlayback);
int MixerOpenLegacy(bool isPlayback, int card);
void ReadOutSoundCard(void);
void ReadInSoundCard(void);
void RoutePcmCardOpen(int card, uint32_t route);
int RoutePcmClose(unsigned route);
void RenderSample(struct pcm **pcm, struct PcmRenderParam* param);
unsigned int CaptureSample(struct pcm **pcm, struct PcmCaptureParam* param);
int GetOutDevInfo(int index, struct DevInfo* devInfo);
int GetInDevInfo(int index, struct DevInfo* devInfo);
#endif
