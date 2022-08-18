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

#ifndef ALSA_LIB_COMMON_H
#define ALSA_LIB_COMMON_H

#include "asoundlib.h"
#include "hdf_io_service_if.h"
#include "hdf_sbuf.h"
#include "osal_mem.h"
#include "audio_uhdf_log.h"
#include "audio_if_lib_common.h"

#define SERVIC_NAME_MAX_LEN 32

#define MAX_VOLUME         100
#define MIN_VOLUME         0
#define AUDIO_MIN_CARD_NUM 1
#define AUDIO_MAX_CARD_NUM 8
#define CARD_ID_LEN_MAX    32
#define MAX_CARD_NAME_LEN  64
#define MAX_CARD_NUM       (4 * (AUDIO_MAX_CARD_NUM))

#define AUDIO_ALSALIB_IOCTRL_RESUME 0
#define AUDIO_ALSALIB_IOCTRL_PAUSE  1
#define AUDIO_ALSALIB_MMAP_MAX      10
#define AUDIO_ALSALIB_RETYR         3

enum SndRKPlayPathItem {
    SND_OUT_CARD_OFF,            /* close play path */
    SND_OUT_CARD_RCV,            /* speaker */
    SND_OUT_CARD_SPK,            /* speaker */
    SND_OUT_CARD_HP,             /* headphone */
    SND_OUT_CARD_HP_NO_MIC,      /* headphone */
    SND_OUT_CARD_BT,             /* bluetooth (Don't set!!!) */
    SND_OUT_CARD_SPK_HP,         /* speaker and headphone */
    SND_OUT_CARD_RING_SPK,       /* speaker */
    SND_OUT_CARD_RING_HP,        /* headphone */
    SND_OUT_CARD_RING_HP_NO_MIC, /* headphone */
    SND_OUT_CARD_RING_SPK_HP     /* speaker and headphone */
};

enum SndRKCapPathItem {
    SND_IN_CARD_MIC_OFF,        /* close capture path */
    SND_IN_CARD_MAIN_MIC,       /* main mic */
    SND_IN_CARD_HANDS_FREE_MIC, /* hands free mic */
    SND_IN_CARD_BT_SCO_MIC      /* bluetooth sco mic (Don't set!!!) */
};

enum SndRKCtrlNumId {
    SND_PLAY_PATH = 1, /* play path  */
    SND_CAP_MIC_PATH,  /* capture path */
    SND_DACL_PLAY_VOL, /* play left volume path */
    SND_DACR_PLAY_VOL, /* play right volume path */
    SND_DACL_CAP_VOL,  /* capture left volume path */
    SND_DACR_CAP_VOL   /* capture right volume path */
};

enum SndCardType {
    SND_CARD_UNKNOWN = -1,
    SND_CARD_PRIMARY = 0,
    SND_CARD_HDMI,
    SND_CARD_USB,
    SND_CARD_BT,
    SND_CARD_MAX
};

struct DevProcInfo {
    char cardName[CARD_ID_LEN_MAX];
    char cid[CARD_ID_LEN_MAX]; /* cardX/id match */
    char did[CARD_ID_LEN_MAX]; /* dai id match */
};

struct AlsaDevInfo {
    char cardId[MAX_CARD_NAME_LEN + 1];
    char pcmInfoId[MAX_CARD_NAME_LEN + 1];
    int32_t card;
    int32_t device;
};

struct AudioCardInfo {
    uint8_t cardStatus;
    snd_pcm_t *capturePcmHandle;
    snd_pcm_t *renderPcmHandle;
    snd_mixer_t *mixer;
    snd_mixer_elem_t *ctrlLeftVolume;
    snd_mixer_elem_t *ctrlRightVolume;
    bool renderMmapFlag;
    bool captureMmapFlag;
    int32_t renderMuteValue;
    int32_t captureMuteValue;
    float tempVolume;
    uint64_t renderMmapFrames;
    uint64_t capMmapFrames;
    uint64_t mmapFrames;
    char cardName[MAX_CARD_NAME_LEN + 1];
    char devName[MAX_CARD_NAME_LEN + 1];
    char alsaCardId[MAX_CARD_NAME_LEN + 1];
    char ctrlName[MAX_CARD_NAME_LEN + 1];
    struct AlsaDevInfo alsaDevIns[MAX_CARD_NUM];
    struct AudioPcmHwParams hwRenderParams;
    struct AudioPcmHwParams hwCaptureParams;
};

struct HdfIoService *HdfIoServiceBindName(const char *serviceName);
void InitSound(snd_mixer_t **mixer, char *hwCtlName);
int32_t CloseMixerHandle(snd_mixer_t *alsaMixHandle);
int32_t InitCardIns(void);
struct AudioCardInfo *GetCardIns(const char *cardName);
struct AudioCardInfo *AudioGetCardInfo(const char *adapterName, snd_pcm_stream_t stream);
void CheckCardStatus(struct AudioCardInfo *cardIns);
int32_t CheckParaFormat(struct AudioPcmHwParams hwParams, snd_pcm_format_t *alsaPcmFormat);
int32_t DestroyCardList(void);
int32_t GetSelCardInfo(struct AudioCardInfo *cardIns, struct AlsaDevInfo *devInsHandle);
int32_t MatchSelAdapter(const char *adapterName, struct AudioCardInfo *cardIns);
int32_t GetPriMixerCtlElement(struct AudioCardInfo *cardIns, snd_mixer_elem_t *pcmElement);
int32_t AudioMixerSetCtrlMode(
    struct AudioCardInfo *cardIns, const char *adapterName, const char *mixerCtrlName, int numId, int item);
snd_mixer_elem_t *AudioUsbFindElement(snd_mixer_t *mixer);
int32_t CardInfoParseFromConfig(void);

#endif /* ALSA_LIB_COMMON_H */
