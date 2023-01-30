/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "audio_if_lib_common.h"
#include "audio_uhdf_log.h"
#include "hdf_io_service_if.h"
#include "hdf_sbuf.h"
#include "osal_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#define ALSA_CTL_NAME_LEN 64
#define MIXER_CTL_MAX_NUM 64

enum SndCardType {
    SND_CARD_UNKNOWN = -1,
    SND_CARD_PRIMARY = 0,
    SND_CARD_HDMI,
    SND_CARD_USB,
    SND_CARD_BT,
    SND_CARD_MAX
};

struct MixerCtlVolumeName {
    char name[ALSA_CTL_NAME_LEN]; /* name part of simple element identifier */
};

struct DevProcInfo {
    char cardName[CARD_ID_LEN_MAX];                /* adapter name */
    char cid[CARD_ID_LEN_MAX];                     /* cardX/id match */
    char did[CARD_ID_LEN_MAX];                     /* dai id match */
    struct MixerCtlVolumeName *ctlRenderNameList;  /* Simple mixer control list */
    struct MixerCtlVolumeName *ctlCaptureNameList; /* Simple mixer control list */
    uint32_t ctlRenderVolNameCount;
    uint32_t ctlCaptureVolNameCount;
};

struct AlsaDevInfo {
    char cardId[MAX_CARD_NAME_LEN + 1];
    char pcmInfoId[MAX_CARD_NAME_LEN + 1];
    int32_t card;
    int32_t device;
};

struct AlsaCardsList {
    struct AlsaDevInfo alsaDevIns[MAX_CARD_NUM];
};

struct AlsaMixerPath {
    const char *pathName; /* ASCII name of item */
    uint32_t numId;       /* numeric identifier */
    uint32_t item;        /* item number */
};

struct AlsaMixerElem {
    snd_mixer_elem_t *elem; /* Simple mixer control */
};

struct AudioCardInfo {
    uint8_t cardStatus;
    snd_pcm_t *capturePcmHandle;
    snd_pcm_t *renderPcmHandle;
    snd_mixer_t *mixer;
    struct AlsaMixerElem *volElemList; /* Simple mixer control list for primary */
    uint32_t volElemCount;             /* Simple mixer control list count for primary */
    snd_mixer_elem_t *usbCtlVolume;
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
    char alsaPcmInfoId[MAX_CARD_NAME_LEN + 1];
    struct AudioPcmHwParams hwRenderParams;
    struct AudioPcmHwParams hwCaptureParams;
    struct AlsaMixerPath renderMixerPath;
    struct AlsaMixerPath captureMixerPath;
};

struct DevHandle *AudioBindService(const char *name);
void AudioCloseService(const struct DevHandle *handle);
void InitSound(snd_mixer_t **mixer, char *hwCtlName);
int32_t CloseMixerHandle(snd_mixer_t *alsaMixHandle);
int32_t InitCardIns(void);
struct AudioCardInfo *GetCardIns(const char *cardName);
struct AudioCardInfo *AudioGetCardInstance(const char *adapterName);
int32_t AudioGetCardInfo(struct AudioCardInfo *cardIns, const char *adapterName, snd_pcm_stream_t stream);
int32_t InitMixerCtlElement(
    const char *adapterName, struct AudioCardInfo *cardIns, snd_mixer_t *mixer, snd_pcm_stream_t stream);
void CheckCardStatus(struct AudioCardInfo *cardIns);
int32_t CheckParaFormat(struct AudioPcmHwParams hwParams, snd_pcm_format_t *alsaPcmFormat);
int32_t DestroyCardList(void);
int32_t GetSelCardInfo(struct AudioCardInfo *cardIns, struct AlsaDevInfo *devInsHandle);
int32_t MatchSelAdapter(const char *adapterName, struct AudioCardInfo *cardIns);
int32_t GetPriMixerCtlElement(struct AudioCardInfo *cardIns, snd_mixer_t *mixer, snd_pcm_stream_t stream);
int32_t AudioSetCtrlVolumeRange(struct AudioCardInfo *cardIns, const char *adapterName, snd_pcm_stream_t stream);
int32_t CardInfoParseFromConfig(void);
int32_t AudioMixerSetCtrlMode(struct AudioCardInfo *cardIns, const char *adapterName, snd_pcm_stream_t stream);
int32_t EnableAudioRenderRoute(const struct AudioHwRenderParam *renderData);
int32_t EnableAudioCaptureRoute(const struct AudioHwCaptureParam *captureData);
#ifdef __cplusplus
}
#endif
#endif /* ALSA_LIB_COMMON_H */
