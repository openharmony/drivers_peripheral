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
#include "audio_hal_log.h"
#include "audio_if_lib_common.h"

#define SERVIC_NAME_MAX_LEN 32

#define MAX_VOLUME  100
#define MIN_VOLUME  0
#define MAX_ELEMENT 100
#define AUDIO_MIN_CARD_NUM  1
#define AUDIO_MAX_CARD_NUM  8
#define MAX_CARD_NAME_LEN   64
#define MAX_CARD_NUM        (4 * AUDIO_MAX_CARD_NUM)

#define SND_DEVCICE_DEFAULT     "default"   /** about SND_DEVCICE0 */
#define SND_DEVCICE0            "hw:0,0"
#define SND_DEVCICE1            "hw:1,0"

#define CTRL_DEVCICE_DEFAULT    "hw:0"

#define  USB_AUDIO              "USB Audio"

/** Codec list supported by current driver */
#define CODEC_CARD_ID     "rockchiprk809co"   /** rockchip,rk809-codec cid */

#define AUDIO_ALSALIB_IOCTRL_RESUME 0
#define AUDIO_ALSALIB_IOCTRL_PAUSE  1
#define AUDIO_ALSALIB_MMAP_MAX      10

enum SndRKPlayPathItem {
    SND_OUT_CARD_OFF,
    SND_OUT_CARD_RCV,
    SND_OUT_CARD_SPK,
    SND_OUT_CARD_HP,
    SND_OUT_CARD_HP_NO_MIC,
    SND_OUT_CARD_BT,
    SND_OUT_CARD_SPK_HP,
    SND_OUT_CARD_RING_SPK,
    SND_OUT_CARD_RING_HP,
    SND_OUT_CARD_RING_HP_NO_MIC,
    SND_OUT_CARD_RING_SPK_HP
};

enum SndRKCapPathItem {
    SND_OUT_CARD_MIC_OFF,
    SND_OUT_CARD_MAIN_MIC,
    SND_OUT_CARD_HANDS_FREE_MIC,
    SND_OUT_CARD_BT_SCO_MIC
};

enum SndRKCtrlNumId {
    SND_PLAY_PATH = 1,
    SND_CAP_MIC_PATH,
    SND_DACL_PLAY_VOL,
    SND_DACR_PLAY_VOL,
    SND_DACL_CAP_VOL,
    SND_DACR_CAP_VOL
};

struct DeviceInfo {
    const char *id;
    int32_t card;
    int32_t device;
};

struct DevProcInfo {
    const char *cid; /* cardX/id match */
    const char *did; /* dai id match */
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
int32_t DestroyCardList(void);
void GetDeviceList(struct AudioCardInfo *cardIns, snd_pcm_stream_t stream);
int32_t GetSelCardInfo(struct AudioCardInfo *cardIns, struct AlsaDevInfo *devInsHandle);
int32_t MatchSelAdapter(const char *adapterName, struct AudioCardInfo *cardIns);
int32_t GetPriMixerCtlElement(struct AudioCardInfo *cardIns, snd_mixer_elem_t *pcmElement);
int32_t AudioMixerSetCtrlMode(struct AudioCardInfo *cardIns,
    const char *adapterName, const char *mixerCtrlName, int numId, int item);
snd_mixer_elem_t *AudioUsbFindElement(snd_mixer_t *mixer);

#endif /* ALSA_LIB_COMMON_H */
