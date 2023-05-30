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

#ifndef AUDIO_MIXER_H
#define AUDIO_MIXER_H

#include <stdint.h>
#include <stdbool.h>

#include "audio_interface_lib_mixer.h"

#define CARD_NAME_LEN 32
/** bitmask for chan-map */
#define AUDIO_CHMAP_MASK 0xFFFF

#define STRING(x) (#x)

#define ERR_LOG(fmt, arg...)                                  \
    do {                                                      \
        printf("[%s]-[%d]: " fmt, __func__, __LINE__, ##arg); \
    } while (0)

#define DEBUG_LOG(fmt, arg...)                                                    \
    do {                                                                          \
        if (g_debugFlag) {                                                          \
            printf("[%s]: [%s]-[%d]: " fmt, __FILE__, __func__, __LINE__, ##arg); \
        }                                                                         \
    } while (0)

struct HdfIoService;

typedef enum {
    U_SUCCESS = 0,
    U_FAILURE = -1,
    U_NOT_SUPPORT = -2,
    U_INVALID_PARAM = -3,
    U_MALLOC_FAIL = -6,
    U_UNKNOW = U_FAILURE,
} UTILS_STATUS;

typedef enum {
    SND_OTHER = -1,
    SND_PRIMARY = 0,
    SND_HDMI,
    SND_USB,
    SND_A2DP,
} SND_TYPE;

struct AudioHwCardInfo {
    int card; /* card number */
    unsigned char name[CARD_NAME_LEN];
};

typedef enum {
    PCM_CHMAP_NONE = 0, /* unspecified channel position */
    PCM_CHMAP_FIXED,    /* fixed channel position */
    PCM_CHMAP_FREELY,   /* freely swappable channel position */
    PCM_CHMAP_PAIRED,   /* pair-wise swappable channel position */
    PCM_CHMAP_LAST = PCM_CHMAP_PAIRED
} AudioPcmChmapType;

/* Audio mixer element channel identifier */
typedef enum {
    AMIXER_CHN_UNKNOWN = -1,
    AMIXER_CHN_FRONT_LEFT = 0,
    AMIXER_CHN_FRONT_RIGHT,
    AMIXER_CHN_REAR_LEFT,
    AMIXER_CHN_REAR_RIGHT,
    AMIXER_CHN_FRONT_CENTER,
    AMIXER_CHN_WOOFER,
    AMIXER_CHN_SIDE_LEFT,
    AMIXER_CHN_SIDE_RIGHT,
    AMIXER_CHN_REAR_CENTER,
    AMIXER_CHN_LAST = 31,
    AMIXER_CHN_MONO = AMIXER_CHN_FRONT_LEFT
} AudioMixerChannelIdType;

struct ChannelMask {
    const char *name;
    uint32_t mask;
};

struct AudioPcmChmap {
    uint32_t channels;  /* number of channels */
    uint32_t pos;       /* bit map for channel position */
};

struct AudioPcmChmapId {
    AudioPcmChmapType type;
    struct ChannelMask map; /* available channel map */
};

struct MixerCtsElemIdx {
    uint32_t index; /* index of item */
    struct AudioHwCtlElemId *id;
};

struct MixerCardCtlInfo {
    char cardSrvName[AUDIO_CARD_SRV_NAME_LEN];
    struct AudioHwCtlElemIndex edx;
};

struct AudioMixer {
    /**
     * @brief Gets a list of controls supported by the current sound card.
     *
     * @parm service: Audio binding control service.
     * @param mixerCts: Control list information, memory control is applied by the interface lib layer,
     * the caller obtains the information, and releases the corresponding space before exiting.
     * (Release the mixerCts->data).
     *
     * @return Returns <b>0</b> if the getting is successful; returns a negative value otherwise.
     */
    int32_t (*GetElemList)(const struct HdfIoService *service, struct AudioMixerContents *mixerCts);

    /**
     * @brief Gets the properties of the specified element of the sound card control.
     *
     * @parm service: Audio binding control service.
     * @param infoData: Gets element attribute information.
     *
     * @return Returns <b>0</b> if the mute operation is obtained; returns a negative value otherwise.
     */
    int32_t (*GetElemProp)(const struct HdfIoService *service, struct AudioMixerCtlElemInfo *infoData);

    /**
     * @brief Sets the properties of the specified element of the sound card control.
     *
     * @parm service: Audio binding control service.
     * @param infoData: Sets element attribute information.
     *
     * @return Returns <b>0</b> if the setting is successful; returns a negative value otherwise.
     */
    int32_t (*SetElemProp)(const struct HdfIoService *service, struct AudioMixerCtlElemInfo *infoData);
};

void DebugLog(bool flag);
const char *ShowVersion(void);
struct HdfIoService *MixerBindCrlSrv(const char *serviceName);
struct HdfIoService *MixerBindCrlSrvDefault(void);

void AudioMixerOpsInit(void);
int32_t MctlInfo(const struct HdfIoService *service, const char *cardSrv);
int32_t MctlList(const struct HdfIoService *service, const char *cardSrv);
int32_t MctlGetElem(const struct HdfIoService *service, struct MixerCardCtlInfo *ctlInfo);
int32_t MctlSetElem(const struct HdfIoService *srv,
                    struct MixerCardCtlInfo *ctlInfo,
                    unsigned int argc, char *argv[]);
bool MixerFindSelem(const struct HdfIoService *srv, const char *cardSrv, const struct AudioHwCtlElemId *eId);
int32_t SetChannels(const struct HdfIoService *srv, const char *cardSrv, unsigned int argc, char *argv);
int32_t GetLibsoHandle(AudioPcmType pcm);
void ReleaseCtlElemList(void);
void CloseLibsoHandle(void);
void MixerRecycleCrlSrv(struct HdfIoService *srv);
int32_t GetAllCards(const struct HdfIoService *service);
void UpdateCardSname(int card, const struct HdfIoService *srv, char * const sname, size_t snameLen);

#endif /* AUDIO_MIXER_H */
