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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "audio_mixer.h"
#include "securec.h"

#define AUDIO_MAX_CARDS   32
#define SND_CARD_NAME_LEN 64
#define INFO_BUF_LEN      128
#define CARD_SRV_NAME_LEN (SND_CARD_NAME_LEN)
#define DEFAULT_CARD_NAME "hdf_audio_codec_primary_dev0"

#define SRV_SND_PRIMARY_MIN 0
#define SRV_SND_PRIMARY_MAX 10
#define SRV_SND_HDMI_MIN    11
#define SRV_SND_HDMI_MAX    20
#define SRV_SND_USB_MIN     21
#define SRV_SND_USB_MAX     30
#define SRV_SND_A2DP_MIN    31
#define SRV_SND_A2DP_MAX    40

#define SSET_WR 0
#define SSET_RO 1
#define STRTOL_BASE 10

#define L_INACTIV (1 << 1)

struct HdfIoService *g_service = NULL;
static char g_serviceName[CARD_SRV_NAME_LEN] = DEFAULT_CARD_NAME;
static char g_card[SND_CARD_NAME_LEN] = "primary0";
static char g_dev[SND_CARD_NAME_LEN] = "default";
static AudioPcmType g_pcm = PCM_RENDER;
static bool g_debugFlag = false;
#ifdef CHANNEL_MAP
static bool chnmapFlag = false;
#endif

static int32_t ShowUsage(void)
{
    printf("Usage: audio_mixer <options> [command]\n");
    printf("\nAvailable options:\n");
    printf("  -h, --help        this help\n");
    printf("  -l, --list-cards  list all soundcards and digital audio devices\n");
    printf("  -c, --card N      select the card\n");
    printf("  -D, --device N    select the device, default '%s'\n", g_dev);
    printf("  -P, --pcm N       select the PCM type(1: reader/2: capture), default 1\n");
    printf("  -d, --debug       debug mode\n");
    printf("  -v, --version     print version of this program\n");
    printf("  -i, --inactive    show also inactive controls. (Reserved)\n");
    printf("  -S, --service N   select the audio card service default '%s'\n", DEFAULT_CARD_NAME);
#ifdef CHANNEL_MAP
    printf("  -m, --chmap=ch1,ch2,..    Give the channel map to override or follow\n");
#endif

    printf("\nAvailable commands:\n");
    printf("  info      show all info for mixer\n");
    printf("  controls  show all controls for given card\n");
    printf("  contents  show contents of all controls for given card\n");
    printf("  set ID P  set control contents for one control\n");
    printf("  get ID    get control contents for one control\n");

    return 0;
}

#ifdef LEGECY_STRATEGY
static int32_t AudioCard2Dev(int32_t card)
{
    int32_t ret;
    SND_TYPE sndType;
    char ctlDev[CARD_SRV_NAME_LEN] = {0};

    switch (card) {
        case SRV_SND_PRIMARY_MIN ... SRV_SND_PRIMARY_MAX:
            sndType = SND_PRIMARY;
            ret = sprintf_s(ctlDev, CARD_SRV_NAME_LEN - 1, "%s%d", "primary", card);
            break;
        case SRV_SND_HDMI_MIN ... SRV_SND_HDMI_MAX:
            sndType = SND_HDMI;
            ret = sprintf_s(ctlDev, CARD_SRV_NAME_LEN - 1, "%s%d", "hdmi", card);
            break;
        case SRV_SND_USB_MIN ... SRV_SND_USB_MAX:
            sndType = SND_USB;
            ret = sprintf_s(ctlDev, CARD_SRV_NAME_LEN - 1, "%s%d", "usb", card);
            break;
        case SRV_SND_A2DP_MIN ... SRV_SND_A2DP_MAX:
            sndType = SND_A2DP;
            ret = sprintf_s(ctlDev, CARD_SRV_NAME_LEN - 1, "%s%d", "a2dp", card);
            break;
        default:
            DEBUG_LOG("Unknown sound card type!\n");
            return U_FAILURE;
    }
    if (ret < 0) {
        DEBUG_LOG("Failed to synthesize the card name!\n");
        return U_FAILURE;
    }
    DEBUG_LOG("The card type: %i\n", sndType);
    DEBUG_LOG("The card name: %s\n", ctlDev);
    ret = memcpy_s(g_card, SND_CARD_NAME_LEN, ctlDev, strlen(ctlDev));
    if (ret != 0) {
        DEBUG_LOG("memcpy_s fail!\n");
        return U_FAILURE;
    }

    return U_SUCCESS;
}

static int32_t AudioCard2Dev2(const char *string, int32_t *index)
{
    int32_t ret;
    size_t len, offset;
    char *name = NULL;

    name = strrchr(string, '/') + 1;
    len = strlen(name);
    if (len == 0) {
        *index = -1;
        DEBUG_LOG("name is empty!!!\n");
        return U_FAILURE;
    }
    DEBUG_LOG("name is %s, len = %zu\n", name, len);

    offset = len - 1;
    if (isdigit(name[offset]) == 0) {
        *index = -1;
        DEBUG_LOG("name is error!!!\n");
        return U_FAILURE;
    }
    name += isdigit(name[offset - 1]) ? offset - 1 : offset;

    ret = sscanf_s(name, "%i", index);
    if (ret <= 0) {
        DEBUG_LOG("%s\n", strerror(errno));
        printf("%s\n", strerror(errno));
        return U_FAILURE;
    }

    return AudioCard2Dev(*index);
}

static int32_t AudioCardGetIndex(const char *string, int32_t *index)
{
    int32_t ret;
    int32_t card = -1;

    if (string == NULL || *string == '\0') {
        DEBUG_LOG("Invalid parameters!\n");
        return U_INVALID_PARAM;
    }

    if ((isdigit(*string) && *(string + 1) == 0) ||
        (isdigit(*string) && isdigit(*(string + 1)) && *(string + 2) == 0)) {   // 2 for offset
        /* An index was found */
        ret = sscanf_s(string, "%i", &card);
        if (ret <= 0) {
            DEBUG_LOG("%s\n", strerror(errno));
            printf("%s\n", strerror(errno));
            return U_FAILURE;
        }
        if (card < 0 || card >= AUDIO_MAX_CARDS) {
            DEBUG_LOG("%s\n", strerror(errno));
            printf("%s\n", strerror(errno));
            return U_FAILURE;
        }

        ret = AudioCard2Dev(card);
        if (ret != U_SUCCESS) {
            return ret;
        }
        *index = card;
    } else if (string[0] == '/') {
        /* Find the device name */
        return AudioCard2Dev2(string, index);
    } else {
        *index = -1;
        DEBUG_LOG("Sound card name that cannot be converted\n");
        return U_FAILURE;
    }

    return U_SUCCESS;
}
#endif

static void UpdateCardName(const char *card)
{
    int32_t id;

    if (card == NULL || *card == '\0') {
        DEBUG_LOG("Invalid card!\n");
        return;
    }

    if ((isdigit(*card) && *(card + 1) == 0) ||
        (isdigit(*card) && isdigit(*(card + 1)) && *(card + 2) == 0)) { // 2 for offset
        id = (int32_t)strtol(card, NULL, STRTOL_BASE);
        DEBUG_LOG("card %i\n", id);
        UpdateCardSname(id, g_service, g_serviceName, CARD_SRV_NAME_LEN);
        DEBUG_LOG("cardServiceName:%s, dev:%s\n", g_serviceName, g_dev);
    }
}

static int32_t MixerInfo(void)
{
    printf("card/dev: '%s'/'%s'\n", g_card, g_dev);
    printf("  Mixer name : '%s'\n", "MIXER");
    printf("  Components : '%s'\n", "Audio Components");
    printf("----------------------------------\n");
    MctlInfo(g_service, g_serviceName);

    return U_SUCCESS;
}

#ifdef LEGECY_STRATEGY
static bool CheckCardAndDev(int32_t index)
{
    switch (index) {
        case SRV_SND_PRIMARY_MIN ... SRV_SND_PRIMARY_MAX:
            DEBUG_LOG("primary%d\n", index);
            break;
        case SRV_SND_HDMI_MIN ... SRV_SND_HDMI_MAX:
            DEBUG_LOG("hdmi%d\n", index);
            break;
        case SRV_SND_USB_MIN ... SRV_SND_USB_MAX:
            DEBUG_LOG("usb%d\n", index);
            break;
        case SRV_SND_A2DP_MIN ... SRV_SND_A2DP_MAX:
            DEBUG_LOG("a2dp%d\n", index);
            break;
        default:
            DEBUG_LOG("Unknown sound card!!!\n");
            return false;
    }

    return true;
}
#endif

static int32_t MixerControls(void)
{
    if (g_service == NULL) {
        DEBUG_LOG("Invalid service!\n");
        return U_FAILURE;
    }

    return MctlList(g_service, g_serviceName);
}

static void ShowAllCardList(void)
{
    int32_t ret;

    if (g_service == NULL) {
        DEBUG_LOG("Invalid service!\n");
        return;
    }

    ret = GetAllCards(g_service);
    if (ret != U_SUCCESS) {
        DEBUG_LOG("Couldn't find any sound card equipment!\n");
    }
}

static int32_t DupCtlName(char *data, int32_t dataLen, char *buf, int32_t bufSize)
{
    int32_t ret;

    if (dataLen <= 0 || bufSize <= 0) {
        DEBUG_LOG("Unable to copy to control name space!\n");
        return U_FAILURE;
    }

    if (bufSize >= dataLen) {
        bufSize = dataLen - 1;
    }

    ret = strncpy_s(data, dataLen, buf, bufSize);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s fail!\n");
        return U_FAILURE;
    }
    data[dataLen - 1] = '\0';

    return U_SUCCESS;
}

static int32_t ParseName(const char *s, struct AudioHwCtlElemId *eId)
{
    int32_t c, size, len;
    char *ptr = NULL;
    char buf[INFO_BUF_LEN] = {0};
    char *sbuf = buf;

    ptr = strstr(s, "=");
    if (ptr == NULL) {
        DEBUG_LOG("Cannot find the given element from control default!\n");
        return U_FAILURE;
    }
    ptr++;

    size = 0;
    if (*ptr == '\"' || *ptr == '\'') {
        c = *ptr++;
        while (*ptr && *ptr != c) {
            if (size < (int32_t)sizeof(buf)) {
                *sbuf++ = *ptr;
                size++;
            }
            ptr++;
        }
        if (*ptr == c) {
            ptr++;
        }
    } else {
        while (*ptr && *ptr != ',') {
            if (size < (int32_t)sizeof(buf)) {
                *sbuf++ = *ptr;
                size++;
            }
            ptr++;
        }
    }
    *sbuf = (*ptr == '\0') ? *ptr : '\0';
    DEBUG_LOG("control name=%s, size=%d\n", buf, size);
    len = (int32_t)sizeof(eId->name);

    return DupCtlName((char *)eId->name, len, buf, size);
}

static int32_t ParseNumId(const char *s, uint32_t *idx)
{
    int32_t numid;
    char *ptr = NULL;

    ptr = strstr(s, "=");
    if (ptr == NULL) {
        DEBUG_LOG("Cannot find the given element from control default!\n");
        return U_FAILURE;
    }
    ptr++;

    if (!isdigit(*ptr)) {
        DEBUG_LOG("Invalid elem index!\n");
        printf("Invalid elem index!\n");
        return U_FAILURE;
    }

    numid = (int32_t)strtol(ptr, NULL, STRTOL_BASE);
    if (numid <= 0) {
        DEBUG_LOG("audio_mixer: Invalid numid %d\n", numid);
        return U_FAILURE;
    }
    *idx = (uint32_t)numid;

    return U_SUCCESS;
}

static int32_t ParseElemIndex(const char *str, struct AudioHwCtlElemIndex *sid)
{
    int32_t ret;

    while (isspace(*str) || *str == '\t') {
        str++;
    }

    if (!(*str)) {
        DEBUG_LOG("Invalid elem index string!\n");
        return U_FAILURE;
    }

    sid->eId.iface = AUDIO_CTL_ELEM_IFACE_MIXER;
    if (strncasecmp(str, "name", strlen("name")) == 0) {
        ret = ParseName(str + strlen("name"), &sid->eId);
        if (ret != U_SUCCESS) {
            DEBUG_LOG("Invalid elem index string!\n");
            printf("Invalid elem index string!\n");
            return U_FAILURE;
        }
        sid->index = 0;
    } else if (strncasecmp(str, "numid", strlen("numid")) == 0) {
        ret = ParseNumId(str + strlen("numid"), &sid->index);
        if (ret != U_SUCCESS) {
            DEBUG_LOG("Invalid elem index string!\n");
            printf("Invalid elem index string!\n");
            return U_FAILURE;
        }
        while (!isdigit(*str)) {
            str++;
        }
    } else {
        DEBUG_LOG("Cannot be resolved at present %s!\n", str);
        return U_FAILURE;
    }

    return U_SUCCESS;
}

static int32_t FillSndCardName(struct MixerCardCtlInfo *ctlInfo)
{
    int32_t ret;

    if (strlen(g_serviceName) == 0) {
        DEBUG_LOG("The sound card service name is error!\n");
        return U_FAILURE;
    }

    ret = strncpy_s(ctlInfo->cardSrvName, AUDIO_CARD_SRV_NAME_LEN, g_serviceName, strlen(g_serviceName));
    if (ret != 0) {
        DEBUG_LOG("strncpy_s fail!\n");
        return U_FAILURE;
    }
    ctlInfo->cardSrvName[AUDIO_CARD_SRV_NAME_LEN - 1] = '\0';

    return U_SUCCESS;
}

static int32_t MixerESet(unsigned int argc, char *argv[], int32_t roflag)
{
    int32_t ret, slen;
    struct MixerCardCtlInfo ctlInfo;

    if (argc < 1) {
        printf("Specify a full control identifier: "
               "[[iface=<iface>,][name='name',]"
               "[index=<index>,]] | [numid=<numid>]\n");
        return U_FAILURE;
    }

    slen = (int32_t)sizeof(struct MixerCardCtlInfo);
    memset_s(&ctlInfo, slen, 0, slen);
    ret = ParseElemIndex(argv[0], &ctlInfo.edx);
    if (ret != U_SUCCESS) {
        DEBUG_LOG("Wrong scontrol identifier: %s\n", argv[0]);
        printf("Wrong scontrol identifier: %s\n", argv[0]);
        return U_FAILURE;
    }
    if (g_debugFlag) {
        printf("index=%u, iface=%s, name='%s'\n", ctlInfo.edx.index, STRING(MIXER), ctlInfo.edx.eId.name);
    }

    if (roflag == SSET_WR && argc < 2) {    // 2 for number of argcs
        DEBUG_LOG("Specify what you want to set...\n");
        printf("Specify what you want to set...\n");
        return U_FAILURE;
    }

    /* Query whether the control to be set exists. */
    if (!MixerFindSelem(g_service, g_serviceName, &ctlInfo.edx.eId)) {
        DEBUG_LOG("Can't find scontrol identifier: %s, %i\n", ctlInfo.edx.eId.name, ctlInfo.edx.index);
        return U_FAILURE;
    }

    ret = FillSndCardName(&ctlInfo);
    if (ret != U_SUCCESS) {
        return ret;
    }

    if (roflag == SSET_WR) {
        ret = MctlSetElem(g_service, &ctlInfo, argc, argv);
        if (ret != U_SUCCESS) {
            return ret;
        }
    }

    return MctlGetElem(g_service, &ctlInfo);
}

static int32_t ServiceHandleInit(void)
{
    int32_t ret;

    ret = GetLibsoHandle(g_pcm);
    if (ret != U_SUCCESS) {
        return ret;
    }

    if (g_service != NULL) {
        return U_SUCCESS;
    }

    if (strlen(g_serviceName) >= CARD_SRV_NAME_LEN) {
        g_service = MixerBindCrlSrvDefault();
    } else {
        g_service = MixerBindCrlSrv(g_serviceName);
    }
    if (g_service == NULL) {
        DEBUG_LOG("Failed to obtain the service!\n");
        CloseLibsoHandle();
        return U_FAILURE;
    }

    return U_SUCCESS;
}

static void FreeGlobal(void)
{
    ReleaseCtlElemList();
    MixerRecycleCrlSrv(g_service);
    CloseLibsoHandle();
}

static void GetPcm(const char *string)
{
    int type;

    type = (int32_t)strtol(string, NULL, STRTOL_BASE);
    switch (type) {
        case PCM_RENDER:
            g_pcm = PCM_RENDER;
            break;
        case PCM_CAPTURE:
            g_pcm = PCM_CAPTURE;
            break;
        default:
            DEBUG_LOG("Wrong PCM type!\n");
            break;
    }
}

#ifdef CHANNEL_MAP
static int32_t MixerSetChannels(unsigned int argc, char *str)
{
    if (argc < 1) {
        DEBUG_LOG("Channels error!\n");
        return U_FAILURE;
    }

    return SetChannels(g_service, g_serviceName, argc, str);
}
#endif

int main(int argc, char *argv[])
{
    int32_t ret;
    int32_t c;
    int32_t optionIndex = -1;
#ifdef LEGECY_STRATEGY
    int index = 0;
#else
    int updateId = 0;
    char *newCard = NULL;
#endif
    int badOpt = 0;
    int level = 0;
#ifdef CHANNEL_MAP
    int chnmapId = 0;
    char *chnmapString = "front,render,2";
#endif
    bool doDeviceList = false;
    bool doUpdateCardName = false;
    static const struct option longOpts[] = {
        {"help",       0, NULL, 'h'},
        {"list-cards", 0, NULL, 'l'},
        {"card",       1, NULL, 'c'},
        {"device",     1, NULL, 'D'},
        {"pcm",        1, NULL, 'P'},
        {"inactive",   0, NULL, 'i'},
        {"debug",      0, NULL, 'd'},
        {"version",    0, NULL, 'v'},
        {"service",    1, NULL, 'S'},
#ifdef CHANNEL_MAP
        {"chmap",      1, NULL, 'm'},
#endif
        {NULL,         0, NULL, 0  }
    };

    static const char shortOptions[] = "hlc:D:P:idvS:"
#ifdef CHANNEL_MAP
                                       "m:"
#endif
        ;

    while (1) {
        c = getopt_long(argc, argv, shortOptions, longOpts, &optionIndex);
        if (c < 0) {
            DEBUG_LOG("Parameter parsing completed!\n");
            break;
        }

        switch (c) {
            case 'h':
                ShowUsage();
                return 0;
            case 'l':
                doDeviceList = true;
                break;
            case 'c':
#ifdef LEGECY_STRATEGY
                ret = AudioCardGetIndex(optarg, &index);
                if (ret != U_SUCCESS) {
                    return ret;
                }
                if (!CheckCardAndDev(index)) {
                    fprintf(stderr, "Invalid card number '%s'.\n", optarg);
                    badOpt++;
                }
#else
                /* The new version conversion policy is enabled. */
                doUpdateCardName = true;
                updateId = optind;
                newCard = optarg;
#endif
                break;
            case 'D':
                ret = strncpy_s(g_dev, SND_CARD_NAME_LEN - 1, optarg, strlen(optarg));
                if (ret != 0) {
                    DEBUG_LOG("strncpy_s fail!\n");
                    goto FINISH;
                }
                g_dev[sizeof(g_dev) - 1] = '\0';

                break;
            case 'P':
                GetPcm(optarg);
                break;
            case 'i':
                level |= L_INACTIV;
                printf("Reserved Parameters. [level %i]\n", level);
                return 0;
            case 'd':
                g_debugFlag = true;
                break;
            case 'v':
                printf("audio_mixer version %s\n", ShowVersion());
                return 0;
            case 'S':
                ret = strncpy_s(g_serviceName, CARD_SRV_NAME_LEN - 1, optarg, strlen(optarg));
                if (ret != 0) {
                    DEBUG_LOG("strncpy_s fail!\n");
                    goto FINISH;
                }
                g_serviceName[strlen(optarg)] = '\0';

                break;
#ifdef CHANNEL_MAP
            case 'm':
                chnmapFlag = true;
                chnmapId = optind;
                chnmapString = optarg;

                break;
#endif
            default:
                fprintf(stderr, "Invalid switch or option -%c needs an argument.\n", c);
                badOpt++;
        }
    }
    if (badOpt) {
        ERR_LOG("The argument passed in was incorrect!\n");
        return 1;
    }

    DebugLog(g_debugFlag);
    ret = ServiceHandleInit();
    if (ret != U_SUCCESS) {
        goto FINISH;
    }
    AudioMixerOpsInit();

    if (doDeviceList) {
        ShowAllCardList();
        goto FINISH;
    }

#ifdef CHANNEL_MAP
    if (chnmapFlag) {
        if (chnmapId < 1) {
            chnmapId = 1;
        }
        ret = MixerSetChannels((unsigned int)chnmapId, chnmapString);
        if (ret != U_SUCCESS) {
            DEBUG_LOG("Unable to parse channel map string: %s\n", optarg);
        }
        goto FINISH;
    }
#endif

    if (doUpdateCardName) {
        UpdateCardName(newCard);
        if (argc - optind <= 0) {
            ret = 0;
            goto FINISH;
        }
    }

    if (argc - optind <= 0) {
        DEBUG_LOG("The parameter passed in is incorrect, argc = %i, optind = %i\n", argc, optind);
        printf("Use this parameter together with other parameters!\n");
        ShowUsage();
        ret = 0;
        goto FINISH;
    }

    if (strcmp(argv[optind], "help") == 0) {
        ret = ShowUsage() ? 1 : 0;
    } else if (strcmp(argv[optind], "info") == 0) {
        ret = MixerInfo() ? 1 : 0;
    } else if (strcmp(argv[optind], "controls") == 0) {
        ret = MixerControls() ? 1 : 0;
    } else if (strcmp(argv[optind], "contents") == 0) {
        ret = MixerControls() ? 1 : 0;
    } else if (strcmp(argv[optind], "set") == 0) {
        ret = MixerESet(argc - optind - 1, (argc - optind > 1) ? (argv + optind + 1) : NULL, SSET_WR) ? 1 : 0;
    } else if (strcmp(argv[optind], "get") == 0) {
        ret = MixerESet(argc - optind - 1, (argc - optind > 1) ? (argv + optind + 1) : NULL, SSET_RO) ? 1 : 0;
    } else {
        fprintf(stderr, "audio_mixer: Unknown command '%s'...\n", argv[optind]);
        ret = 0;
    }

FINISH:
    /* Releasing Global Resources. */
    FreeGlobal();

    return ret;
}
