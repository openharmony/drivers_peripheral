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

#include "audio_mixer.h"

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "hdf_base.h"
#include "securec.h"

#define AUDIO_UTIL_VERSION_STR "V1.0.0"

#define AUDIO_DEV_FILE_PATH    "/dev/"
#define CTL_SRV_NAME_PRE       "hdf_audio_control"
#define CTL_SRV_DEFAULT        CTL_SRV_NAME_PRE
#define MIXER_SRV_NAME_PRE     "hdf_audio_codec_"
#define MIXER_SRV_NAME         MIXER_SRV_NAME_PRE "%s_dev%i"
#define MIXER_SRV_NAME_DEFAULT MIXER_SRV_NAME_PRE "primary_dev0"
#define SERVICE_NAME_LEN       64
#define BUF_SIZE_T             256
#define CHN_MONO               (1 << 0)
#define CHN_STEREO             (1 << 1)
#define OUTPUT_ALIGN           16
#define BIT_VALULE_OFFSET      31
#define STRTOL_BASE            10

#define IFACE(v) [AUDIO_CTL_ELEM_IFACE_##v] = #v
#define TYPE(v)  [AUDIO_CTL_ELEM_TYPE_##v] = #v

static struct AudioMixer g_audioMixer;
static struct AudioMixerContents g_mixerCts;

static const char *g_capLibPath = HDF_LIBRARY_FULL_PATH("libaudio_capture_adapter");
static const char *g_renLibPath = HDF_LIBRARY_FULL_PATH("libaudio_render_adapter");
static void *g_soHandle = NULL;
static AudioPcmType g_pcmT = PCM_RENDER;
static bool g_debugFlag = false;

static const char * const ctlEIfNames[] = {
    IFACE(CARD),
    IFACE(PCM),
    IFACE(MIXER),
};

static const char * const ctlElemTypeNames[] = {
    TYPE(NONE),
    TYPE(BOOLEAN),
    TYPE(INTEGER),
    TYPE(ENUMERATED),
    TYPE(BYTES),
};

void DebugLog(bool flag)
{
    g_debugFlag = flag;
}

static void *CallLibFunction(const char *funcName)
{
    void *func = NULL;
    char *error = NULL;

    if (g_soHandle == NULL) {
        DEBUG_LOG("Invalid dynamic library handle!\n");
        return NULL;
    }

    (void)dlerror(); /* Clear any existing error */
    func = dlsym(g_soHandle, funcName);
    error = dlerror();
    if (error != NULL) {
        DEBUG_LOG("%s\n", error);
        printf("%s\n", error);
        return NULL;
    }

    return func;
}

static int32_t AudioMixerList(const struct HdfIoService *service, struct AudioMixerContents *mixerCts)
{
    int32_t (*AmixerCtlElemList)(AudioPcmType, const struct HdfIoService *, struct AudioMixerContents *);

    AmixerCtlElemList = CallLibFunction("AudioMixerCtlElem");
    if (AmixerCtlElemList == NULL) {
        return U_FAILURE;
    }

    return AmixerCtlElemList(g_pcmT, service, mixerCts);
}

static int32_t AudioMixerGet(const struct HdfIoService *service, struct AudioMixerCtlElemInfo *infoData)
{
    int32_t (*AmixerGetCtlElem)(AudioPcmType, const struct HdfIoService *, struct AudioMixerCtlElemInfo *);

    AmixerGetCtlElem = CallLibFunction("AudioMixerCtlGetElem");
    if (AmixerGetCtlElem == NULL) {
        return U_FAILURE;
    }

    return AmixerGetCtlElem(g_pcmT, service, infoData);
}

static int32_t AudioMixerSet(const struct HdfIoService *service, struct AudioMixerCtlElemInfo *infoData)
{
    int32_t (*AmixerSetCtlElem)(AudioPcmType, const struct HdfIoService *, struct AudioMixerCtlElemInfo *);

    AmixerSetCtlElem = CallLibFunction("AudioMixerCtlSetElem");
    if (AmixerSetCtlElem == NULL) {
        return U_FAILURE;
    }

    return AmixerSetCtlElem(g_pcmT, service, infoData);
}

static int32_t GetSoHandle(const char *filename)
{
    char buf[PATH_MAX] = {0};

    if (realpath(filename, buf) == NULL) {
        return U_FAILURE;
    }

    if (g_soHandle != NULL) {
        DEBUG_LOG("It's been initialized!\n");
        return U_SUCCESS;
    }

    g_soHandle = dlopen(buf, RTLD_LAZY);
    if (g_soHandle == NULL) {
        DEBUG_LOG("%s\n", dlerror());
        printf("%s\n", dlerror());
        return U_FAILURE;
    }

    return U_SUCCESS;
}

int32_t GetLibsoHandle(AudioPcmType pcm)
{
    int32_t ret;

    g_pcmT = pcm;
    switch (pcm) {
        default:
            DEBUG_LOG("Wrong PCM type!\n");
            /* fall through */
            __attribute__((fallthrough));
        case PCM_RENDER:
            ret = GetSoHandle(g_renLibPath);
            if (ret != U_SUCCESS) {
                DEBUG_LOG("Failed to open the render dynamic library!\n");
            }
            break;
        case PCM_CAPTURE:
            ret = GetSoHandle(g_capLibPath);
            if (ret != U_SUCCESS) {
                DEBUG_LOG("Failed to open the capture dynamic library!\n");
            }
            break;
    }

    return ret;
}

void CloseLibsoHandle(void)
{
    if (g_soHandle != NULL) {
        (void)dlclose(g_soHandle);
        g_soHandle = NULL;
    }
}

void AudioMixerOpsInit(void)
{
    g_audioMixer.GetElemList = AudioMixerList;
    g_audioMixer.GetElemProp = AudioMixerGet;
    g_audioMixer.SetElemProp = AudioMixerSet;

    g_mixerCts.data = NULL;
    g_mixerCts.elemNum = 0;
    (void)memset_s(g_mixerCts.cardServiceName, AUDIO_CARD_SRV_NAME_LEN, 0x0, AUDIO_CARD_SRV_NAME_LEN);
}

const char *ShowVersion(void)
{
    return AUDIO_UTIL_VERSION_STR;
}

static bool CheckMixerDevFile(const char *file)
{
    char buf[PATH_MAX] = {0};

    if (realpath(file, buf) == NULL) {
        DEBUG_LOG("%s\n", strerror(errno));
        return false;
    }

    if (access(file, F_OK)) {
        DEBUG_LOG("%s\n", strerror(errno));
        return false;
    }

    return true;
}

struct HdfIoService *MixerBindCrlSrvDefault(void)
{
    int ret;
    char buf[BUF_SIZE_T + 1] = {0};
    struct HdfIoService *(*SrvBindDef)(const char *);

    ret = snprintf_s(buf, BUF_SIZE_T, BUF_SIZE_T, "%s%s", AUDIO_DEV_FILE_PATH, MIXER_SRV_NAME_DEFAULT);
    if (ret < 0) {
        DEBUG_LOG("Failed to synthesize the service path!\n");
        return NULL;
    }

    if (!CheckMixerDevFile(buf)) {
        /* The sound card service file does not exist */
        return NULL;
    }

    SrvBindDef = CallLibFunction("HdfIoServiceBindName");
    if (SrvBindDef == NULL) {
        return NULL;
    }

    return SrvBindDef(CTL_SRV_DEFAULT);
}

struct HdfIoService *MixerBindCrlSrv(const char *serviceName)
{
    int ret;
    char path[BUF_SIZE_T + 1] = {0};
    struct HdfIoService *(*SrvBind)(const char *);

    if (serviceName == NULL) {
        DEBUG_LOG("Invalid parameters!\n");
        return NULL;
    }

    if (strncmp(serviceName, MIXER_SRV_NAME_PRE, strlen(MIXER_SRV_NAME_PRE))) {
        DEBUG_LOG("The service name does not match!\n");
        return NULL;
    }

    ret = snprintf_s(path, BUF_SIZE_T, BUF_SIZE_T, "%s%s", AUDIO_DEV_FILE_PATH, serviceName);
    if (ret < 0) {
        DEBUG_LOG("Failed to synthesize the service path!\n");
        return NULL;
    }
    if (!CheckMixerDevFile(path)) {
        /* The sound card service file does not exist */
        return NULL;
    }

    SrvBind = CallLibFunction("HdfIoServiceBindName");
    if (SrvBind == NULL) {
        return NULL;
    }

    return SrvBind(CTL_SRV_DEFAULT);
}

void MixerRecycleCrlSrv(struct HdfIoService *srv)
{
    void (*SrvRecycle)(struct HdfIoService *);

    if (srv != NULL) {
        SrvRecycle = CallLibFunction("AudioCloseServiceSub");
        if (SrvRecycle != NULL) {
            SrvRecycle(srv);
        }
    }
}

static const char *CtlElemIfaceName(AudioCtlElemIfaceType iface)
{
    return ctlEIfNames[iface];
}

static const char *CtlElemName(struct AudioHwCtlElemIndex *id)
{
    return (const char *)id->eId.name;
}

static void PrintCtlElemInfo(struct AudioHwCtlElemId *id)
{
    printf("iface=%s, name='%s'\n", CtlElemIfaceName(id->iface), id->name);
}

static void PrintCtlElemInfoidx(struct MixerCtsElemIdx *eidx)
{
    printf("index=%u, numid=%u, ", eidx->index, eidx->index + 1);
    PrintCtlElemInfo(eidx->id);
}

static void PrintCtlElemList(struct AudioMixerContents *contents)
{
    uint32_t num, idx;
    struct MixerCtsElemIdx eidx;
    struct AudioHwCtlElemId *id = NULL;

    num = contents->elemNum;
    id = (struct AudioHwCtlElemId *)contents->data;
    for (idx = 0; idx < num; idx++) {
        eidx.id = id++;
        eidx.index = idx;
        PrintCtlElemInfoidx(&eidx);
    }
}

void ReleaseCtlElemList(void)
{
    if (g_mixerCts.data != NULL) {
        free(g_mixerCts.data);
        g_mixerCts.data = NULL;
    }
    g_mixerCts.elemNum = 0;
    (void)memset_s(g_mixerCts.cardServiceName, AUDIO_CARD_SRV_NAME_LEN, 0x0, AUDIO_CARD_SRV_NAME_LEN);
}

static int32_t MctlListSub(const struct HdfIoService *service, const char *cardSrv)
{
    int32_t ret;

    ret = strncpy_s(g_mixerCts.cardServiceName, AUDIO_CARD_SRV_NAME_LEN - 1, cardSrv, AUDIO_CARD_SRV_NAME_LEN - 1);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s fail!\n");
        return U_FAILURE;
    }
    g_mixerCts.cardServiceName[AUDIO_CARD_SRV_NAME_LEN - 1] = '\0';
    if (g_audioMixer.GetElemList == NULL) {
        DEBUG_LOG("The callback function is NULL!\n");
        return U_FAILURE;
    }

    if (g_mixerCts.data != NULL && g_mixerCts.elemNum > 0) {
        /* The list of control elements has been obtained */
        return U_SUCCESS;
    }

    if (g_mixerCts.data != NULL) {
        free(g_mixerCts.data);
        g_mixerCts.data = NULL;
    }
    g_mixerCts.elemNum = 0;

    ret = g_audioMixer.GetElemList(service, &g_mixerCts);
    if (ret != U_SUCCESS) {
        return ret;
    }
    if (g_mixerCts.data == NULL) {
        g_mixerCts.elemNum = 0;
        (void)memset_s(g_mixerCts.cardServiceName, AUDIO_CARD_SRV_NAME_LEN, 0x0, AUDIO_CARD_SRV_NAME_LEN);
        DEBUG_LOG("Failed to obtain data!\n");
        return U_FAILURE;
    }
    if (g_mixerCts.elemNum == 0) {
        free(g_mixerCts.data);
        g_mixerCts.data = NULL;
        (void)memset_s(g_mixerCts.cardServiceName, AUDIO_CARD_SRV_NAME_LEN, 0x0, AUDIO_CARD_SRV_NAME_LEN);
        DEBUG_LOG("Description Failed to obtain the number of data!\n");
        return U_FAILURE;
    }

    return U_SUCCESS;
}

int32_t MctlList(const struct HdfIoService *service, const char *cardSrv)
{
    int32_t ret;

    if (service == NULL || cardSrv == NULL) {
        DEBUG_LOG("Invalid parameters!\n");
        return U_INVALID_PARAM;
    }

    ret = MctlListSub(service, cardSrv);
    if (ret != U_SUCCESS) {
        return ret;
    }
    PrintCtlElemList(&g_mixerCts);

    return U_SUCCESS;
}

int32_t MctlInfo(const struct HdfIoService *service, const char *cardSrv)
{
    int32_t ret;
    uint32_t num;
    struct AudioHwCtlElemId *id;

    if (g_mixerCts.data == NULL || g_mixerCts.elemNum == 0) {
        ReleaseCtlElemList();
        ret = MctlListSub(service, cardSrv);
        if (ret != U_SUCCESS) {
            DEBUG_LOG("No reference data\n");
            return ret;
        }
    }

    /* The list of control elements has been obtained */
    num = g_mixerCts.elemNum;
    id = (struct AudioHwCtlElemId *)g_mixerCts.data;
    while (num--) {
        PrintCtlElemInfo(id++);
    }
    ReleaseCtlElemList();

    return U_SUCCESS;
}

bool MixerFindSelem(const struct HdfIoService *srv, const char *cardSrv, const struct AudioHwCtlElemId *eId)
{
    int32_t ret;
    uint32_t index;
    struct AudioHwCtlElemId *findElem;

    if (eId == NULL) {
        DEBUG_LOG("Invalid parameters\n");
        return false;
    }

    if (g_mixerCts.elemNum == 0 || g_mixerCts.data == NULL) {
        ReleaseCtlElemList();
        ret = MctlListSub(srv, cardSrv);
        if (ret != U_SUCCESS) {
            DEBUG_LOG("No reference data\n");
            return false;
        }
    }

    findElem = g_mixerCts.data;
    for (index = 0; index < g_mixerCts.elemNum; index++) {
        if (strcmp(eId->name, findElem[index].name) == 0) {
            break;
        }
    }
    if (index == g_mixerCts.elemNum) {
        DEBUG_LOG("The corresponding control does not match!\n");
        ReleaseCtlElemList();
        return false;
    }
    ReleaseCtlElemList();

    return true;
}

static AudioCtlElemIfaceType GetCtlElemIface(struct AudioHwCtlElemIndex *id)
{
    return id->eId.iface;
}

static unsigned int CtlElemGetIdx(struct AudioHwCtlElemIndex *id)
{
    return id->index;
}

static unsigned int CtlElemInfoCnt(struct AudioMixerCtlElemInfo *info)
{
    return info->count;
}

static AudioCtlElemType CtlElemGetInfoType(struct AudioMixerCtlElemInfo *info)
{
    return info->type;
}

static const char *CtlElemTypeName(AudioCtlElemType type)
{
    return ctlElemTypeNames[type];
}

static const char *MixerCtlType(struct AudioMixerCtlElemInfo *info)
{
    return CtlElemTypeName(CtlElemGetInfoType(info));
}

static int32_t CtlElemInfoGetMin(struct AudioMixerCtlElemInfo *info)
{
    return info->value.intVal.min;
}

static int32_t CtlElemInfoGetMax(struct AudioMixerCtlElemInfo *info)
{
    return info->value.intVal.max;
}

static int32_t CtlElemInfoGetStep(struct AudioMixerCtlElemInfo *info)
{
    return info->value.intVal.step;
}

static long *CtlElemInfoGetVals(struct AudioMixerCtlElemInfo *info)
{
    return info->value.intVal.vals;
}

static void CtlElemInfoSetItem(struct AudioMixerCtlElemInfo *info, uint32_t val)
{
    info->value.enumVal.item = val;
}

static uint32_t CtlElemInfoGetItems(struct AudioMixerCtlElemInfo *info)
{
    return info->value.enumVal.items;
}

static uint32_t CtlElemInfoGetItem(struct AudioMixerCtlElemInfo *info)
{
    return info->value.enumVal.item;
}

static char *CtlElemInfoGetItemName(struct AudioMixerCtlElemInfo *info)
{
    return info->value.enumVal.name;
}

static int32_t CtlElemValueGetBoolean(struct AudioMixerCtlElemInfo *info, uint32_t idx)
{
    if (idx > BIT_VALULE_OFFSET - 1) {
        return 0;
    }

    return ((info->value.intVal.max >> idx) & 0x1);
}

static int32_t CtlElemValueGetInt(struct AudioMixerCtlElemInfo *info, uint32_t idx)
{
    return CtlElemValueGetBoolean(info, idx);
}

static char CtlElemValueGetByte(struct AudioMixerCtlElemInfo *info, uint32_t idx)
{
    if (idx >= RESERVED_BUF_LEN) {
        return '?';
    }

    return info->value.reserved[idx];
}

static unsigned char *CtlElemValueGetBytes(struct AudioMixerCtlElemInfo *info)
{
    return info->value.reserved;
}

static uint32_t CtlElemValueGetEnum(struct AudioMixerCtlElemInfo *info, uint32_t idx)
{
    if (idx > BIT_VALULE_OFFSET) {
        return 0;
    }

    return ((info->value.enumVal.item >> idx) & 0x1);
}

static void PrintOtherVal(struct AudioMixerCtlElemInfo *info)
{
    uint32_t idx;
    unsigned int count;
    AudioCtlElemType type;

    type = CtlElemGetInfoType(info);
    count = CtlElemInfoCnt(info);
    for (idx = 0; idx < count; idx++) {
        if (idx > 0) {
            printf(", ");
        }

        switch (type) {
            case AUDIO_CTL_ELEM_TYPE_BOOLEAN:
                printf("%s", CtlElemValueGetBoolean(info, idx) ? "on" : "off");
                break;
            case AUDIO_CTL_ELEM_TYPE_BYTES:
                printf("0x%02x", CtlElemValueGetByte(info, idx));
                break;
            case AUDIO_CTL_ELEM_TYPE_INTEGER:
                printf("%i", CtlElemValueGetInt(info, idx));
                break;
            case AUDIO_CTL_ELEM_TYPE_ENUMERATED:
                printf("%u", CtlElemValueGetEnum(info, idx));
                break;
            default:
                printf("?");
                break;
        }
    }
    printf("\n");
}

static void PrintValue(struct AudioMixerCtlElemInfo *info)
{
    long *ptr;
    uint32_t idx, items;
    AudioCtlElemType type;

    type = CtlElemGetInfoType(info);
    switch (type) {
        case AUDIO_CTL_ELEM_TYPE_INTEGER:
            printf(", min=%i, max=%i, step=%i\n",
                CtlElemInfoGetMin(info),
                CtlElemInfoGetMax(info),
                CtlElemInfoGetStep(info));
            ptr = CtlElemInfoGetVals(info);
            printf("  : values=");
            for (idx = 0; idx < info->count; idx++) {
                if (idx > 0) {
                    printf(", ");
                }
                printf("%i", (int)ptr[idx]);
            }
            printf("\n");
            break;
        case AUDIO_CTL_ELEM_TYPE_ENUMERATED:
            {
                items = CtlElemInfoGetItems(info);
                printf(", items=%u\n", items);
                for (idx = 0; idx < items; idx++) {
                    CtlElemInfoSetItem(info, idx);
                    printf("%s; Item #%u '%s'\n", "  ", idx, CtlElemInfoGetItemName(info));
                }
                printf("  : values=%u\n", CtlElemInfoGetItem(info));
            }
            break;
        case AUDIO_CTL_ELEM_TYPE_BOOLEAN:
            printf("\n  : values=");
            PrintOtherVal(info);
            break;
        case AUDIO_CTL_ELEM_TYPE_BYTES:
            printf("  : values=%s\n", CtlElemValueGetBytes(info));
            break;
        default:
            DEBUG_LOG("Mismatched control value type!\n");
            break;
    }
}

static void ShowIntVal(struct AudioMixerCtlElemInfo *info)
{
    int32_t ret;
    uint32_t index;
    unsigned int count;
    const char *iface;
    const char *space = "  ";
    char buf[BUF_SIZE_T + 1] = {0};

    index = CtlElemGetIdx(&info->eIndexId);
    iface = CtlElemIfaceName(GetCtlElemIface(&info->eIndexId));
    if (index > 0) {
        ret = snprintf_s(buf, BUF_SIZE_T, BUF_SIZE_T, "index=%u, iface=%s, name=%s",
            index, iface, CtlElemName(&info->eIndexId));
    } else {
        ret = snprintf_s(buf, BUF_SIZE_T, BUF_SIZE_T, "iface=%s, name=%s",
            iface, CtlElemName(&info->eIndexId));
    }
    if (ret < 0) {
        DEBUG_LOG("Failed to snprintf_s!\n");
        return;
    }

    buf[BUF_SIZE_T] = '\0';
    printf("%s\n", buf);

    count = CtlElemInfoCnt(info);
    printf("%s; type=%s, values=%u", space, MixerCtlType(info), count);
    PrintValue(info);
}

static void ShowEnumVal(struct AudioMixerCtlElemInfo *info)
{
    printf("  : values=%u\n", CtlElemInfoGetItem(info));
}

static void ShowBytesVal(const unsigned char *data)
{
    int i;
    const unsigned char *p = data;

    printf("\ndata:\t");
    for (i = 0; i < RESERVED_BUF_LEN; i++) {
        if (*p == '\0') {
            break;
        }

        if ((i % OUTPUT_ALIGN) == 0) {
            printf("\n");
        }
        printf("0x%02x \n", *p++);
    }
    printf("\n");
    printf("string: %s\n", data);
}

static void ShowElemInfo(struct AudioMixerCtlElemInfo *info)
{
    switch (info->type) {
        case AUDIO_CTL_ELEM_TYPE_INTEGER:
        case AUDIO_CTL_ELEM_TYPE_BOOLEAN:
            ShowIntVal(info);
            break;
        case AUDIO_CTL_ELEM_TYPE_ENUMERATED:
            ShowEnumVal(info);
            break;
        case AUDIO_CTL_ELEM_TYPE_BYTES:
            ShowBytesVal(info->value.reserved);
            break;
        default:
            DEBUG_LOG("Mismatched control value type!\n");
            break;
    }
}

int32_t MctlGetElem(const struct HdfIoService *service, struct MixerCardCtlInfo *ctlInfo)
{
    int32_t ret;
    struct AudioMixerCtlElemInfo info;

    if (service == NULL || ctlInfo == NULL) {
        DEBUG_LOG("Invalid parameters!\n");
        return U_INVALID_PARAM;
    }

    ret = strncpy_s(info.cardSrvName, AUDIO_CARD_SRV_NAME_LEN - 1, ctlInfo->cardSrvName, AUDIO_CARD_SRV_NAME_LEN - 1);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s cardSrvName fail!\n");
        return U_FAILURE;
    }
    info.cardSrvName[AUDIO_CARD_SRV_NAME_LEN - 1] = '\0';
    ret = strncpy_s(info.eIndexId.eId.name, AUDIO_ELEM_NAME_LEN - 1, ctlInfo->edx.eId.name, AUDIO_ELEM_NAME_LEN - 1);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s element name fail!\n");
        return U_FAILURE;
    }
    info.eIndexId.eId.name[AUDIO_ELEM_NAME_LEN - 1] = '\0';
    info.eIndexId.eId.iface = ctlInfo->edx.eId.iface;
    // need info.type
    info.type = AUDIO_CTL_ELEM_TYPE_INTEGER;

    if (g_audioMixer.GetElemProp == NULL) {
        DEBUG_LOG("The callback function is NULL!\n");
        return U_FAILURE;
    }
    ret = g_audioMixer.GetElemProp(service, &info);
    if (ret != U_SUCCESS) {
        DEBUG_LOG("Failed to get control!\n");
        return U_FAILURE;
    }
    ShowElemInfo(&info);

    return U_SUCCESS;
}

static const struct ChannelMask g_chnMask[] = {
    {"frontleft",   1 << AMIXER_CHN_FRONT_LEFT                                    },
    {"frontright",  1 << AMIXER_CHN_FRONT_RIGHT                                   },
    {"frontcenter", 1 << AMIXER_CHN_FRONT_CENTER                                  },
    {"front",       ((1 << AMIXER_CHN_FRONT_LEFT) | (1 << AMIXER_CHN_FRONT_RIGHT))},
    {"center",      1 << AMIXER_CHN_FRONT_CENTER                                  },
    {"rearleft",    1 << AMIXER_CHN_REAR_LEFT                                     },
    {"rearright",   1 << AMIXER_CHN_REAR_RIGHT                                    },
    {"rear",        ((1 << AMIXER_CHN_REAR_LEFT) | (1 << AMIXER_CHN_REAR_RIGHT))  },
    {"woofer",      1 << AMIXER_CHN_WOOFER                                        },
    {NULL,          0                                                             }
};

static uint32_t ChannelsMask(char **ptr, unsigned int chns)
{
    const struct ChannelMask *msk;

    for (msk = g_chnMask; msk->name != NULL; msk++) {
        if (strncasecmp(*ptr, msk->name, strlen(msk->name)) == 0) {
            /* Stop loop at specified character. */
            while (**ptr != '\0' && **ptr != ',' && **ptr != ' ' && **ptr != '\t') {
                (*ptr)++;
            }
            /* Skip the specified character. */
            if (**ptr == ',' || **ptr == ' ' || **ptr == '\t') {
                (*ptr)++;
            }

            return msk->mask;
        }
    }

    return chns;
}

static uint32_t DirMask(char **ptr, unsigned int dir)
{
    int find = 0;

    /* Stop loop at specified character. */
    while (**ptr != '\0' && **ptr != ',' && **ptr != ' ' && **ptr != '\t') {
        (*ptr)++;
    }

    /* Skip the specified character. */
    if (**ptr == ',' || **ptr == ' ' || **ptr == '\t') {
        (*ptr)++;
    }

    if (strncasecmp(*ptr, "render", strlen("render")) == 0) {
        dir = find = PCM_RENDER + 1;
    } else if (strncasecmp(*ptr, "capture", strlen("capture")) == 0) {
        dir = find = PCM_CAPTURE + 1;
    }

    if (find) {
        /* Stop loop at specified character. */
        while (**ptr != '\0' && **ptr != ',' && **ptr != ' ' && **ptr != '\t') {
            (*ptr)++;
        }

        /* Skip the specified character. */
        if (**ptr == ',' || **ptr == ' ' || **ptr == '\t') {
            (*ptr)++;
        }
    }

    return dir;
}

static bool IsRenderChannel(AudioMixerChannelIdType chn)
{
    return !!(chn);
}

static bool IsCaptureChannel(AudioMixerChannelIdType chn)
{
    return !(chn);
}

static int32_t FillChnmap(struct AudioMixerCtlElemInfo *info, uint32_t chns, uint32_t dir, char **ptr)
{
    char *sp;
    AudioMixerChannelIdType chn;

    /* Matches the specified channel. */
    for (chn = AMIXER_CHN_FRONT_LEFT; chn < AMIXER_CHN_LAST; chn++) {
        sp = NULL;
        if (!(chns & (1 << (uint32_t)chn))) {
            continue;
        }

        if (!((dir & PCM_RENDER) && IsRenderChannel(chn)) && !((dir & PCM_CAPTURE) && IsCaptureChannel(chn))) {
            DEBUG_LOG("Unable to set channel!\n");
            return U_FAILURE;
        }

        info->value.enumVal.item |= (chns & (1 << chn));
        /* Search for the next channel. */
        while (**ptr != '\0' && **ptr != ',') {
            (*ptr)++;
        }
        if (**ptr == '\0') {
            break;
        }
        (*ptr)++; // skip ','
        DEBUG_LOG("skip, = %s\n", *ptr);
    }

    if (info->value.enumVal.item > CHN_STEREO) {
        info->value.enumVal.item = CHN_STEREO;
    } else {
        info->value.enumVal.item = CHN_MONO;
    }
    DEBUG_LOG("chns = %i\n", info->value.enumVal.item);

    return U_SUCCESS;
}

static int32_t FillChnlsIntVal(struct AudioMixerCtlElemInfo *info, unsigned int argc, char *argv)
{
    bool mchns;
    int32_t ret;
    char *ptr = NULL;
    uint32_t dir = 3;
    uint32_t chns = ~0U;

    ptr = argv;
    chns = ChannelsMask(&ptr, chns);
    if (*ptr == '\0') {
        DEBUG_LOG("Channels Mask = %u\n", chns);
        return U_FAILURE;
    }

    dir = DirMask(&ptr, dir);
    if (*ptr == '\0') {
        DEBUG_LOG("Direct Mask = %u\n", chns);
        return U_FAILURE;
    }

    mchns = (strchr(ptr, ',') != NULL);
    if (!mchns) {
        info->value.enumVal.item = CHN_MONO;
        return U_SUCCESS;
    }

    ret = FillChnmap(info, chns, dir, &ptr);
    if (ret != U_SUCCESS) {
        return ret;
    }

    return U_SUCCESS;
}

int32_t SetChannels(const struct HdfIoService *srv, const char *cardSrv, unsigned int argc, char *argv)
{
    int32_t ret;
    struct AudioMixerCtlElemInfo infoData;

    if (srv == NULL || cardSrv == NULL || argc == 0) {
        DEBUG_LOG("Invalid parameters!\n");
        return U_INVALID_PARAM;
    }

    DEBUG_LOG("argc = %u, argv = %s\n", argc, argv);
    (void)memset_s(infoData.cardSrvName, AUDIO_CARD_SRV_NAME_LEN, 0, AUDIO_CARD_SRV_NAME_LEN);
    ret = strncpy_s(infoData.cardSrvName, AUDIO_CARD_SRV_NAME_LEN, cardSrv, strlen(cardSrv) + 1);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s card service name is faild!\n");
        return U_FAILURE;
    }
    infoData.cardSrvName[AUDIO_CARD_SRV_NAME_LEN - 1] = '\0';

    (void)memset_s(infoData.eIndexId.eId.name, AUDIO_ELEM_NAME_LEN, 0, AUDIO_ELEM_NAME_LEN);
    ret = strncpy_s(
        infoData.eIndexId.eId.name, AUDIO_ELEM_NAME_LEN, "Captrue Channel Mode", strlen("Captrue Channel Mode") + 1);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s element name is failed!\n");
        return U_FAILURE;
    }
    infoData.eIndexId.eId.iface = AUDIO_CTL_ELEM_IFACE_MIXER;
    infoData.type = AUDIO_CTL_ELEM_TYPE_INTEGER;
    ret = FillChnlsIntVal(&infoData, argc, argv);
    if (ret != U_SUCCESS) {
        return ret;
    }

    if (g_audioMixer.SetElemProp == NULL) {
        DEBUG_LOG("The callback function is NULL!\n");
        return U_FAILURE;
    }
    ret = g_audioMixer.SetElemProp(srv, &infoData);
    if (ret != U_SUCCESS) {
        return ret;
    }

    ret = strncpy_s(
        infoData.eIndexId.eId.name, AUDIO_ELEM_NAME_LEN, "Render Channel Mode", strlen("Render Channel Mode") + 1);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s element name is failed!\n");
        return U_FAILURE;
    }

    return g_audioMixer.SetElemProp(srv, &infoData);
}

static int32_t FillIntVal(struct AudioMixerCtlElemInfo *info, unsigned int argc, char *argv[])
{
    char *vals, *minPtr, *maxPtr, *stepPtr;
    char *ptr = NULL;
    char *outPtr = NULL;

    if (argc != 2) {    // 2 for numbers of argc
        DEBUG_LOG("Unable to set too much value!\n");
        return U_FAILURE;
    }

    ptr = argv[argc - 1];
    DEBUG_LOG("argv[%u] = %s\n", argc - 1, ptr);
    vals = strtok_r(ptr, ",", &outPtr);
    if (outPtr == NULL) {
        info->value.intVal.vals[0] = strtol(ptr, NULL, STRTOL_BASE);
        info->value.intVal.min = 0;
        info->value.intVal.step = 0;

        return U_SUCCESS;
    }

    info->value.intVal.vals[0] = strtol(vals, NULL, STRTOL_BASE);
    maxPtr = strtok_r(NULL, ",", &outPtr);
    if (outPtr == NULL) {
        info->value.intVal.max = (int32_t)strtol(maxPtr, NULL, STRTOL_BASE);
        info->value.intVal.min = 0;
        info->value.intVal.step = 0;

        return U_SUCCESS;
    }

    info->value.intVal.max = (int32_t)strtol(maxPtr, NULL, STRTOL_BASE);
    minPtr = strtok_r(NULL, ",", &outPtr);
    if (outPtr != NULL) {
        info->value.intVal.min = (int32_t)strtol(minPtr, NULL, STRTOL_BASE);
        stepPtr = strtok_r(NULL, ",", &outPtr);
        info->value.intVal.step = outPtr != NULL ? (int32_t)strtol(stepPtr, NULL, STRTOL_BASE) : 0;
    } else {
        info->value.intVal.min = (int32_t)strtol(minPtr, NULL, STRTOL_BASE);
        info->value.intVal.step = 0;
    }

    return U_SUCCESS;
}

static int32_t FillEnumVal(struct AudioMixerCtlElemInfo *info, unsigned int argc, char *argv[])
{
    int32_t ret;
    unsigned int idx;
    char *ptr = NULL;

    printf("\n");
    /* Multiple enumerated values are output line by line. */
    for (idx = 1; idx < argc; idx++) {
        ptr = argv[idx];
        // Control Settings with enumerated values.
        ret = strcpy_s(info->value.enumVal.name, AUDIO_ELEM_NAME_LEN - 1, ptr);
        if (ret != EOK) {
            printf("strcpy_s failed: argv = %s\n", ptr);
        } else {
            printf("%s\n", ptr);
        }
    }

    return U_SUCCESS;
}

static int32_t FillBytesVal(unsigned char *buf, unsigned int argc, char *argv[])
{
    int32_t ret;
    size_t len;
    unsigned int idx;
    unsigned char *ptr = buf;
    char *sptr = NULL;
    size_t size = RESERVED_BUF_LEN;

    /* Multiple input parameters are separated and combined with a ",". */
    for (idx = 1; idx < argc; idx++) {
        sptr = argv[idx];
        len = strlen(argv[idx]);
        if (size <= len) {
            DEBUG_LOG("The callback function is NULL!\n");
            break;
        }
        ret = strncpy_s((char *)ptr, RESERVED_BUF_LEN - 1, sptr, len);
        if (ret != 0) {
            DEBUG_LOG("strncpy_s faild!\n");
            return U_FAILURE;
        }
        ptr += len;
        *ptr++ = ',';
        size -= len + 1;
    }
    if (idx < argc) {
        DEBUG_LOG("Unable to set too much data!\n");
        return U_FAILURE;
    }
    printf("data buf = %s\n", buf);

    return U_SUCCESS;
}


int32_t MctlSetElem(const struct HdfIoService *srv,
                    struct MixerCardCtlInfo *ctlInfo,
                    unsigned int argc, char *argv[])
{
    int32_t ret;
    struct AudioMixerCtlElemInfo infoData;

    if (srv == NULL || ctlInfo == NULL || argc == 0) {
        DEBUG_LOG("Invalid parameters!\n");
        return U_INVALID_PARAM;
    }

    ret = strncpy_s(infoData.cardSrvName, AUDIO_CARD_SRV_NAME_LEN, ctlInfo->cardSrvName, AUDIO_CARD_SRV_NAME_LEN);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s card service name is faild!\n");
        return U_FAILURE;
    }
    infoData.cardSrvName[AUDIO_CARD_SRV_NAME_LEN - 1] = '\0';

    ret = strncpy_s(infoData.eIndexId.eId.name, AUDIO_ELEM_NAME_LEN, ctlInfo->edx.eId.name, AUDIO_ELEM_NAME_LEN);
    if (ret != 0) {
        DEBUG_LOG("strncpy_s element name is failed!\n");
        return U_FAILURE;
    }
    infoData.eIndexId.eId.name[AUDIO_ELEM_NAME_LEN - 1] = '\0';
    infoData.eIndexId.eId.iface = AUDIO_CTL_ELEM_IFACE_MIXER;

    // First, read the value type.(infoData.type)
    infoData.type = AUDIO_CTL_ELEM_TYPE_INTEGER;
    switch (infoData.type) {
        case AUDIO_CTL_ELEM_TYPE_INTEGER:
        case AUDIO_CTL_ELEM_TYPE_BOOLEAN:
            ret = FillIntVal(&infoData, argc, argv);
            break;
        case AUDIO_CTL_ELEM_TYPE_ENUMERATED:
            ret = FillEnumVal(&infoData, argc, argv);
            break;
        case AUDIO_CTL_ELEM_TYPE_BYTES:
            ret = FillBytesVal(infoData.value.reserved, argc, argv);
            break;
        default:
            ret = U_FAILURE;
            break;
    }
    if (ret != U_SUCCESS) {
        DEBUG_LOG("The value type does not match!\n");
        return U_FAILURE;
    }

    if (g_audioMixer.SetElemProp == NULL) {
        DEBUG_LOG("The callback function is NULL!\n");
        return U_FAILURE;
    }

    return g_audioMixer.SetElemProp(srv, &infoData);
}

static char *SkipSpecifyStr(const char *src, const char *needle)
{
    char *p = NULL;

    p = strstr(src, needle);
    if (p != NULL) {
        p += strlen(needle);
    }

    return p;
}

static int32_t GetSndCardType(const char *name, char *buf, uint32_t len)
{
    int32_t ret;
    char *ptr = NULL;
    char *out = NULL;

    if (name == NULL || buf == NULL || len == 0) {
        DEBUG_LOG("Invalid parameters!\n");
        return U_INVALID_PARAM;
    }

    ptr = SkipSpecifyStr(name, MIXER_SRV_NAME_PRE);
    if (ptr == NULL) {
        DEBUG_LOG("No found card type!\n");
        return U_FAILURE;
    }

    ret = memcpy_s(buf, len, ptr, strlen(ptr) + 1);
    if (ret != EOK) {
        DEBUG_LOG("memcpy_s fail!\n");
        return U_FAILURE;
    }
    ptr = strtok_r(buf, "_", &out);
    ret = memcpy_s(buf, len, ptr, strlen(ptr) + 1);
    if (ret != EOK) {
        DEBUG_LOG("memcpy_s fail!\n");
        return U_FAILURE;
    }

    return U_SUCCESS;
}

static void ShowAllAdapters(struct SndCardsList *sndList)
{
    int32_t i, ret;
    uint32_t cnums;
    char ctype[AUDIO_BASE_LEN] = {0};
    struct AudioCardId *clist = NULL;

    if (sndList->cardNums == 0 || sndList->cardsList == NULL) {
        DEBUG_LOG("No sound cards found...!\n");
        goto end;
    }

    cnums = sndList->cardNums;
    clist = sndList->cardsList;
    printf("****** List of Audio Hardware Devices ******\n");
    /* To keep the primary sound card always in front of the total,
     * output it in the following order.
     */
    for (i = (int32_t)cnums - 1; i >= 0; i--) {
        (void)memset_s(ctype, AUDIO_BASE_LEN, 0, AUDIO_BASE_LEN);
        ret = GetSndCardType(clist[i].cardName, ctype, AUDIO_BASE_LEN);
        if (ret != U_SUCCESS) {
            goto end;
        }
        printf("card %i: %s [%s], device 0\n", clist[i].index, ctype, clist[i].cardName);
        printf("  Subdevices: 1/1\n");
        printf("  Subdevice #0: subdevice #0\n");
    }

end:
    if (sndList->cardsList != NULL) {
        free(sndList->cardsList);
        sndList->cardsList = NULL;
    }
}

int32_t GetAllCards(const struct HdfIoService *service)
{
    int32_t ret;
    struct SndCardsList sndcards;
    int32_t (*GetAllAdapters)(const struct HdfIoService *, struct SndCardsList *);

    if (service == NULL) {
        DEBUG_LOG("Invalid parameter!\n");
        return U_INVALID_PARAM;
    }

    GetAllAdapters = CallLibFunction("AudioMixerGetAllAdapters");
    if (GetAllAdapters == NULL) {
        return U_FAILURE;
    }

    (void)memset_s(&sndcards, sizeof(struct SndCardsList), 0, sizeof(struct SndCardsList));
    ret = GetAllAdapters(service, &sndcards);
    if (ret != U_SUCCESS) {
        DEBUG_LOG("Description Failed to obtain the sound card list!\n");
        return U_FAILURE;
    }
    ShowAllAdapters(&sndcards);

    return U_SUCCESS;
}

static char *FindSpecificCardName(int card, struct SndCardsList *cardList)
{
    int32_t i;
    uint32_t cnums;
    struct AudioCardId *clist = NULL;

    if (cardList->cardNums == 0 || cardList->cardsList == NULL) {
        DEBUG_LOG("No sound cards found...!\n");
        goto end;
    }

    cnums = cardList->cardNums;
    clist = cardList->cardsList;
    for (i = 0; i < (int32_t)cnums; i++) {
        if (card == clist[i].index) {
            DEBUG_LOG("I found this sound card. [card%i: %s]\n", card, clist[i].cardName);
            return clist[i].cardName;
        }
    }

end:
    if (cardList->cardsList != NULL) {
        free(cardList->cardsList);
        cardList->cardsList = NULL;
    }
    cardList->cardNums = 0;

    return NULL;
}

void UpdateCardSname(int card, const struct HdfIoService *srv, char * const sname, size_t snameLen)
{
    int32_t ret;
    struct SndCardsList cardList;
    int32_t (*GetAllCardsFunc)(const struct HdfIoService *, struct SndCardsList *);
    char *cname = NULL;

    if (card < 0 || srv == NULL || sname == NULL || snameLen == 0) {
        DEBUG_LOG("Invalid parameter!\n");
        return;
    }

    GetAllCardsFunc = CallLibFunction("AudioMixerGetAllAdapters");
    if (GetAllCardsFunc == NULL) {
        DEBUG_LOG("Description Failed to obtain the current sound card list of the system!\n");
        return;
    }

    (void)memset_s(&cardList, sizeof(struct SndCardsList), 0, sizeof(struct SndCardsList));
    ret = GetAllCardsFunc(srv, &cardList);
    if (ret != U_SUCCESS) {
        DEBUG_LOG("Update failed: Description Failed to obtain the sound card list!\n");
        return;
    }

    cname = FindSpecificCardName(card, &cardList);
    if (cname == NULL) {
        DEBUG_LOG("Update failed: The corresponding sound card cannot be matched!\n");
        return;
    }

    ret = memcpy_s(sname, snameLen, cname, strlen(cname) + 1);
    if (ret != EOK) {
        DEBUG_LOG("Update failed: memcpy_s fail!\n");
    }
    sname[snameLen - 1] = '\0';
    if (g_debugFlag) {
        printf("|--> [%s]\n", sname);
    }

    if (cardList.cardsList != NULL) {
        free(cardList.cardsList);
        cardList.cardsList = NULL;
    }
    cardList.cardNums = 0;
}
