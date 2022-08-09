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

#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <securec.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "hdf_base.h"
#include "hdf_io_service_if.h"
#include "hdf_remote_adapter_if.h"
#include "hdf_service_status.h"
#include "inttypes.h"
#include "ioservstat_listener.h"
#include "osal_mem.h"
#include "svcmgr_ioservice.h"
#include "v1_0/audio_manager.h"
#include "v1_0/audio_types.h"

#define AUDIO_FUNC_LOGE(fmt, arg...)                                                     \
    do {                                                                                 \
        printf("%s: [%s]: [%d]:[ERROR]:" fmt "\n", __FILE__, __func__, __LINE__, ##arg); \
    } while (0)

#define WAV_HEAD_OFFSET      44
#define WAV_HEAD_RIFF_OFFSET 8

#define MOVE_LEFT_NUM         8
#define AUDIO_CHANNELCOUNT    2
#define AUDIO_SAMPLE_RATE_48K 48000
#define PATH_LEN              256
char g_adapterName[PATH_LEN] = {0};
#define BUFFER_PERIOD_SIZE              (4 * 1024)
#define DEEP_BUFFER_RENDER_PERIOD_SIZE  4096
#define DEEP_BUFFER_RENDER_PERIOD_COUNT 8
#define INT_32_MAX                      0x7fffffff
#define BUFFER_SIZE_BASE                1024
#define AUDIO_BUFF_SIZE                 (1024 * 16)
#define PCM_8_BIT                       8
#define PCM_16_BIT                      16
#define AUDIO_TOTALSIZE_15M             (1024 * 15)
#define AUDIO_RECORD_INTERVAL_512KB     512
#define MAX_AUDIO_ADAPTER_DESC          5
#define FILE_CAPTURE_SIZE               (1024 * 1024 * 3) // 3M
#define BUFFER_LEN                      256
#define EXT_PARAMS_MAXLEN               107
#define ONE_MS                          1000

struct AudioHeadInfo {
    uint32_t riffId;
    uint32_t riffSize;
    uint32_t riffType;
    uint32_t audioFileFmtId;
    uint32_t audioFileFmtSize;
    uint16_t audioFileFormat;
    uint16_t audioChannelNum;
    uint32_t audioSampleRate;
    uint32_t audioByteRate;
    uint16_t audioBlockAlign;
    uint16_t audioBitsPerSample;
    uint32_t dataId;
    uint32_t dataSize;
};

struct StrParaCapture {
    struct AudioCapture *capture;
    FILE *file;
    struct AudioSampleAttributes attrs;
    uint64_t *replyBytes;
    char *frame;
    int32_t bufferSize;
};
struct AudioAdapter *g_adapter = NULL;
struct AudioDeviceDescriptor g_devDesc;
struct AudioSampleAttributes g_attrs;
struct AudioCapture *g_capture = NULL;
static struct AudioManager *g_audioManager = NULL;
static struct StrParaCapture g_str;
void *g_captureHandle;
void (*g_AudioManagerRelease)(struct AudioManager *) = NULL;
void (*g_AudioAdapterRelease)(struct AudioAdapter *) = NULL;
void (*g_AudioCaptureRelease)(struct AudioCapture *) = NULL;

pthread_t g_tids;
FILE *g_file;
char *g_frame;
char g_path[256] = {'\0'};

enum CaptureSoundCardMode {
    PRIMARY = 1,
    PRIMARY_EXT = 2,
    AUDIO_USB = 3,
    AUDIO_A2DP = 4,
};

enum AudioCaptureMode {
    CAPTURE_POLL = 1,
    CAPTURE_INTERUPT,
};

int g_CaptureModeFlag = CAPTURE_POLL;

#ifndef __LITEOS__
int g_receiveFrameCount = 0;
uint64_t g_totalSize = 0;
struct ISvcMgrIoservice *g_servmgr = NULL;
struct ServiceStatusListener *g_listener = NULL;
#endif

enum CaptureMenuId {
    CAPTURE_START = 1,
    CAPTURE_STOP,
    CAPTURE_RESUME,
    CAPTURE_PAUSE,
    SET_CAPTURE_VOLUME,
    SET_CAPTURE_GAIN,
    SET_CAPTURE_MUTE,
    SET_CAPTURE_ATTRIBUTES,
    SET_CAPTURE_SLECET_SCENE,
    GET_CAPTURE_EXT_PARAMS,
    GET_CAPTURE_POSITION,
};

enum CaptureInputType {
    INPUT_INT = 0,
    INPUT_FLOAT,
    INPUT_UINT32,
};

typedef int32_t (*AudioCaptureOperation)(struct AudioCapture **);

struct ProcessCaptureMenuSwitchList {
    enum CaptureMenuId cmd;
    AudioCaptureOperation operation;
};

static int32_t g_closeEnd = 0;

void CleanStdin(void)
{
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);
}

int32_t CheckInputName(int type, void *val)
{
    if (val == NULL) {
        return HDF_FAILURE;
    }
    printf("\n");
    int ret;
    int inputInt = 0;
    float inputFloat = 0.0;
    uint32_t inputUint = 0;
    switch (type) {
        case INPUT_INT:
            ret = scanf_s("%d", &inputInt);
            if (inputInt < 0 || inputInt > GET_CAPTURE_POSITION + 1) {
                AUDIO_FUNC_LOGE("Input failure");
                return HDF_FAILURE;
            }
            *(int *)val = inputInt;
            break;
        case INPUT_FLOAT:
            ret = scanf_s("%f", &inputFloat);
            *(float *)val = inputFloat;
            break;
        case INPUT_UINT32:
            ret = scanf_s("%u", &inputUint);
            if (inputUint > 0xFFFFFFFF || inputUint < 0) {
                return HDF_FAILURE;
            }
            *(uint32_t *)val = inputUint;
            break;
        default:
            ret = EOF;
            break;
    }
    if (ret == 0) {
        CleanStdin();
    } else if (ret == EOF) {
        AUDIO_FUNC_LOGE("Input failure occurs!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
void SystemInputFail(void)
{
    printf("please ENTER to go on...");
    while (getchar() != '\n') {
        continue;
    }
}
int32_t InitAttrsCapture(struct AudioSampleAttributes *attrs)
{
    if (attrs == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    attrs->format = AUDIO_FORMAT_PCM_16_BIT;
    attrs->channelCount = AUDIO_CHANNELCOUNT;
    attrs->sampleRate = AUDIO_SAMPLE_RATE_48K;
    attrs->interleaved = 0;
    attrs->type = AUDIO_IN_MEDIA;
    attrs->period = BUFFER_PERIOD_SIZE;
    attrs->frameSize = PCM_16_BIT * attrs->channelCount / PCM_8_BIT;
    attrs->isBigEndian = false;
    attrs->isSignedData = true;
    attrs->startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs->frameSize);
    attrs->stopThreshold = INT_32_MAX;
    attrs->silenceThreshold = AUDIO_BUFF_SIZE;
    return 0;
}

int32_t InitDevDescCapture(struct AudioDeviceDescriptor *devDesc, uint32_t portId)
{
    if (devDesc == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    devDesc->portId = portId;
    devDesc->pins = PIN_IN_MIC;
    devDesc->desc = strdup("devName");
    return HDF_SUCCESS;
}

uint32_t PcmFormatToBits(enum AudioFormat format)
{
    switch (format) {
        case AUDIO_FORMAT_PCM_16_BIT:
            return PCM_16_BIT;
        case AUDIO_FORMAT_PCM_8_BIT:
            return PCM_8_BIT;
        default:
            return PCM_16_BIT;
    };
}

void StreamClose(int32_t sig)
{
    /* allow the stream to be closed gracefully */
    (void)signal(sig, SIG_IGN);
    g_closeEnd = 1;
}

uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs)
{
    return DEEP_BUFFER_RENDER_PERIOD_SIZE * attrs.channelCount * (PcmFormatToBits(attrs.format) >> 3);
}

static inline void FileClose(FILE **file)
{
    if ((file != NULL) && ((*file) != NULL)) {
        (void)fclose(*file);
        *file = NULL;
    }
    return;
}

uint32_t StringToInt(const char *flag)
{
    if (flag == NULL) {
        return 0;
    }
    uint32_t temp = flag[0];
    for (int32_t i = strlen(flag) - 1; i >= 0; i--) {
        temp <<= MOVE_LEFT_NUM;
        temp += flag[i];
    }
    return temp;
}

int32_t AddWavFileHeader(struct StrParaCapture *StrParam)
{
    if (StrParam == NULL) {
        AUDIO_FUNC_LOGE("InitCaptureStrParam is NULL");
        return HDF_FAILURE;
    }

    struct AudioHeadInfo headInfo;
    (void)fseek(g_file, 0, SEEK_END);

    headInfo.riffId = StringToInt("RIFF");
    headInfo.riffSize = (uint32_t)ftell(g_file) - WAV_HEAD_RIFF_OFFSET;
    headInfo.riffType = StringToInt("WAVE");
    headInfo.audioFileFmtId = StringToInt("fmt ");
    headInfo.audioFileFmtSize = PcmFormatToBits(StrParam->attrs.format);
    headInfo.audioFileFormat = 1;
    headInfo.audioChannelNum = StrParam->attrs.channelCount;
    headInfo.audioSampleRate = StrParam->attrs.sampleRate;
    headInfo.audioByteRate =
        headInfo.audioSampleRate * headInfo.audioChannelNum * headInfo.audioFileFmtSize / PCM_8_BIT;
    headInfo.audioBlockAlign = headInfo.audioChannelNum * headInfo.audioFileFmtSize / PCM_8_BIT;
    headInfo.audioBitsPerSample = headInfo.audioFileFmtSize;
    headInfo.dataId = StringToInt("data");
    headInfo.dataSize = (uint32_t)ftell(g_file) - WAV_HEAD_OFFSET;

    rewind(g_file);

    ssize_t ret = fwrite(&headInfo, sizeof(struct AudioHeadInfo), 1, g_file);
    if (ret != 1) {
        AUDIO_FUNC_LOGE("write wav file head error");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t StopButtonCapture(struct AudioCapture **captureS)
{
    if (captureS == NULL) {
        return HDF_FAILURE;
    }
    if (!g_closeEnd) {
        g_closeEnd = true;
        usleep(100000); // sleep 100000us
    }
    struct AudioCapture *capture = *captureS;
    if (capture == NULL) {
        return HDF_FAILURE;
    }
    int ret = capture->Stop((void *)capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Stop capture!");
    }
    if (g_adapter == NULL || g_adapter->DestroyCapture == NULL) {
        return HDF_FAILURE;
    }
    ret = g_adapter->DestroyCapture(g_adapter);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Capture already destroy!");
    }
    g_AudioCaptureRelease(capture);
    *captureS = NULL;
    g_capture = NULL;
    if (g_frame != NULL) {
        OsalMemFree(g_frame);
        g_frame = NULL;
    }

    if (AddWavFileHeader(&g_str) < 0) {
        AUDIO_FUNC_LOGE("AddWavFileHeader Fail");
        return HDF_FAILURE;
    }

    FileClose(&g_file);
    if (g_CaptureModeFlag == CAPTURE_INTERUPT) {
        AUDIO_FUNC_LOGE("litoOs  not support!");
    }
    printf("Stop Successful\n");
    return HDF_SUCCESS;
}

int32_t FrameStartCaptureMmap(const struct StrParaCapture *param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    const struct StrParaCapture *strParam = param;
    struct AudioCapture *capture = strParam->capture;
    struct AudioMmapBufferDescripter mmapDesc;
    // Modify file size

    int fd = fileno(strParam->file);
    if (fd == -1) {
        printf("fileno failed, fd is %d\n", fd);
        return HDF_FAILURE;
    }
    ftruncate(fd, FILE_CAPTURE_SIZE);
    // Init param
    mmapDesc.memoryFd = 0; // default 0
    mmapDesc.filePath = strdup(g_path);
    mmapDesc.isShareable = 1;                                        // 1:Shareable ,0:Don't share
    mmapDesc.transferFrameSize = DEEP_BUFFER_RENDER_PERIOD_SIZE / 4; // One frame size 4 bit
    mmapDesc.offset = 0;                                             // Recording must be 0
    // start
    if (capture == NULL || capture->ReqMmapBuffer == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret = capture->ReqMmapBuffer(capture, FILE_CAPTURE_SIZE, &mmapDesc);
    if (ret < 0) {
        printf("Request map fail,please check.\n");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t WriteDataToFile(FILE *file, char *buffer, uint64_t replyBytes, uint32_t *failCount, uint64_t *totalSize)
{
    if (file == NULL || buffer == NULL || failCount == NULL || totalSize == NULL) {
        AUDIO_FUNC_LOGE("WriteDataToFile params is null!");
        return HDF_FAILURE;
    }
    *failCount = 0;
    (void)fwrite(buffer, (size_t)replyBytes, 1, file);
    *totalSize += (replyBytes / BUFFER_SIZE_BASE);       // 1024 = 1Kb
    if (*totalSize % AUDIO_RECORD_INTERVAL_512KB < 24) { // 512KB
        printf("\nRecording,the audio file size is %" PRIu64 "Kb\n", *totalSize);
    }
    return HDF_SUCCESS;
}

int32_t FrameStartCapture(const struct StrParaCapture *param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    uint32_t bufferSize = AUDIO_BUFF_SIZE;
    uint64_t requestBytes = AUDIO_BUFF_SIZE;
    const struct StrParaCapture *strParam = param;
    struct AudioCapture *capture = strParam->capture;
    uint64_t totalSize = 0;
    uint32_t failCount = 0;
    if (capture == NULL || capture->CaptureFrame == NULL) {
        return HDF_FAILURE;
    }
    char *frame = (char *)OsalMemCalloc(bufferSize);
    if (frame == NULL) {
        return HDF_FAILURE;
    }
    do {
        int32_t ret = capture->CaptureFrame(capture, (int8_t *)frame, &bufferSize, requestBytes);
        if (ret < 0) {
            if (ret == HDF_ERR_INVALID_OBJECT) {
                AUDIO_FUNC_LOGE("Record already stop!");
                break;
            }
            usleep(ONE_MS);
            if (failCount++ >= 300000) { // Try 300000 times for CaptureFrame fail
                OsalMemFree(frame);
                return HDF_FAILURE;
            }
            continue;
        }
        if (WriteDataToFile(strParam->file, frame, bufferSize, &failCount, &totalSize) < 0) {
            OsalMemFree(frame);
            return HDF_FAILURE;
        }
    } while ((totalSize <= AUDIO_TOTALSIZE_15M) && (!g_closeEnd)); // 15 * 1024 = 15M
    OsalMemFree(frame);
    if (!g_closeEnd) {
        if (StopButtonCapture(&g_capture) < 0) {
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

void PrintPlayMode(void)
{
    printf(" ============= Play Capture start Mode ==========\n");
    printf("| 1. Capture non-mmap                           |\n");
    printf("| 2. Capture mmap                               |\n");
    printf(" ================================================\n");
}

int32_t SelectPlayMode(int32_t *palyModeFlag)
{
    if (palyModeFlag == NULL) {
        AUDIO_FUNC_LOGE("palyModeFlag is null");
        return HDF_FAILURE;
    }
    system("clear");
    int choice = 0;
    PrintPlayMode();
    printf("Please enter your choice:");
    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CheckInputName Fail");
        return HDF_FAILURE;
    } else {
        *palyModeFlag = choice;
    }
    return HDF_SUCCESS;
}

int32_t StartPlayThread(int32_t palyModeFlag)
{
    pthread_attr_t tidsAttr;
    pthread_attr_init(&tidsAttr);
    pthread_attr_setdetachstate(&tidsAttr, PTHREAD_CREATE_DETACHED);
    switch (palyModeFlag) {
        case 1: // 1. Stander Loading
            if (pthread_create(&g_tids, &tidsAttr, (void *)(&FrameStartCapture), &g_str) != 0) {
                AUDIO_FUNC_LOGE("Create Thread Fail");
                return HDF_FAILURE;
            }
            break;
        case 2: // 2. Low latency Loading
            if (pthread_create(&g_tids, &tidsAttr, (void *)(&FrameStartCaptureMmap), &g_str) != 0) {
                AUDIO_FUNC_LOGE("Create Thread Fail");
                return HDF_FAILURE;
            }
            break;
        default:
            printf("Input error,Switched to non-mmap Mode for you,");
            SystemInputFail();
            if (pthread_create(&g_tids, &tidsAttr, (void *)(&FrameStartCapture), &g_str) != 0) {
                AUDIO_FUNC_LOGE("Create Thread Fail");
                return HDF_FAILURE;
            }
            break;
    }
    return HDF_SUCCESS;
}

int32_t CaptureChoiceModeAndRecording(
    struct StrParaCapture *StrParam, struct AudioCapture *capture, int32_t palyModeFlag)
{
    if (StrParam == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("InitCaptureStrParam is NULL");
        return HDF_FAILURE;
    }
    memset_s(StrParam, sizeof(struct StrParaCapture), 0, sizeof(struct StrParaCapture));
    StrParam->capture = capture;
    StrParam->file = g_file;
    StrParam->attrs = g_attrs;
    StrParam->frame = g_frame;
    if (g_CaptureModeFlag == CAPTURE_INTERUPT) {
        printf("not suport liteos!");
    } else {
        if (StartPlayThread(palyModeFlag) < 0) {
            AUDIO_FUNC_LOGE("Create Thread Fail");
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int32_t PlayingAudioInitFile(void)
{
    if (g_file != NULL) {
        AUDIO_FUNC_LOGE("the capture is playing,please stop first");
        return HDF_FAILURE;
    }
    g_closeEnd = false;
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(g_path, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    g_file = fopen(pathBuf, "wb+");
    if (g_file == NULL) {
        printf("failed to open '%s'\n", g_path);
        return HDF_FAILURE;
    }

    int32_t ret = fseek(g_file, WAV_HEAD_OFFSET, SEEK_SET);
    if (ret != 0) {
        printf("write wav file head error");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t PlayingAudioInitCapture(struct AudioCapture **captureTemp)
{
    if (captureTemp == NULL) {
        AUDIO_FUNC_LOGE("captureTemp is null");
        return HDF_FAILURE;
    }
    struct AudioCapture *capture = NULL;
    int32_t ret = g_adapter->CreateCapture(g_adapter, &g_devDesc, &g_attrs, &capture);
    if (capture == NULL || ret < 0) {
        return HDF_FAILURE;
    }
    ret = capture->Start((void *)capture);
    if (ret < 0) {
        g_adapter->DestroyCapture(g_adapter);
        g_AudioCaptureRelease(capture);
        return HDF_FAILURE;
    }
    uint32_t bufferSize = PcmFramesToBytes(g_attrs);
    g_frame = (char *)OsalMemCalloc(bufferSize);
    if (g_frame == NULL) {
        g_adapter->DestroyCapture(g_adapter);
        g_AudioCaptureRelease(capture);
        return HDF_FAILURE;
    }
    *captureTemp = capture;
    return HDF_SUCCESS;
}

int32_t StartButtonCapture(struct AudioCapture **captureS)
{
    if (captureS == NULL || g_adapter == NULL || g_adapter->CreateCapture == NULL) {
        return HDF_FAILURE;
    }
    if (PlayingAudioInitFile() < 0) {
        AUDIO_FUNC_LOGE("PlayingAudioInitFile Fail");
        return HDF_FAILURE;
    }
    int32_t palyModeFlag = 0;
    if (SelectPlayMode(&palyModeFlag) < 0) {
        AUDIO_FUNC_LOGE("SelectPlayMode Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    struct AudioCapture *capture = NULL;
    if (PlayingAudioInitCapture(&capture) < 0) {
        AUDIO_FUNC_LOGE("PlayingAudioInitCapture Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    if (CaptureChoiceModeAndRecording(&g_str, capture, palyModeFlag) < 0) {
        AUDIO_FUNC_LOGE("CaptureChoiceModeAndRecording failed");
        FileClose(&g_file);
        if (g_adapter != NULL && g_adapter->DestroyCapture != NULL) {
            g_adapter->DestroyCapture(g_adapter);
        }
        g_AudioCaptureRelease(capture);
        return HDF_FAILURE;
    }
    *captureS = capture;
    printf("Start Successful\n");
    return HDF_SUCCESS;
}

int32_t SwitchAdapterCapture(struct AudioAdapterDescriptor *descs, const char *adapterNameCase,
    enum AudioPortDirection portFlag, struct AudioPort *capturePort, const int32_t size)
{
    struct AudioAdapterDescriptor *desc = NULL;
    int32_t index;
    uint32_t port;
    if (descs == NULL || adapterNameCase == NULL || capturePort == NULL) {
        return HDF_FAILURE;
    }
    for (index = 0; index < size; index++) {
        desc = &descs[index];
        if (desc == NULL) {
            continue;
        }
        if (desc->adapterName == NULL) {
            return HDF_FAILURE;
        }
        if (strcmp((const char *)desc->adapterName, adapterNameCase)) {
            printf("adapter name case = %s\n", adapterNameCase);
            continue;
        }
        for (port = 0; port < desc->portsLen; port++) {
            // Only find out the port of out in the sound card
            if (desc->ports[port].dir == portFlag) {
                *capturePort = desc->ports[port];
                return index;
            }
        }
    }
    return HDF_FAILURE;
}
void PrintMenu1(void)
{
    printf(" ============== Play Capture Loading Mode ===========\n");
    printf("| 1. Capture Direct Loading                         |\n");
    printf("| 2. Capture Service Loading                        |\n");
    printf("| Note: switching is not supported in the MPI's     |\n");
    printf("|       version.                                    |\n");
    printf(" =================================================== \n");
}

void PrintMenuFirst(void)
{
    printf(" ============= Play Capture Sound Card Mode ==========\n");
    printf("| 1. Capture Primary                                 |\n");
    printf("| 2. Capture Primary_Ext                             |\n");
    printf("| 3. Capture Usb                                     |\n");
    printf("| 4. Capture A2dp                                    |\n");
    printf(" =================================================== \n");
}

int32_t SwitchInternalOrExternal(char *adapterNameCase, int32_t nameLen)
{
    system("clear");
    int choice = 0;
    PrintMenuFirst();
    printf("Please enter your choice:");
    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    switch (choice) {
        case PRIMARY:
            snprintf_s(adapterNameCase, nameLen, nameLen - 1, "%s", "primary");
            break;
        case PRIMARY_EXT:
            snprintf_s(adapterNameCase, nameLen, nameLen - 1, "%s", "primary_ext");
            break;
        case AUDIO_USB:
            snprintf_s(adapterNameCase, nameLen, nameLen - 1, "%s", "usb");
            break;
        case AUDIO_A2DP:
            snprintf_s(adapterNameCase, nameLen, nameLen - 1, "%s", "a2dp");
            break;
        default:
            printf("Input error,Switched to Acodec in for you,");
            SystemInputFail();
            snprintf_s(adapterNameCase, nameLen, nameLen - 1, "%s", "primary");
            break;
    }
    return HDF_SUCCESS;
}

int32_t SelectLoadingMode(char *resolvedPath, int32_t pathLen)
{
    system("clear");
    int choice = 0;
    char *soPathHdi = NULL;
    char *soPathProxy = NULL;
    int32_t ret;
    soPathHdi = HDF_LIBRARY_FULL_PATH("libhdi_audio_passthrough");
#ifdef __aarch64__
    soPathProxy = "/system/lib64/libaudio_proxy_1.0.z.so";
#else
    soPathProxy = "/system/lib/libaudio_proxy_1.0.z.so";
#endif

    PrintMenu1();
    printf("Please enter your choice:");
    ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    switch (choice) {
        case 1: // 1. Capture Direct Loading
            if (snprintf_s(resolvedPath, pathLen, pathLen - 1, "%s", soPathHdi) < 0) {
                AUDIO_FUNC_LOGE("snprintf_s failed!");
                return HDF_FAILURE;
            }
            break;
        case 2: // 2. Capture Service Loading
            if (snprintf_s(resolvedPath, pathLen, pathLen - 1, "%s", soPathProxy) < 0) {
                AUDIO_FUNC_LOGE("snprintf_s failed!");
                return HDF_FAILURE;
            }
            break;
        default:
            printf("Input error,Switched to direct loading in for you,");
            SystemInputFail();
            if (snprintf_s(resolvedPath, pathLen, pathLen - 1, "%s", soPathHdi) < 0) {
                return HDF_FAILURE;
            }
            break;
    }
    return HDF_SUCCESS;
}

void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (dataBlock->adapterName != NULL) {
        OsalMemFree(dataBlock->adapterName);
        dataBlock->adapterName = NULL;
    }

    if (dataBlock->ports != NULL) {
        OsalMemFree(dataBlock->ports);
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if (descsLen > 0 && descs != NULL && (*descs) != NULL) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = NULL;
    }
}

int32_t GetManagerAndLoadAdapter(const char *adapterNameCase, struct AudioPort *capturePort)
{
    if (adapterNameCase == NULL || capturePort == NULL) {
        AUDIO_FUNC_LOGE("The Parameter is NULL");
        return HDF_FAILURE;
    }

    struct AudioManager *(*getAudioManager)(const char *) = NULL;
    getAudioManager = (struct AudioManager *(*)(const char *))(dlsym(g_captureHandle, "AudioManagerGetInstance"));
    if (getAudioManager == NULL) {
        return HDF_FAILURE;
    }

    (void)HdfRemoteGetCallingPid();

    struct AudioManager *audioManager = getAudioManager("idl_audio_service");
    if (audioManager == NULL) {
        AUDIO_FUNC_LOGE("Get audio Manager Fail");
        return HDF_FAILURE;
    }
    g_audioManager = audioManager;
    struct AudioAdapterDescriptor *descs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (MAX_AUDIO_ADAPTER_DESC));
    if (descs == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc for descs failed");
        return HDF_FAILURE;
    }
    uint32_t adapterNum = MAX_AUDIO_ADAPTER_DESC;
    int32_t ret = audioManager->GetAllAdapters(audioManager, descs, &adapterNum);
    if (ret < 0 || adapterNum == 0) {
        AUDIO_FUNC_LOGE("Get All Adapters Fail");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    // Get qualified sound card and port
    enum AudioPortDirection port = PORT_OUT; // Set port information
    int32_t index = SwitchAdapterCapture(descs, adapterNameCase, port, capturePort, adapterNum);
    if (index < 0) {
        AUDIO_FUNC_LOGE("Not Switch Adapter Fail");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (audioManager->LoadAdapter(audioManager, &descs[index], &g_adapter)) {
        AUDIO_FUNC_LOGE("Load Adapter Fail");
        ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    ReleaseAdapterDescs(&descs, MAX_AUDIO_ADAPTER_DESC);
    if (g_adapter == NULL) {
        AUDIO_FUNC_LOGE("load audio device failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
int32_t InitCaptureParam(const char *adapterNameCase, uint32_t portId)
{
    if (adapterNameCase == NULL) {
        AUDIO_FUNC_LOGE("The Parameter is NULL");
        return HDF_FAILURE;
    }
    if (g_adapter == NULL) {
        AUDIO_FUNC_LOGE("g_adapter is NULL");
        return HDF_FAILURE;
    }
    // Initialization port information, can fill through mode and other parameters
    (void)g_adapter->InitAllPorts(g_adapter);
    // User needs to set
    if (InitAttrsCapture(&g_attrs) < 0) {
        return HDF_FAILURE;
    }
    // Specify a hardware device
    if (InitDevDescCapture(&g_devDesc, portId) < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CaptureGetAdapterAndInitEnvParams(const char *adapterNameCase)
{
    struct AudioPort capturePort;
    if (adapterNameCase == NULL) {
        AUDIO_FUNC_LOGE("The Parameter is NULL");
        return HDF_FAILURE;
    }
    int32_t ret = GetManagerAndLoadAdapter(adapterNameCase, &capturePort);
    if (ret < 0) {
        return ret;
    }
    if (InitCaptureParam(adapterNameCase, capturePort.portId) < 0) {
        g_audioManager->UnloadAdapter(g_audioManager, adapterNameCase);
        g_AudioAdapterRelease(g_adapter);
        g_adapter = NULL;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t InitReleaseFun(void)
{
    g_AudioManagerRelease = (void (*)(struct AudioManager *))(dlsym(g_captureHandle, "AudioManagerRelease"));
    if (g_AudioManagerRelease == NULL) {
        AUDIO_FUNC_LOGE("get AudioManagerRelease fun ptr failed");
        return HDF_FAILURE;
    }
    g_AudioAdapterRelease = (void (*)(struct AudioAdapter *))(dlsym(g_captureHandle, "AudioAdapterRelease"));
    if (g_AudioAdapterRelease == NULL) {
        AUDIO_FUNC_LOGE("get AudioAdapterRelease fun ptr failed");
        return HDF_FAILURE;
    }
    g_AudioCaptureRelease = (void (*)(struct AudioCapture *))(dlsym(g_captureHandle, "AudioCaptureRelease"));
    if (g_AudioCaptureRelease == NULL) {
        AUDIO_FUNC_LOGE("get AudioCaptureRelease fun ptr failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t InitParam(void)
{
    /* Internal and external switch,begin */
    if (SwitchInternalOrExternal(g_adapterName, PATH_LEN) < 0) {
        return HDF_FAILURE;
    }

    char resolvedPath[PATH_LEN] = {0};
    if (SelectLoadingMode(resolvedPath, PATH_LEN) < 0) {
        AUDIO_FUNC_LOGE("SelectLoadingMode failed!");
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(resolvedPath, pathBuf) == NULL) {
        AUDIO_FUNC_LOGE("realpath failed!");
        return HDF_FAILURE;
    }
    g_captureHandle = dlopen(pathBuf, 1);
    if (g_captureHandle == NULL) {
        AUDIO_FUNC_LOGE("Open so Fail, reason:%s", dlerror());
        return HDF_FAILURE;
    }
    if (InitReleaseFun() < 0) {
        AUDIO_FUNC_LOGE("InitReleaseFun Fail");
        dlclose(g_captureHandle);
        return HDF_FAILURE;
    }
    struct AudioPort audioPort;
    audioPort.dir = PORT_IN;
    audioPort.portId = 0;
    audioPort.portName = "AOP";
    if (CaptureGetAdapterAndInitEnvParams(g_adapterName) < 0) {
        AUDIO_FUNC_LOGE("GetCaptureProxyManagerFunc Fail");
        if (g_audioManager != NULL) {
            g_AudioManagerRelease(g_audioManager);
            g_audioManager = NULL;
        }
        dlclose(g_captureHandle);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SetCaptureMute(struct AudioCapture **capture)
{
    (void)capture;
    int32_t val = 0;
    bool isMute = false;
    int32_t ret;
    if (g_capture == NULL || g_capture->GetMute == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->GetMute((void *)g_capture, &isMute);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The current mute state was not obtained!");
    }
    printf("Now %s ,Do you need to set mute status(1/0):\n", isMute ? "mute" : "not mute");
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (isMute != 0 && isMute != 1) {
        AUDIO_FUNC_LOGE("Invalid value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture == NULL || g_capture->SetMute == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (val == 1) {
        ret = g_capture->SetMute((void *)g_capture, !isMute);
    }
    return ret;
}

int32_t SetCaptureVolume(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    float val = 0.5;
    if (g_capture == NULL || g_capture->GetVolume == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->GetVolume((void *)g_capture, &val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get current volume failed,");
        SystemInputFail();
        return ret;
    }
    printf("Now the volume is %f ,Please enter the volume value you want to set (0.0-1.0):\n", val);
    ret = CheckInputName(INPUT_FLOAT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (val < 0.0 || val > 1.0) {
        AUDIO_FUNC_LOGE("Invalid volume value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture->SetVolume == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->SetVolume((void *)g_capture, val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("set volume fail,");
        SystemInputFail();
    }
    return ret;
}

int32_t SetCaptureGain(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    float val = 1.0;
    if (g_capture == NULL || g_capture->GetGain == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->GetGain((void *)g_capture, &val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get current gain failed,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("Now the gain is %f, Please enter the gain value you want to set (0.0-15.0):\n", val);
    ret = CheckInputName(INPUT_FLOAT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    // gain is 0.0 ~ 15.0
    if (val < 0.0 || val > 15.0) {
        AUDIO_FUNC_LOGE("Invalid gain value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture->SetGain == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->SetGain((void *)g_capture, val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set capture gain failed,");
        SystemInputFail();
    }
    return ret;
}

int32_t SetCaptyrePause(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    if (g_capture == NULL || g_capture->Pause == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->Pause((void *)g_capture);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SetCaptureResume(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    if (g_capture == NULL || g_capture->Resume == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->Resume((void *)g_capture);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void PrintAttributesFromat(void)
{
    printf(" ============= Capture Sample Attributes Fromat =============== \n");
    printf("| 1. Capture AUDIO_FORMAT_PCM_8_BIT                            |\n");
    printf("| 2. Capture AUDIO_FORMAT_PCM_16_BIT                           |\n");
    printf("| 3. Capture AUDIO_FORMAT_PCM_24_BIT                           |\n");
    printf("| 4. Capture AUDIO_FORMAT_PCM_32_BIT                           |\n");
    printf(" ============================================================== \n");
}

int32_t SelectAttributesFomat(uint32_t *fomat)
{
    if (fomat == NULL) {
        return HDF_FAILURE;
    }
    PrintAttributesFromat();
    printf("Please select audio format,If not selected, the default is 16bit:");
    int32_t ret;
    int val = 0;
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    switch (val) {
        case AUDIO_FORMAT_PCM_8_BIT:
            *fomat = AUDIO_FORMAT_PCM_8_BIT;
            break;
        case AUDIO_FORMAT_PCM_16_BIT:
            *fomat = AUDIO_FORMAT_PCM_16_BIT;
            break;
        case AUDIO_FORMAT_PCM_24_BIT:
            *fomat = AUDIO_FORMAT_PCM_24_BIT;
            break;
        case AUDIO_FORMAT_PCM_32_BIT:
            *fomat = AUDIO_FORMAT_PCM_32_BIT;
            break;
        default:
            *fomat = AUDIO_FORMAT_PCM_16_BIT;
            break;
    }
    return HDF_SUCCESS;
}

int32_t SetCaptureAttributes(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    struct AudioSampleAttributes attrs;
    if (g_capture == NULL || g_capture->GetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("pointer is NULL");
        return HDF_FAILURE;
    }
    ret = g_capture->GetSampleAttributes((void *)g_capture, &attrs);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetCaptureAttributes failed\n");
    } else {
        printf("Current sample attributes:\n");
        printf("audioType is %u\nfomat is %u\nsampleRate is %u\nchannalCount is"
               "%u\nperiod is %u\nframesize is %u\nbigEndian is %u\nSignedData is %u\n",
            attrs.type, attrs.format, attrs.sampleRate, attrs.channelCount, attrs.period, attrs.frameSize,
            attrs.isBigEndian, attrs.isSignedData);
    }
    printf("Set Sample Attributes,");
    SystemInputFail();
    system("clear");
    printf("The sample attributes you want to set,Step by step, please.\n");
    ret = SelectAttributesFomat((uint32_t *)(&attrs.format));
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetCaptureAttributes format failed");
        return HDF_FAILURE;
    }
    printf("\nPlease input sample rate(48000,44100,32000...):");
    ret = CheckInputName(INPUT_UINT32, (void *)(&attrs.sampleRate));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    printf("\nPlease input bigEndian(false=0/true=1):");
    ret = CheckInputName(INPUT_UINT32, (void *)(&attrs.isBigEndian));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (g_capture == NULL || g_capture->SetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand set the attrbutes,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_capture->SetSampleAttributes((void *)g_capture, &attrs);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set capture attributes failed,");
        SystemInputFail();
    }
    return ret;
}

int32_t SelectCaptureScene(struct AudioCapture **capture)
{
    (void)capture;
    system("clear");
    int32_t ret;
    int val = 0;
    struct AudioSceneDescriptor scene;
    printf(" ====================  Select Scene ==================== \n");
    printf("0 is Mic.                                               |\n");
    printf("1 is Headphone mic.                                     |\n");
    printf(" ======================================================= \n");
    printf("Please input your choice:\n");
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0 || (val != 0 && val != 1)) {
        AUDIO_FUNC_LOGE("Invalid value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (val == 1) {
        scene.scene.id = 0;
        scene.desc.pins = PIN_IN_HS_MIC;
    } else {
        scene.scene.id = 0;
        scene.desc.pins = PIN_IN_MIC;
    }
    scene.desc.desc = "mic";
    if (g_capture == NULL) {
        AUDIO_FUNC_LOGE("Record already stop,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture->SelectScene == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->SelectScene((void *)g_capture, &scene);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Select scene fail");
    }
    return ret;
}
int32_t GetCaptureExtParams(struct AudioCapture **capture)
{
    (void)capture;
    char keyValueList[BUFFER_LEN] = {0};
    int32_t ret;
    if (g_capture == NULL || g_capture->GetExtraParams == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->GetExtraParams((void *)g_capture, keyValueList, EXT_PARAMS_MAXLEN);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get EXT params failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("keyValueList = %s\n", keyValueList);
    return HDF_SUCCESS;
}

int32_t GetCaptureMmapPosition(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    if (g_capture == NULL || g_capture->GetMmapPosition == NULL) {
        return HDF_FAILURE;
    }
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;
    ret = g_capture->GetMmapPosition((void *)g_capture, &frames, &time);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get current Mmap frames Position failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("Now the Position is %" PRIu64 "\n", frames);
    SystemInputFail();
    return HDF_SUCCESS;
}

void PrintMenu2(void)
{
    printf(" ================== Play Capture Menu ================== \n");
    printf("| 1. Capture Start                                      |\n");
    printf("| 2. Capture Stop                                       |\n");
    printf("| 3. Capture Resume                                     |\n");
    printf("| 4. Capture Pause                                      |\n");
    printf("| 5. Capture SetVolume                                  |\n");
    printf("| 6. Capture SetGain                                    |\n");
    printf("| 7. Capture SetMute                                    |\n");
    printf("| 8. Capture SetAttributes                              |\n");
    printf("| 9. Capture SelectScene                                |\n");
    printf("| 10. Capture GetExtParams                              |\n");
    printf("| 11. Capture getMmapPosition                           |\n");
    printf("| 12.Exit                                               |\n");
    printf(" ======================================================= \n");
}

static struct ProcessCaptureMenuSwitchList g_processCaptureMenuSwitchList[] = {
    {CAPTURE_START, StartButtonCapture},
    {CAPTURE_STOP, StopButtonCapture},
    {CAPTURE_RESUME, SetCaptureResume},
    {CAPTURE_PAUSE, SetCaptyrePause},
    {SET_CAPTURE_VOLUME, SetCaptureVolume},
    {SET_CAPTURE_GAIN, SetCaptureGain},
    {SET_CAPTURE_MUTE, SetCaptureMute},
    {SET_CAPTURE_ATTRIBUTES, SetCaptureAttributes},
    {SET_CAPTURE_SLECET_SCENE, SelectCaptureScene},
    {GET_CAPTURE_EXT_PARAMS, GetCaptureExtParams},
    {GET_CAPTURE_POSITION, GetCaptureMmapPosition},
};

void ProcessMenu(int32_t choice)
{
    int32_t i;
    if (choice == GET_CAPTURE_POSITION + 1) {
        AUDIO_FUNC_LOGE("Exit from application program!");
        return;
    }
    if (g_capture == NULL && choice != 1) {
        AUDIO_FUNC_LOGE("this capture already release,");
        SystemInputFail();
        return;
    }
    for (i = CAPTURE_START; i <= GET_CAPTURE_POSITION; ++i) {
        if ((choice == (int32_t)g_processCaptureMenuSwitchList[i - 1].cmd) &&
            (g_processCaptureMenuSwitchList[i - 1].operation != NULL)) {
            g_processCaptureMenuSwitchList[i - 1].operation(&g_capture);
        }
    }
}

void PrintMenu0(void)
{
    printf(" ============== Play Capture select ===========\n");
    printf("| 1. Capture Poll                             |\n");
    printf("| 2. Capture Interrupt                        |\n");
    printf(" ==============================================\n");
}

void Choice0(void)
{
    system("clear");
    int choice = 0;
    PrintMenu0();
    printf("Please enter your choice:");
    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        return;
    }
    switch (choice) {
        case CAPTURE_POLL:
            g_CaptureModeFlag = CAPTURE_POLL;
            break;
        case CAPTURE_INTERUPT:
            g_CaptureModeFlag = CAPTURE_INTERUPT;
            break;
        default:
            printf("Input error,Switched to Poll mode in for you,");
            SystemInputFail();
            break;
    }
    return;
}

void Choice(void)
{
    int32_t option = 0;
    while (option < GET_CAPTURE_POSITION + 1 && option >= 0) {
        system("clear");
        PrintMenu2();
        printf("your choice is:\n");
        int32_t ret = CheckInputName(INPUT_INT, (void *)&option);
        if (ret < 0) {
            continue;
        }
        if (option < CAPTURE_START || option > GET_CAPTURE_POSITION + 1) {
            printf("You input is wrong,");
            option = 0;
            SystemInputFail();
            continue;
        }
        ProcessMenu(option);
    }
}

int32_t CheckAndOpenFile(int32_t argc, char const *argv[])
{
    if (argc < 2 || argv == NULL || argv[0] == NULL) { // The parameter number is not greater than 2
        printf("usage:[1]sample [2]/data/test.wav\n");
        return HDF_FAILURE;
    }
    int32_t ret;
    if (argv[1] == NULL || strlen(argv[1]) == 0) {
        return HDF_FAILURE;
    }
    ret = strncpy_s(g_path, PATH_LEN - 1, argv[1], strlen(argv[1]) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("copy fail");
        return HDF_FAILURE;
    }
    char *path = g_path;
    if (path == NULL) {
        return HDF_FAILURE;
    }
    FILE *file = fopen(path, "wb+");
    if (file == NULL) {
        printf("failed to open '%s',Please enter the correct file name \n", g_path);
        return HDF_FAILURE;
    }
    (void)fclose(file);
    return HDF_SUCCESS;
}

int32_t main(int32_t argc, char const *argv[])
{
    int32_t ret = CheckAndOpenFile(argc, argv);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    if (InitParam()) { // init
        AUDIO_FUNC_LOGE("InitParam Fail");
        return HDF_FAILURE;
    }
    Choice0();

    Choice();
    if (g_capture != NULL && g_adapter != NULL) {
        StopButtonCapture(&g_capture);
    }
    if (g_audioManager != NULL && g_audioManager->UnloadAdapter != NULL) {
        g_audioManager->UnloadAdapter(g_audioManager, g_adapterName);
        g_AudioAdapterRelease(g_adapter);
        g_adapter = NULL;
        g_AudioManagerRelease(g_audioManager);
        g_audioManager = NULL;
    }
    dlclose(g_captureHandle);
    printf("Record file path:%s\n", g_path);
    return 0;
}
