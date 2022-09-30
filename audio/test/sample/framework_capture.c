/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "inttypes.h"
#include "ioservstat_listener.h"
#include "hdf_base.h"
#include "hdf_io_service_if.h"
#ifndef __LITEOS__
#include "hdf_remote_adapter_if.h"
#endif
#include "hdf_service_status.h"
#include "svcmgr_ioservice.h"
#include "audio_events.h"
#include "audio_manager.h"
#include "framework_common.h"
#include "hdf_audio_events.h"

#define WAV_HEAD_OFFSET 44
#define WAV_HEAD_RIFF_OFFSET 8

#define AUDIO_CHANNELCOUNT 2
#define AUDIO_SAMPLE_RATE_48K 48000
#define PATH_LEN 256

#define BUFFER_PERIOD_SIZE (4 * 1024)
#define DEEP_BUFFER_RENDER_PERIOD_SIZE 4096
#define DEEP_BUFFER_RENDER_PERIOD_COUNT 8
#define INT_32_MAX 0x7fffffff
#define BUFFER_SIZE_BASE 1024
#define AUDIO_BUFF_SIZE (1024 * 16)
#define AUDIO_TOTALSIZE_15M (1024 * 15)
#define AUDIO_RECORD_INTERVAL_512KB 512
#define FILE_CAPTURE_SIZE (1024 * 1024 * 3) // 3M
#define BUFFER_LEN 256
#define EXT_PARAMS_MAXLEN 107
#define ONE_MS 1000
#define BITS_TO_FROMAT 3

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
struct AudioManager *g_manager = NULL;
static struct StrParaCapture g_str;
void *g_captureHandle;

pthread_t g_tids;
FILE *g_file;
char *g_frame;
void *g_handle;
char g_path[256] = {'\0'};

enum AudioCaptureMode {
    CAPTURE_POLL   = 1,
    CAPTURE_INTERUPT,
};

int g_captureModeFlag = CAPTURE_POLL;

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
static int32_t CheckInputName(int type, void *val)
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
                SystemInputFail();
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
            if (inputUint > 0xFFFFFFFF) {
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

static int32_t InitAttrsCapture(struct AudioSampleAttributes *captureAttrs)
{
    if (captureAttrs == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    captureAttrs->format = AUDIO_FORMAT_PCM_16_BIT;
    captureAttrs->channelCount = AUDIO_CHANNELCOUNT;
    captureAttrs->sampleRate = AUDIO_SAMPLE_RATE_48K;
    captureAttrs->interleaved = 1;
    captureAttrs->type = AUDIO_IN_MEDIA;
    captureAttrs->period = BUFFER_PERIOD_SIZE;
    captureAttrs->frameSize = PCM_16_BIT * captureAttrs->channelCount / PCM_8_BIT;
    captureAttrs->isBigEndian = false;
    captureAttrs->isSignedData = true;
    captureAttrs->startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (captureAttrs->frameSize);
    captureAttrs->stopThreshold = INT_32_MAX;
    captureAttrs->silenceThreshold = AUDIO_BUFF_SIZE;
    return 0;
}

static int32_t InitDevDescCapture(struct AudioDeviceDescriptor *devDesc,
    uint32_t portId)
{
    if (devDesc == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    devDesc->portId = portId;
    devDesc->pins = PIN_IN_MIC;
    devDesc->desc = NULL;
    return 0;
}

void StreamClose(int32_t sig)
{
    /* allow the stream to be closed gracefully */
    (void)signal(sig, SIG_IGN);
    g_closeEnd = 1;
}

static uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs)
{
    return DEEP_BUFFER_RENDER_PERIOD_SIZE * attrs.channelCount * (PcmFormatToBits(attrs.format) >> BITS_TO_FROMAT);
}

#ifndef __LITEOS__
static int AudioPnpSvcThresholdMsgCheck(struct ServiceStatus *svcStatus, struct AudioEvent *audioEvent)
{
    if (svcStatus == NULL || audioEvent == NULL) {
        printf("AudioPnpSvcThresholdMsgCheck:input param is null!\n");
        return HDF_FAILURE;
    }
    if ((AudioPnpMsgReadValue(svcStatus->info, "EVENT_TYPE", &(audioEvent->eventType)) != HDF_SUCCESS) ||
        (AudioPnpMsgReadValue(svcStatus->info, "DEVICE_TYPE", &(audioEvent->deviceType)) != HDF_SUCCESS)) {
        printf("DeSerialize fail!\n");
        return HDF_FAILURE;
    }
    if (audioEvent->eventType != HDF_AUDIO_CAPTURE_THRESHOLD || audioEvent->deviceType != HDF_AUDIO_PRIMARY_DEVICE) {
        printf("AudioPnpSvcThresholdMsgCheck deviceType not fit.\n");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void AudioPnpSvcEvenReceived(struct ServiceStatusListener *listener, struct ServiceStatus *svcStatus)
{
    struct StrParaCapture *strParam = NULL;
    struct AudioCapture *capture = NULL;
    uint32_t bufferSize = AUDIO_BUFF_SIZE;   // 16 * 1024 = 16KB, it needs to be calculated by audio parameters
    uint64_t replyBytes = 0;
    uint64_t requestBytes = AUDIO_BUFF_SIZE; // 16 * 1024 = 16KB
    int32_t index = 0;
    struct AudioEvent audioEvent = {0};
    char *frame = NULL;

    if ((svcStatus == NULL) || (listener == NULL)) {
        printf("input param is null!\n");
        return;
    }
    if (AudioPnpSvcThresholdMsgCheck(svcStatus, &audioEvent) != HDF_SUCCESS) {
        return;
    }
    strParam = (struct StrParaCapture *)listener->priv;
    if (strParam == NULL) {
        printf("strParam is null \n");
        return;
    }
    capture = strParam->capture;
    if (capture == NULL || capture->CaptureFrame == NULL || strParam->file == NULL) {
        printf("capture is null \n");
        return;
    }
    frame = (char *)calloc(1, bufferSize);
    if (frame == NULL) {
        printf("calloc frame failed!\n");
        return;
    }
    g_receiveFrameCount++;
    for (index = g_receiveFrameCount; index > 0; index--) {
        if (capture->CaptureFrame(capture, frame, requestBytes, &replyBytes) != HDF_SUCCESS) {
            printf("\nCaptureFrame fail\n");
        } else {
            fwrite(frame, (size_t)replyBytes, 1, strParam->file);
            g_receiveFrameCount--;
            g_totalSize += (replyBytes / BUFFER_SIZE_BASE); // 1024 = 1Kb
            if (g_totalSize % AUDIO_RECORD_INTERVAL_512KB == 0) { // 512KB
                printf("\nRecording,the audio file size is %"PRIu64"Kb\n", g_totalSize);
            }
        }
    }
    free(frame);
    return;
}

static int RegisterListen(const struct StrParaCapture *capture)
{
    int status;
    if (capture == NULL) {
        return -1;
    }
    g_totalSize = 0;
    g_receiveFrameCount = 0;

    g_servmgr = SvcMgrIoserviceGet(); // kernel
    g_listener = IoServiceStatusListenerNewInstance(); // kernel
    if (g_servmgr == NULL || g_listener == NULL) {
        printf("g_servmgr status g_listener is null .\n");
        return -1;
    }

    g_listener->callback = AudioPnpSvcEvenReceived;
    g_listener->priv = (void *)capture;

    status = g_servmgr->RegisterServiceStatusListener(g_servmgr, g_listener, DEVICE_CLASS_AUDIO);
    if (status != HDF_SUCCESS) {
        printf("RegisterServiceStatusListener file ret = %d.\n", status);
        return -1;
    }

    printf("RegisterListen success \n");
    return 0;
}

static int UnRegisterListen(void)
{
    if (g_servmgr == NULL || g_listener == NULL) {
        printf("UnRegisterListen: input para is null!\n");
        return -1;
    }
    int32_t ret = g_servmgr->UnregisterServiceStatusListener(g_servmgr, g_listener);
    if (ret != HDF_SUCCESS) {
        printf("UnregisterServiceStatusListener file ret = %d.\n", ret);
        return -1;
    }

    printf("UnregisterServiceStatusListener success \n");
    return 0;
}
#endif

static int32_t AddWavFileHeader(const struct StrParaCapture *strParam)
{
    if (strParam == NULL) {
        AUDIO_FUNC_LOGE("InitCaptureStrParam is NULL");
        return HDF_FAILURE;
    }

    struct AudioHeadInfo headInfo;
    (void)fseek(g_file, 0, SEEK_END);

    headInfo.riffId = StringToInt("RIFF");
    headInfo.riffSize = (uint32_t)ftell(g_file) - WAV_HEAD_RIFF_OFFSET;
    headInfo.waveType = StringToInt("WAVE");
    headInfo.audioFileFmtId = StringToInt("fmt ");
    headInfo.audioFileFmtSize = PcmFormatToBits(strParam->attrs.format);
    headInfo.audioFileFormat = 1;
    headInfo.audioChannelNum = strParam->attrs.channelCount;
    headInfo.audioSampleRate = strParam->attrs.sampleRate;
    headInfo.audioByteRate = headInfo.audioSampleRate * headInfo.audioChannelNum *
        headInfo.audioFileFmtSize / PCM_8_BIT;
    headInfo.audioBlockAlign = (uint16_t)(headInfo.audioChannelNum * headInfo.audioFileFmtSize / PCM_8_BIT);
    headInfo.audioBitsPerSample = (uint16_t)headInfo.audioFileFmtSize;
    headInfo.dataId = StringToInt("data");
    headInfo.dataSize = (uint32_t)ftell(g_file) - WAV_HEAD_OFFSET;

    rewind(g_file);

    size_t ret = fwrite(&headInfo, sizeof(struct AudioHeadInfo), 1, g_file);
    if (ret != 1) {
        printf("write wav file head error");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t StopButtonCapture(struct AudioCapture **captureS)
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
    int ret = capture->control.Stop((AudioHandle)capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Stop capture!");
    }
    if (g_adapter == NULL || g_adapter->DestroyCapture == NULL) {
        return HDF_FAILURE;
    }
    ret = g_adapter->DestroyCapture(g_adapter, capture);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Capture already destroy!");
    }
    capture = NULL;
    g_capture = NULL;
    if (g_frame != NULL) {
        free(g_frame);
        g_frame = NULL;
    }

    if (AddWavFileHeader(&g_str) < 0) {
        AUDIO_FUNC_LOGE("AddWavFileHeader Fail");
        return HDF_FAILURE;
    }

    FileClose(&g_file);
    if (g_captureModeFlag == CAPTURE_INTERUPT) {
#ifndef __LITEOS__
        ret = UnRegisterListen();
        if (ret < 0) {
            AUDIO_FUNC_LOGE("UnRegisterListen failed!");
        }
#endif
    }
    printf("Stop Successful\n");
    return HDF_SUCCESS;
}

static int32_t FrameStartCaptureMmap(const AudioHandle param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    struct StrParaCapture *strParam = (struct StrParaCapture *)param;
    struct AudioCapture *capture = strParam->capture;
    struct AudioMmapBufferDescripter desc;
    // Modify file size

    int fd = fileno(strParam->file);
    if (fd == -1) {
        printf("fileno failed, fd is %d\n", fd);
        return HDF_FAILURE;
    }
    ftruncate(fd, FILE_CAPTURE_SIZE);
    // Init param
    desc.memoryFd = fd;
    desc.isShareable = 1; // 1:Shareable ,0:Don't share
    desc.transferFrameSize = DEEP_BUFFER_RENDER_PERIOD_SIZE / 4; // One frame size 4 bit
    desc.offset = 0; // Recording must be 0
    // start
    if (capture == NULL || capture->attr.ReqMmapBuffer == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret = capture->attr.ReqMmapBuffer(capture, FILE_CAPTURE_SIZE, &desc);
    if (ret < 0) {
        printf("Request map fail,please check.\n");
        return HDF_FAILURE;
    }
    ret = msync(desc.memoryAddress, FILE_CAPTURE_SIZE, MS_ASYNC);
    if (ret < 0) {
        printf("sync fail.\n");
    }
    munmap(desc.memoryAddress, FILE_CAPTURE_SIZE);
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
    *totalSize += (replyBytes / BUFFER_SIZE_BASE); // 1024 = 1Kb
    if (*totalSize % AUDIO_RECORD_INTERVAL_512KB == 0) { // 512KB
        printf("\nRecording,the audio file size is %"PRIu64"Kb\n", *totalSize);
    }
    return HDF_SUCCESS;
}

static int32_t FrameStartCapture(const AudioHandle param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    uint32_t bufferSize = AUDIO_BUFF_SIZE;
    uint64_t requestBytes = AUDIO_BUFF_SIZE;
    struct StrParaCapture *strParam = (struct StrParaCapture *)param;
    struct AudioCapture *capture = strParam->capture;
    uint64_t replyBytes = 0;
    uint64_t totalSize = 0;
    uint32_t failCount = 0;
    if (capture == NULL || capture->CaptureFrame == NULL) {
        return HDF_FAILURE;
    }
    char *frame = (char *)calloc(1, bufferSize);
    if (frame == NULL) {
        return HDF_FAILURE;
    }
    do {
        int32_t ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
        if (ret < 0) {
            if (ret == HDF_ERR_INVALID_OBJECT) {
                AUDIO_FUNC_LOGE("Record already stop!");
                break;
            }
            usleep(ONE_MS);
            if (failCount++ >= 300000) { // Try 300000 times for CaptureFrame fail
                free(frame);
                return HDF_FAILURE;
            }
            continue;
        }
        if (WriteDataToFile(strParam->file, frame, replyBytes, &failCount, &totalSize) < 0) {
            free(frame);
            return HDF_FAILURE;
        }
    } while ((totalSize <= AUDIO_TOTALSIZE_15M) && (!g_closeEnd)); // 15 * 1024 = 15M
    free(frame);
    if (!g_closeEnd) {
        if (StopButtonCapture(&g_capture) < 0) {
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}
static void PrintRecordMode(void)
{
    printf(" ============= Play Capture Mode ==========\n");
    printf("| 1. Capture non-mmap                     |\n");
    printf("| 2. Capture mmap                         |\n");
    printf(" ========================================= \n");
}

static int32_t SelectPlayMode(int32_t *recordModeFlag)
{
    if (recordModeFlag == NULL) {
        AUDIO_FUNC_LOGE("recordModeFlag is null");
        return HDF_FAILURE;
    }
    system("clear");
    int choice = 0;
    PrintRecordMode();
    printf("Please enter your choice:");
    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CheckInputName Fail");
        return HDF_FAILURE;
    } else {
        *recordModeFlag = choice;
    }
    return HDF_SUCCESS;
}

static int32_t StartRecordThread(int32_t recordModeFlag)
{
    pthread_attr_t tidsAttr;
    pthread_attr_init(&tidsAttr);
    pthread_attr_setdetachstate(&tidsAttr, PTHREAD_CREATE_DETACHED);
    switch (recordModeFlag) {
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

static int32_t CaptureChoiceModeAndRecording(struct StrParaCapture *strParam, struct AudioCapture *capture,
    int32_t recordModeFlag)
{
    if (strParam == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("InitCaptureStrParam is NULL");
        return HDF_FAILURE;
    }
    int32_t ret;
    (void)memset_s(strParam, sizeof(struct StrParaCapture), 0, sizeof(struct StrParaCapture));
    strParam->capture = capture;
    strParam->file = g_file;
    strParam->attrs = g_attrs;
    strParam->frame = g_frame;
    if (g_captureModeFlag == CAPTURE_INTERUPT) {
#ifndef __LITEOS__
        ret = RegisterListen(&g_str);
        if (ret != 0) {
            printf("---RegisterListen faile--- \n");
            return HDF_FAILURE;
        }
#else
        printf("not support liteos!");
        return HDF_FAILURE;
#endif
    } else {
        if (StartRecordThread(recordModeFlag) < 0) {
            AUDIO_FUNC_LOGE("Create Thread Fail");
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

static int32_t RecordingAudioInitFile(void)
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

static int32_t RecordingAudioInitCapture(struct AudioCapture **captureTemp)
{
    if (captureTemp == NULL || g_adapter == NULL || g_adapter->CreateCapture == NULL ||
        g_adapter->DestroyCapture == NULL) {
        AUDIO_FUNC_LOGE("captureTemp is null");
        return HDF_FAILURE;
    }

    struct AudioCapture *capture = NULL;
    int32_t ret = g_adapter->CreateCapture(g_adapter, &g_devDesc, &g_attrs, &capture);
    if (capture == NULL || ret < 0) {
        return HDF_FAILURE;
    }
    ret = capture->control.Start((AudioHandle)capture);
    if (ret < 0) {
        g_adapter->DestroyCapture(g_adapter, capture);
        return HDF_FAILURE;
    }
    uint32_t bufferSize = PcmFramesToBytes(g_attrs);
    g_frame = (char *)calloc(1, bufferSize);
    if (g_frame == NULL) {
        g_adapter->DestroyCapture(g_adapter, capture);
        return HDF_FAILURE;
    }

    *captureTemp = capture;
    return HDF_SUCCESS;
}

static int32_t StartButtonCapture(struct AudioCapture **captureS)
{
    if (captureS == NULL || g_adapter == NULL || g_adapter->CreateCapture == NULL) {
        return HDF_FAILURE;
    }
    if (RecordingAudioInitFile() < 0) {
        AUDIO_FUNC_LOGE("Init file Failed.");
        return HDF_FAILURE;
    }
    int32_t recordModeFlag = 0;
    if (SelectPlayMode(&recordModeFlag) < 0) {
        AUDIO_FUNC_LOGE("SelectPlayMode Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    struct AudioCapture *capture = NULL;
    if (RecordingAudioInitCapture(&capture) < 0) {
        AUDIO_FUNC_LOGE("RecordingAudioInitCapture Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    if (CaptureChoiceModeAndRecording(&g_str, capture, recordModeFlag) < 0) {
        AUDIO_FUNC_LOGE("CaptureChoiceModeAndRecording failed");
        FileClose(&g_file);
        if (g_adapter != NULL && g_adapter->DestroyCapture != NULL) {
            g_adapter->DestroyCapture(g_adapter, capture);
        }
        return HDF_FAILURE;
    }
    *captureS = capture;
    printf("Start Successful\n");
    return HDF_SUCCESS;
}

static int32_t SwitchAdapterCapture(struct AudioAdapterDescriptor *descs, const char *adapterNameCase,
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
        if (strcmp(desc->adapterName, adapterNameCase)) {
            printf("adapter name case = %s\n", adapterNameCase);
            continue;
        }
        for (port = 0; port < desc->portNum; port++) {
            // Only find out the port of out in the sound card
            if (desc->ports[port].dir == portFlag) {
                *capturePort = desc->ports[port];
                return index;
            }
        }
    }
    return HDF_FAILURE;
}
static void PrintMenu1(void)
{
    printf(" ============== Play Capture Loading Mode ===========\n");
    printf("| 1. Capture Direct Loading                         |\n");
    printf("| 2. Capture Service Loading                        |\n");
    printf("| Note: switching is not supported in the MPI's     |\n");
    printf("|       version.                                    |\n");
    printf(" =================================================== \n");
}

static int32_t SelectLoadingMode(char *resolvedPath, int32_t pathLen)
{
    system("clear");
    int choice = 0;
    int32_t ret;
    PrintMenu1();
    printf("Please enter your choice:");
    ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("capture CheckInputName failed!");
        return HDF_FAILURE;
    }
    ret = FormatLoadLibPath(resolvedPath, pathLen, choice);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("capture FormatLoadLibPath failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static struct AudioManager *GetAudioManagerInsForCapture(const char *funcString)
{
    struct AudioManager *(*getAudioManager)(void) = NULL;
    if (funcString == NULL) {
        AUDIO_FUNC_LOGE("funcString is null!");
        return NULL;
    }
    if (g_captureHandle == NULL) {
        AUDIO_FUNC_LOGE("g_captureHandle is null!");
        return NULL;
    }
    getAudioManager = (struct AudioManager *(*)())(dlsym(g_captureHandle, funcString));
    if (getAudioManager == NULL) {
        AUDIO_FUNC_LOGE("Get Audio Manager Funcs Fail");
        return NULL;
    }
    return getAudioManager();
}

static int32_t GetCaptureManagerFunc(const char *adapterNameCase)
{
    struct AudioAdapterDescriptor *descs = NULL;
    enum AudioPortDirection port = PORT_OUT; // Set port information
    struct AudioPort capturePort;
    int32_t size = 0;
    if (adapterNameCase == NULL) {
        AUDIO_FUNC_LOGE("The Parameter is NULL");
        return HDF_FAILURE;
    }
#ifndef __LITEOS__
    (void)HdfRemoteGetCallingPid();
#endif
    struct AudioManager *manager = GetAudioManagerInsForCapture("GetAudioManagerFuncs");
    if (manager == NULL) {
        AUDIO_FUNC_LOGE("GetAudioManagerInsForCapture Fail");
        return HDF_FAILURE;
    }
    int32_t ret = manager->GetAllAdapters(manager, &descs, &size);
    if ((size == 0) || (descs == NULL) || (ret < 0)) {
        AUDIO_FUNC_LOGE("Get All Adapters Fail");
        return HDF_ERR_NOT_SUPPORT;
    }
    int32_t index = SwitchAdapterCapture(descs, adapterNameCase, port, &capturePort, size);
    if (index < 0) {
        AUDIO_FUNC_LOGE("Not Switch Adapter Fail");
        return HDF_ERR_NOT_SUPPORT;
    }
    struct AudioAdapterDescriptor *desc = &descs[index];
    if (manager->LoadAdapter(manager, desc, &g_adapter) != 0) {
        AUDIO_FUNC_LOGE("Load Adapter Fail");
        return HDF_ERR_NOT_SUPPORT;
    }
    g_manager = manager;
    if (g_adapter == NULL) {
        AUDIO_FUNC_LOGE("load audio device failed");
        return HDF_FAILURE;
    }
    (void)g_adapter->InitAllPorts(g_adapter);
    if (InitAttrsCapture(&g_attrs) < 0) {
        g_manager->UnloadAdapter(g_manager, g_adapter);
        return HDF_FAILURE;
    }
    // Specify a hardware device
    if (InitDevDescCapture(&g_devDesc, capturePort.portId) < 0) {
        g_manager->UnloadAdapter(g_manager, g_adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t InitParam(void)
{
    char resolvedPath[PATH_LEN] = {0};
    if (SelectLoadingMode(resolvedPath, PATH_LEN) < 0) {
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(resolvedPath, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    g_captureHandle = dlopen(pathBuf, 1);
    if (g_captureHandle == NULL) {
        AUDIO_FUNC_LOGE("Open so Fail, reason:%s", dlerror());
        return HDF_FAILURE;
    }
    char adapterNameCase[PATH_LEN] = "primary";

    if (GetCaptureManagerFunc(adapterNameCase) < 0) {
        AUDIO_FUNC_LOGE("GetCaptureManagerFunc Failed.");
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static int32_t SetCaptureMute(struct AudioCapture **capture)
{
    (void)capture;
    int32_t val = 0;
    bool isMute = false;
    int32_t ret;
    if (g_capture == NULL || g_capture->volume.GetMute == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->volume.GetMute((AudioHandle)g_capture, &isMute);
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
    if (g_capture == NULL || g_capture->volume.SetMute == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (val == 1) {
        ret = g_capture->volume.SetMute((AudioHandle)g_capture, !isMute);
    }
    return ret;
}

static int32_t SetCaptureVolume(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    float val = 0.5;
    if (g_capture == NULL || g_capture->volume.GetVolume == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->volume.GetVolume((AudioHandle)g_capture, &val);
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
    if (g_capture->volume.SetVolume == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->volume.SetVolume((AudioHandle)g_capture, val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("set volume fail,");
        SystemInputFail();
    }
    return ret;
}

static int32_t SetCaptureGain(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    float val = 1.0;
    if (g_capture == NULL || g_capture->volume.GetGain == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->volume.GetGain((AudioHandle)g_capture, &val);
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
    if (g_capture->volume.SetGain == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->volume.SetGain((AudioHandle)g_capture, val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set capture gain failed,");
        SystemInputFail();
    }
    return ret;
}

static int32_t SetCaptyrePause(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    if (g_capture == NULL || g_capture->control.Pause == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->control.Pause((AudioHandle)g_capture);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SetCaptureResume(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    if (g_capture == NULL || g_capture->control.Resume == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->control.Resume((AudioHandle)g_capture);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static void PrintAttributesFromat(void)
{
    printf(" ============= Capture Sample Attributes Format =============== \n");
    printf("| 1. Capture AUDIO_FORMAT_PCM_8_BIT                            |\n");
    printf("| 2. Capture AUDIO_FORMAT_PCM_16_BIT                           |\n");
    printf("| 3. Capture AUDIO_FORMAT_PCM_24_BIT                           |\n");
    printf("| 4. Capture AUDIO_FORMAT_PCM_32_BIT                           |\n");
    printf(" ============================================================== \n");
}

static int32_t SelectAttributesFomat(uint32_t *pcmFomat)
{
    int32_t ret;
    int val = 0;
    if (pcmFomat == NULL) {
        return HDF_FAILURE;
    }
    PrintAttributesFromat();
    printf("Please select audio format,If not selected, the default is 16bit:");
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    ret = CheckPcmFormat(val, pcmFomat);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Capture CheckPcmFormat failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SetCaptureAttributes(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    struct AudioSampleAttributes attrs;
    if (g_capture == NULL || g_capture->attr.GetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("pointer is NULL");
        return HDF_FAILURE;
    }
    ret = g_capture->attr.GetSampleAttributes((AudioHandle)g_capture, &attrs);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetCaptureAttributes failed\n");
    } else {
        printf("Current sample attributes:\n");
        printf("audioType is %u\nfomat is %u\nsampleRate is %u\nchannalCount is"
            "%u\nperiod is %u\nframesize is %u\nbigEndian is %u\nSignedData is %u\n",
            attrs.type, attrs.format, attrs.sampleRate, attrs.channelCount,
            attrs.period, attrs.frameSize, attrs.isBigEndian, attrs.isSignedData);
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
    if (ret < 0) return HDF_FAILURE;
    printf("\nPlease input bigEndian(false=0/true=1):");
    ret = CheckInputName(INPUT_UINT32, (void *)(&attrs.isBigEndian));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (g_capture == NULL || g_capture->attr.SetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand set the attrbutes,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_capture->attr.SetSampleAttributes((AudioHandle)g_capture, &attrs);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set capture attributes failed,");
        SystemInputFail();
    }
    return ret;
}

static int32_t SelectCaptureScene(struct AudioCapture **capture)
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
    if (g_capture == NULL) {
        AUDIO_FUNC_LOGE("Record already stop,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture->scene.SelectScene == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->scene.SelectScene((AudioHandle)g_capture, &scene);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Select scene fail");
    }
    return ret;
}
static int32_t GetCaptureExtParams(struct AudioCapture **capture)
{
    (void)capture;
    char keyValueList[BUFFER_LEN] = {0};
    int32_t ret;
    if (g_capture == NULL || g_capture->attr.GetExtraParams == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->attr.GetExtraParams((AudioHandle)g_capture, keyValueList, EXT_PARAMS_MAXLEN);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get EXT params failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("keyValueList = %s\n", keyValueList);
    return HDF_SUCCESS;
}

static int32_t GetCaptureMmapPosition(struct AudioCapture **capture)
{
    (void)capture;
    int32_t ret;
    if (g_capture == NULL || g_capture->attr.GetMmapPosition == NULL) {
        return HDF_FAILURE;
    }
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;
    ret = g_capture->attr.GetMmapPosition((AudioHandle)g_capture, &frames, &time);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get current Mmap frames Position failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("Now the Position is %"PRIu64"\n", frames);
    SystemInputFail();
    return HDF_SUCCESS;
}

static void PrintMenu2(void)
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

static void ProcessMenu(int32_t choice)
{
    int32_t i;
    if (choice == GET_CAPTURE_POSITION + 1) {
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

static void PrintMenu0(void)
{
    printf(" ============== Play Capture select ===========\n");
    printf("| 1. Capture Poll                             |\n");
    printf("| 2. Capture Interrupt                        |\n");
    printf(" ==============================================\n");
}

static void Choice0(void)
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
            g_captureModeFlag = CAPTURE_POLL;
            break;
        case CAPTURE_INTERUPT:
            g_captureModeFlag = CAPTURE_INTERUPT;
            break;
        default:
            printf("Input error,Switched to Poll mode in for you,");
            SystemInputFail();
            break;
    }
    return;
}


static void Choice(void)
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

static int32_t CheckAndOpenFile(int32_t argc, char const *argv[])
{
    if (argc < 2 || argv == NULL || argv[0] == NULL) { // The parameter number is not greater than 2
        printf("usage:[1]sample [2]/data/test.wav\n");
        return HDF_FAILURE;
    }
    int32_t ret;
    if (argv[1] == NULL || strlen(argv[1]) == 0) {
        return HDF_FAILURE;
    }
    ret = strncpy_s(g_path, PATH_LEN, argv[1], strlen(argv[1]) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("copy fail");
        return HDF_FAILURE;
    }
    char *path = g_path;
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
    if (InitParam() < 0) { // init
        AUDIO_FUNC_LOGE("InitParam Fail");
        return HDF_FAILURE;
    }
    Choice0();

    Choice();
    if (g_capture != NULL && g_adapter != NULL) {
        StopButtonCapture(&g_capture);
    }
    if (g_manager != NULL) {
        if (g_manager->UnloadAdapter != NULL) {
            g_manager->UnloadAdapter(g_manager, g_adapter);
        }
    }
    dlclose(g_handle);
    printf("Record file path:%s\n", g_path);
    return 0;
}
