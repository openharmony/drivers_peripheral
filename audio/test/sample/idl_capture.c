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

#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <securec.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "framework_common.h"
#include "hdf_base.h"
#include "hdf_io_service_if.h"
#include "hdf_service_status.h"
#include "inttypes.h"
#include "ioservstat_listener.h"
#include "osal_mem.h"
#include "svcmgr_ioservice.h"
#include "v4_0/iaudio_manager.h"
#include "v4_0/audio_types.h"

#define MOVE_LEFT_NUM                   8
#define AUDIO_CHANNELCOUNT              2
#define AUDIO_SAMPLE_RATE_48K           48000
#define PATH_LEN                        256
#define BUFFER_PERIOD_SIZE              3840
#define DEEP_BUFFER_RENDER_PERIOD_SIZE  4096
#define DEEP_BUFFER_RENDER_PERIOD_COUNT 8
#define INT_32_MAX                      0x7fffffff
#define BUFFER_SIZE_BASE                1024
#define PCM_8_BIT                       8
#define PCM_16_BIT                      16
#define AUDIO_TOTALSIZE_15M             (1024 * 15)
#define AUDIO_RECORD_INTERVAL_512KB     512
#define MAX_AUDIO_ADAPTER_DESC          5
#define FILE_CAPTURE_SIZE               (1024 * 1024 * 3) // 3M
#define BUFFER_LEN                      256
#define EXT_PARAMS_MAXLEN               107
#define ONE_MS                          1000
#define BITS_TO_FROMAT                  3
#ifndef AUDIO_FEATURE_COMMUNITY
#define AUDIO_CAPTURE_STREAM_ID         14
#define AUDIO_ROUTE_NODE_LEN            1
#else
#define AUDIO_BUFF_SIZE                 (1024 * 16)
#endif

struct IAudioAdapter *g_adapter = NULL;
struct AudioDeviceDescriptor g_devDesc;
struct AudioSampleAttributes g_attrs;
struct IAudioCapture *g_capture = NULL;
static struct IAudioManager *g_audioManager = NULL;
static struct StrParaCapture g_str;
uint32_t g_captureId = 0;

pthread_t g_tids;
FILE *g_file;
char *g_frame;
char g_path[PATH_MAX] = {'\0'};
char g_adapterName[PATH_LEN] = {0};

enum AudioCaptureMode {
    CAPTURE_POLL = 1,
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

typedef int32_t (*AudioCaptureOperation)(struct IAudioCapture **);

struct ProcessCaptureMenuSwitchList {
    enum CaptureMenuId cmd;
    AudioCaptureOperation operation;
};

static int32_t g_closeEnd = 0;
bool g_isDirect = true;
static int g_voiceCallType = 0;

static int32_t CheckInputName(int type, void *val)
{
    if (val == NULL) {
        return HDF_FAILURE;
    }

    int ret;
    int capInputInt = 0;
    float capInputFloat = 0.0;
    uint32_t capInputUint = 0;

    printf("\n");
    switch (type) {
        case INPUT_INT:
            ret = scanf_s("%d", &capInputInt);
            if (capInputInt < 0 || capInputInt > GET_CAPTURE_POSITION + 1) {
                if (g_frame != NULL) {
                    OsalMemFree(g_frame);
                    g_frame = NULL;
                }
                AUDIO_FUNC_LOGE("Input failure");
                return HDF_FAILURE;
            }
            *(int *)val = capInputInt;
            break;
        case INPUT_FLOAT:
            ret = scanf_s("%f", &capInputFloat);
            *(float *)val = capInputFloat;
            break;
        case INPUT_UINT32:
            ret = scanf_s("%u", &capInputUint);
            if (capInputUint > 0xFFFFFFFF) {
                return HDF_FAILURE;
            }
            *(uint32_t *)val = capInputUint;
            break;
        default:
            ret = EOF;
            break;
    }
    if (ret == 0) {
        CleanStdin();
    } else if (ret == EOF) {
        AUDIO_FUNC_LOGE("Input error occurs!");
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
    captureAttrs->format = AUDIO_FORMAT_TYPE_PCM_16_BIT;
    captureAttrs->channelCount = AUDIO_CHANNELCOUNT;
    captureAttrs->sampleRate = AUDIO_SAMPLE_RATE_48K;
    captureAttrs->interleaved = 0;
    captureAttrs->type = AUDIO_IN_MEDIA;
    captureAttrs->period = BUFFER_PERIOD_SIZE;
    captureAttrs->frameSize = PCM_16_BIT * captureAttrs->channelCount / PCM_8_BIT;
    captureAttrs->isBigEndian = false;
    captureAttrs->isSignedData = true;
    captureAttrs->startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (captureAttrs->frameSize);
    captureAttrs->stopThreshold = INT_32_MAX;
#ifndef AUDIO_FEATURE_COMMUNITY
    captureAttrs->silenceThreshold = 0;
    captureAttrs->streamId = AUDIO_CAPTURE_STREAM_ID;
#else
    captureAttrs->silenceThreshold = AUDIO_BUFF_SIZE;
#endif
    captureAttrs->sourceType = g_voiceCallType;
    return 0;
}

static int32_t InitDevDescCapture(struct AudioDeviceDescriptor *devDesc, uint32_t portId)
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

static int32_t StopButtonCapture(struct IAudioCapture **captureS)
{
    if (captureS == NULL) {
        return HDF_FAILURE;
    }

    if (!g_closeEnd) {
        g_closeEnd = true;
        usleep(100000); // sleep 100000us
    }

    struct IAudioCapture *capture = *captureS;
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

    ret = g_adapter->DestroyCapture(g_adapter, g_captureId);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Capture already destroy!");
    }

    IAudioCaptureRelease(capture, g_isDirect);
    *captureS = NULL;
    g_capture = NULL;
    if (g_frame != NULL) {
        OsalMemFree(g_frame);
        g_frame = NULL;
    }

    if (AddWavFileHeader(g_file, &g_str) < 0) {
        AUDIO_FUNC_LOGE("AddWavFileHeader Fail");
        return HDF_FAILURE;
    }

    FileClose(&g_file);

    if (g_captureModeFlag == CAPTURE_INTERUPT) {
        AUDIO_FUNC_LOGE("litoOs  not support!");
    }
    printf("Stop Successful\n");
    return HDF_SUCCESS;
}

static int32_t FrameStartCaptureMmap(const struct StrParaCapture *param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    const struct StrParaCapture *strParam = param;
    struct IAudioCapture *capture = strParam->capture;
    struct AudioMmapBufferDescriptor mmapDesc;
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
        free(mmapDesc.filePath);
        return HDF_FAILURE;
    }
    int32_t ret = capture->ReqMmapBuffer(capture, FILE_CAPTURE_SIZE, &mmapDesc);
    if (ret < 0) {
        free(mmapDesc.filePath);
        printf("Request map fail,please check.\n");
        return HDF_FAILURE;
    }
    free(mmapDesc.filePath);
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

static int32_t FrameStartCapture(const struct StrParaCapture *param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
#ifndef AUDIO_FEATURE_COMMUNITY
    uint32_t bufferSize = BUFFER_PERIOD_SIZE;
    uint64_t requestBytes = BUFFER_PERIOD_SIZE;
#else
    uint32_t bufferSize = AUDIO_BUFF_SIZE;
    uint64_t requestBytes = AUDIO_BUFF_SIZE;
#endif
    uint64_t totalSize = 0;
    uint32_t failCount = 0;

    struct IAudioCapture *capture = param->capture;
    if (capture == NULL || capture->CaptureFrame == NULL) {
        return HDF_FAILURE;
    }

    char *frame = (char *)OsalMemCalloc(bufferSize);
    if (frame == NULL) {
        return HDF_FAILURE;
    }

    do {
        int32_t ret = capture->CaptureFrame(capture, (int8_t *)frame, &bufferSize, &requestBytes);
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
        if (WriteDataToFile(param->file, frame, bufferSize, &failCount, &totalSize) < 0) {
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

static void PrintPlayMode(void)
{
    printf(" ============= Play Capture start Mode ==========\n");
    printf("| 1. Capture non-mmap                           |\n");
    printf("| 2. Capture mmap                               |\n");
    printf(" ================================================\n");
}

static int32_t SelectRecordMode(int32_t *recordModeFlag)
{
    if (recordModeFlag == NULL) {
        AUDIO_FUNC_LOGE("recordModeFlag is null");
        return HDF_FAILURE;
    }
    int choice = 0;

    system("clear");

    PrintPlayMode();

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

static int32_t StartPlayThread(int32_t recordModeFlag)
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

static int32_t CaptureChoiceModeAndRecording(
    struct StrParaCapture *strParam, struct IAudioCapture *capture, int32_t recordModeFlag)
{
    if (strParam == NULL || capture == NULL) {
        AUDIO_FUNC_LOGE("InitCaptureStrParam is NULL");
        return HDF_FAILURE;
    }

    (void)memset_s(strParam, sizeof(struct StrParaCapture), 0, sizeof(struct StrParaCapture));

    strParam->capture = capture;
    strParam->file = g_file;
    strParam->attrs = g_attrs;
    strParam->frame = g_frame;

    if (g_captureModeFlag == CAPTURE_INTERUPT) {
        printf("not suport liteos!");
    } else {
        if (StartPlayThread(recordModeFlag) < 0) {
            AUDIO_FUNC_LOGE("Create Thread Fail");
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

static int32_t RecordingAudioInitFile(void)
{
    if (g_file != NULL) {
        AUDIO_FUNC_LOGE("the capture is recording, please stop first");
        return HDF_FAILURE;
    }
    g_closeEnd = false;

    g_file = fopen(g_path, "wb+");
    if (g_file == NULL) {
        printf("capture failed to open '%s'\n", g_path);
        return HDF_FAILURE;
    }

    int32_t ret = fseek(g_file, WAV_HEAD_OFFSET, SEEK_SET);
    if (ret != 0) {
        printf("capture write wav file head error");
        return HDF_FAILURE;
    }

    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(g_path, pathBuf) == NULL) {
        AUDIO_FUNC_LOGE("realpath failed.");
        return HDF_FAILURE;
    }

    (void)memcpy_s(g_path, PATH_MAX, pathBuf, PATH_MAX);

    (void)chmod(g_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    return HDF_SUCCESS;
}

#ifndef AUDIO_FEATURE_COMMUNITY
static int32_t UpdateAudioRoute()
{
    struct AudioRouteNode source = {
        .ext.device.type = PIN_IN_MIC,
        .ext.device.desc = (char *)"pin_in_mic",
        .ext.device.moduleId = 0,
        .portId = 0,
        .role = AUDIO_PORT_SOURCE_ROLE,
        .type = AUDIO_PORT_DEVICE_TYPE,
    };

    struct AudioRouteNode sink = {
        .portId = 0,
        .role = AUDIO_PORT_SINK_ROLE,
        .type = AUDIO_PORT_MIX_TYPE,
        .ext.mix.moduleId = 0,
        .ext.mix.streamId = AUDIO_CAPTURE_STREAM_ID,
        .ext.device.desc = (char *)"",
    };

    struct AudioRoute route = {
        .sources = &source,
        .sourcesLen = AUDIO_ROUTE_NODE_LEN,
        .sinks = &sink,
        .sinksLen = AUDIO_ROUTE_NODE_LEN,
    };

    int routeHandle = 0;
    int32_t ret = g_adapter->UpdateAudioRoute(g_adapter, &route, &routeHandle);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("UpdateAudioRoute failed");
    }
    return ret;
}
#endif

static int32_t RecordingAudioInitCapture(struct IAudioCapture **captureTemp)
{
    if (captureTemp == NULL) {
        AUDIO_FUNC_LOGE("captureTemp is null");
        return HDF_FAILURE;
    }

    struct IAudioCapture *capture = NULL;
    int32_t ret = g_adapter->CreateCapture(g_adapter, &g_devDesc, &g_attrs, &capture, &g_captureId);
    if (capture == NULL || ret < 0) {
        return HDF_FAILURE;
    }
#ifndef AUDIO_FEATURE_COMMUNITY
    if (UpdateAudioRoute() < 0) {
        return HDF_FAILURE;
    }
#endif

    ret = capture->Start((void *)capture);
    if (ret < 0) {
        g_adapter->DestroyCapture(g_adapter, g_captureId);
        IAudioCaptureRelease(capture, g_isDirect);
        return HDF_FAILURE;
    }

    uint32_t bufferSize = PcmFramesToBytes(g_attrs);
    g_frame = (char *)OsalMemCalloc(bufferSize);
    if (g_frame == NULL) {
        g_adapter->DestroyCapture(g_adapter, g_captureId);
        IAudioCaptureRelease(capture, g_isDirect);
        return HDF_FAILURE;
    }
    *captureTemp = capture;
    return HDF_SUCCESS;
}

static int32_t StartButtonCapture(struct IAudioCapture **captureS)
{
    if (captureS == NULL || g_adapter == NULL || g_adapter->CreateCapture == NULL) {
        return HDF_FAILURE;
    }

    if (RecordingAudioInitFile() < 0) {
        AUDIO_FUNC_LOGE("RecordingAudioInitFile Fail");
        return HDF_FAILURE;
    }

    int32_t recordModeFlag = 0;
    if (SelectRecordMode(&recordModeFlag) < 0) {
        AUDIO_FUNC_LOGE("SelectRecordMode Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }

    struct IAudioCapture *capture = NULL;
    if (RecordingAudioInitCapture(&capture) < 0) {
        AUDIO_FUNC_LOGE("PlayingAudioInitCapture Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }

    if (CaptureChoiceModeAndRecording(&g_str, capture, recordModeFlag) < 0) {
        AUDIO_FUNC_LOGE("CaptureChoiceModeAndRecording failed");
        FileClose(&g_file);
        if (g_adapter != NULL && g_adapter->DestroyCapture != NULL) {
            g_adapter->DestroyCapture(g_adapter, g_captureId);
        }
        IAudioCaptureRelease(capture, g_isDirect);
        return HDF_FAILURE;
    }
    *captureS = capture;
    printf("Start Successful\n");
    return HDF_SUCCESS;
}

static int32_t SelectLoadingMode(void)
{
    system("clear");
    int choice = 0;

    PrintLoadModeMenu();
    printf("Please enter your choice: ");

    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    switch (choice) {
        case 1: // 1. Capture Passthrough Loading
            g_isDirect = true;
            break;
        case 2: // 2. Capture IPC Loading
            g_isDirect = false;
            break;
        default:
            printf("Input error, Switched to direct loading in for you.\n");
            SystemInputFail();
            g_isDirect = true;
            break;
    }
    return HDF_SUCCESS;
}

static int32_t SelectAudioInputType(void)
{
    system("clear");
    int choice = 0;
    g_voiceCallType = 0;

    PrintAudioInputTypeMenu();
    printf("Please enter your choice: ");

    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        return HDF_FAILURE;
    }

    if ((choice >= 0) && (choice <= 7)) { // 7. the max value of audio input type
        g_voiceCallType = 1 << choice;
    }

    return HDF_SUCCESS;
}

void AudioAdapterDescriptorFree(struct AudioAdapterDescriptor *captureDataBlock, bool freeSelf)
{
    if (captureDataBlock == NULL) {
        return;
    }

    if (captureDataBlock->adapterName != NULL) {
        OsalMemFree(captureDataBlock->adapterName);
        captureDataBlock->adapterName = NULL;
    }

    if (captureDataBlock->ports != NULL) {
        OsalMemFree(captureDataBlock->ports);
    }

    if (freeSelf) {
        OsalMemFree(captureDataBlock);
    }
}

static void ReleaseAdapterDescs(struct AudioAdapterDescriptor **descs, uint32_t descsLen)
{
    if (descsLen > 0 && descs != NULL && (*descs) != NULL) {
        for (uint32_t i = 0; i < descsLen; i++) {
            AudioAdapterDescriptorFree(&(*descs)[i], false);
        }
        OsalMemFree(*descs);
        *descs = NULL;
    }
}

static int32_t GetManagerAndLoadAdapter(struct AudioPort *capturePort)
{
    int32_t adapterIndex = 0;
    uint32_t adapterNum = MAX_AUDIO_ADAPTER_DESC;

    if (capturePort == NULL) {
        AUDIO_FUNC_LOGE("The Parameter is NULL");
        return HDF_FAILURE;
    }

    struct IAudioManager *audioManager = IAudioManagerGet(g_isDirect);
    if (audioManager == NULL) {
        AUDIO_FUNC_LOGE("Get audio Manager Fail");
        return HDF_FAILURE;
    }

    g_audioManager = audioManager;
    struct AudioAdapterDescriptor *captureDescs = (struct AudioAdapterDescriptor *)OsalMemCalloc(
        sizeof(struct AudioAdapterDescriptor) * (MAX_AUDIO_ADAPTER_DESC));
    if (captureDescs == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret = audioManager->GetAllAdapters(audioManager, captureDescs, &adapterNum);
    if (ret < 0 || adapterNum == 0) {
        AUDIO_FUNC_LOGE("Get All Adapters Fail");
        ReleaseAdapterDescs(&captureDescs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (SelectAudioCard(captureDescs, adapterNum, &adapterIndex) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&captureDescs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (strcpy_s(g_adapterName, PATH_LEN, captureDescs[adapterIndex - 1].adapterName) < 0) {
        ReleaseAdapterDescs(&captureDescs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (SwitchAudioPort(&captureDescs[adapterIndex - 1], PORT_IN, capturePort) != HDF_SUCCESS) {
        ReleaseAdapterDescs(&captureDescs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }
    if (audioManager->LoadAdapter(audioManager, &captureDescs[adapterIndex - 1], &g_adapter) != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Load Adapter Fail");
        ReleaseAdapterDescs(&captureDescs, MAX_AUDIO_ADAPTER_DESC);
        return HDF_ERR_NOT_SUPPORT;
    }

    ReleaseAdapterDescs(&captureDescs, MAX_AUDIO_ADAPTER_DESC);

    return HDF_SUCCESS;
}

static int32_t InitCaptureParam(uint32_t portId)
{
    if (g_adapter == NULL || g_adapter->InitAllPorts == NULL) {
        AUDIO_FUNC_LOGE("g_adapter is NULL.");
        return HDF_FAILURE;
    }

    // Initialization port information, can fill through mode and other parameters
    (void)g_adapter->InitAllPorts(g_adapter);

    // User needs to set
    if (InitAttrsCapture(&g_attrs) < 0) {
        AUDIO_FUNC_LOGE("InitDevDescCapture failed.");
        return HDF_FAILURE;
    }

    // Specify a hardware device
    if (InitDevDescCapture(&g_devDesc, portId) < 0) {
        AUDIO_FUNC_LOGE("InitDevDescCapture failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t CaptureGetAdapterAndInitEnvParams(void)
{
    struct AudioPort capturePort;

    int32_t ret = GetManagerAndLoadAdapter(&capturePort);
    if (ret < 0) {
        return ret;
    }

    if (InitCaptureParam(capturePort.portId) < 0) {
        g_audioManager->UnloadAdapter(g_audioManager, g_adapterName);
        IAudioAdapterRelease(g_adapter, g_isDirect);
        g_adapter = NULL;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t InitParam(void)
{
    if (SelectLoadingMode() < 0) {
        AUDIO_FUNC_LOGE("SelectLoadingMode failed!");
        return HDF_FAILURE;
    }

    if (SelectAudioInputType() < 0) {
        AUDIO_FUNC_LOGE("SelectAudioInputType failed!");
        return HDF_FAILURE;
    }

    if (CaptureGetAdapterAndInitEnvParams() < 0) {
        AUDIO_FUNC_LOGE("GetCaptureProxyManagerFunc Fail");
        if (g_audioManager != NULL) {
            IAudioManagerRelease(g_audioManager, g_isDirect);
            g_audioManager = NULL;
        }
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SetCaptureMute(struct IAudioCapture **capture)
{
    (void)capture;
    int32_t val = 0;
    bool isMute = false;
    if (g_capture == NULL || g_capture->GetMute == NULL) {
        return HDF_FAILURE;
    }

    int32_t ret = g_capture->GetMute((void *)g_capture, &isMute);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The current mute state was not obtained!");
    }

    printf("Now %s ,Do you need to set mute status(1/0):\n", isMute ? "mute" : "not mute");

    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CheckInputName failed!");
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

static int32_t SetCaptureVolume(struct IAudioCapture **capture)
{
    (void)capture;
    float val = 0.5;
    if (g_capture == NULL || g_capture->GetVolume == NULL) {
        return HDF_FAILURE;
    }

    int32_t ret = g_capture->GetVolume((void *)g_capture, &val);
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

    if (g_capture == NULL || g_capture->SetVolume == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }

    ret = g_capture->SetVolume((void *)g_capture, val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("set volume fail,");
        SystemInputFail();
    }
    return ret;
}

static int32_t SetCaptureGain(struct IAudioCapture **capture)
{
    (void)capture;
    float val = 1.0;

    if (g_capture == NULL || g_capture->GetGain == NULL) {
        return HDF_FAILURE;
    }

    int32_t ret = g_capture->GetGain((void *)g_capture, &val);
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

    if (g_capture == NULL || g_capture->SetGain == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }

    ret = g_capture->SetGain((void *)g_capture, val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set capture gain failed,");
        SystemInputFail();
    }
    return ret;
}

static int32_t SetCaptyrePause(struct IAudioCapture **capture)
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

static int32_t SetCaptureResume(struct IAudioCapture **capture)
{
    (void)capture;

    if (g_capture == NULL || g_capture->Resume == NULL) {
        return HDF_FAILURE;
    }

    if (g_capture->Resume((void *)g_capture) != 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static void PrintAttributesFromat(void)
{
    printf(" ============= Capture Sample Attributes Fromat =============== \n");
    printf("| 1. Capture AUDIO_FORMAT_TYPE_PCM_8_BIT                            |\n");
    printf("| 2. Capture AUDIO_FORMAT_TYPE_PCM_16_BIT                           |\n");
    printf("| 3. Capture AUDIO_FORMAT_TYPE_PCM_24_BIT                           |\n");
    printf("| 4. Capture AUDIO_FORMAT_TYPE_PCM_32_BIT                           |\n");
    printf(" ============================================================== \n");
}

static int32_t SelectAttributesFomat(uint32_t *fomat)
{
    if (fomat == NULL) {
        return HDF_FAILURE;
    }

    int val = 0;

    PrintAttributesFromat();

    printf("Please select audio format,If not selected, the default is 16bit:");

    if (CheckInputName(INPUT_INT, (void *)&val) < 0) {
        return HDF_FAILURE;
    }
    switch (val) {
        case AUDIO_FORMAT_TYPE_PCM_8_BIT:
            *fomat = AUDIO_FORMAT_TYPE_PCM_8_BIT;
            break;
        case AUDIO_FORMAT_TYPE_PCM_16_BIT:
            *fomat = AUDIO_FORMAT_TYPE_PCM_16_BIT;
            break;
        case AUDIO_FORMAT_TYPE_PCM_24_BIT:
            *fomat = AUDIO_FORMAT_TYPE_PCM_24_BIT;
            break;
        case AUDIO_FORMAT_TYPE_PCM_32_BIT:
            *fomat = AUDIO_FORMAT_TYPE_PCM_32_BIT;
            break;
        default:
            *fomat = AUDIO_FORMAT_TYPE_PCM_16_BIT;
            break;
    }
    return HDF_SUCCESS;
}

static int32_t SetCaptureAttributes(struct IAudioCapture **capture)
{
    (void)capture;

    struct AudioSampleAttributes captureAttrs;

    if (g_capture == NULL || g_capture->GetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("pointer is NULL");
        return HDF_FAILURE;
    }

    int32_t ret = g_capture->GetSampleAttributes((void *)g_capture, &captureAttrs);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetCaptureAttributes failed\n");
    } else {
        printf("Current sample attributes:\n");
        printf("audioType is %u\nfomat is %u\nsampleRate is %u\nchannalCount is"
               "%u\nperiod is %u\nframesize is %u\nbigEndian is %u\nSignedData is %u\n",
            captureAttrs.type, captureAttrs.format, captureAttrs.sampleRate, captureAttrs.channelCount,
            captureAttrs.period, captureAttrs.frameSize, captureAttrs.isBigEndian, captureAttrs.isSignedData);
    }

    printf("Set Sample Attributes,");

    SystemInputFail();

    system("clear");

    printf("The sample attributes you want to set,Step by step, please.\n");

    ret = SelectAttributesFomat((uint32_t *)(&captureAttrs.format));
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetCaptureAttributes format failed");
        return HDF_FAILURE;
    }

    printf("\nPlease input sample rate(48000,44100,32000...):");

    ret = CheckInputName(INPUT_UINT32, (void *)(&captureAttrs.sampleRate));
    if (ret < 0) {
        return HDF_FAILURE;
    }

    printf("\nPlease input bigEndian(false=0/true=1):");

    ret = CheckInputName(INPUT_UINT32, (void *)(&captureAttrs.isBigEndian));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (g_capture == NULL || g_capture->SetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("Record already complete,Please record againand set the attrbutes,");
        SystemInputFail();
        return HDF_FAILURE;
    }

    ret = g_capture->SetSampleAttributes((void *)g_capture, &captureAttrs);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set capture attributes failed,");
        SystemInputFail();
    }
    return ret;
}

static int32_t PrintCaptureSelectPin(struct AudioSceneDescriptor *scene)
{
    system("clear");
    printf(" ==================== Select Pin =====================  \n");
    printf("| 0. MIC                                                |\n");
    printf("| 1. MIC HeadSet                                        |\n");
    printf(" =====================================================  \n");

    printf("Please input your choice:\n");
    int32_t val = 0;
    int32_t ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Invalid value!");
        SystemInputFail();
        return HDF_FAILURE;
    }

    if (val == 1) {
        scene->desc.pins = PIN_IN_HS_MIC;
    } else {
        scene->desc.pins = PIN_IN_MIC;
    }

    return HDF_SUCCESS;
}

static void SelectSceneMenu(void)
{
    printf(" ====================  Select Scene ==================== \n");
    printf("0 is Midea.                                             |\n");
    printf("1 is Communication.                                     |\n");
    printf("2 is Voice-all.                                         |\n");
    printf(" ======================================================= \n");
}

static int32_t SelectCaptureScene(struct IAudioCapture **capture)
{
    (void)capture;
    int32_t val = 0;
    struct AudioSceneDescriptor captureScene;
    system("clear");
    SelectSceneMenu();
    printf("Please input your choice:\n");

    int32_t ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Invalid value,");
        SystemInputFail();
        return HDF_FAILURE;
    }

    switch (val) {
        case AUDIO_IN_MEDIA:
            captureScene.scene.id = AUDIO_IN_MEDIA;
            break;
        case AUDIO_IN_COMMUNICATION:
            captureScene.scene.id = AUDIO_IN_COMMUNICATION;
            break;
        case AUDIO_IN_CALL - 1:
            captureScene.scene.id = AUDIO_IN_CALL;
            break;
        default:
            AUDIO_FUNC_LOGE("Select Scene invaild.");
            return HDF_FAILURE;
    }
    ret = PrintCaptureSelectPin(&captureScene);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("Select pin failed");
        return HDF_FAILURE;
    }

    captureScene.desc.desc = "mic";

    if (g_capture == NULL || g_capture->SelectScene == NULL) {
        AUDIO_FUNC_LOGE("Record already stop,");
        SystemInputFail();
        return HDF_FAILURE;
    }

    ret = g_capture->SelectScene((void *)g_capture, &captureScene);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Select scene fail");
    }
    return ret;
}

static int32_t GetCaptureExtParams(struct IAudioCapture **capture)
{
    (void)capture;
    char keyValueList[BUFFER_LEN] = {0};

    if (g_capture == NULL || g_capture->GetExtraParams == NULL) {
        return HDF_FAILURE;
    }

    int32_t ret = g_capture->GetExtraParams((void *)g_capture, keyValueList, EXT_PARAMS_MAXLEN);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get EXT params failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("keyValueList = %s\n", keyValueList);
    return HDF_SUCCESS;
}

static int32_t GetCaptureMmapPosition(struct IAudioCapture **capture)
{
    (void)capture;

    if (g_capture == NULL || g_capture->GetMmapPosition == NULL) {
        return HDF_FAILURE;
    }

    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;

    int32_t ret = g_capture->GetMmapPosition((void *)g_capture, &frames, &time);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get current Mmap frames Position failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("Now the Position is %" PRIu64 "\n", frames);
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
    {CAPTURE_START,            StartButtonCapture    },
    {CAPTURE_STOP,             StopButtonCapture     },
    {CAPTURE_RESUME,           SetCaptureResume      },
    {CAPTURE_PAUSE,            SetCaptyrePause       },
    {SET_CAPTURE_VOLUME,       SetCaptureVolume      },
    {SET_CAPTURE_GAIN,         SetCaptureGain        },
    {SET_CAPTURE_MUTE,         SetCaptureMute        },
    {SET_CAPTURE_ATTRIBUTES,   SetCaptureAttributes  },
    {SET_CAPTURE_SLECET_SCENE, SelectCaptureScene    },
    {GET_CAPTURE_EXT_PARAMS,   GetCaptureExtParams   },
    {GET_CAPTURE_POSITION,     GetCaptureMmapPosition},
};

static void ProcessMenu(int32_t choice)
{
    if (choice == GET_CAPTURE_POSITION + 1) {
        return;
    }

    if (g_capture == NULL && choice != 1) {
        AUDIO_FUNC_LOGE("this capture already release,");
        SystemInputFail();
        return;
    }

    for (int32_t i = CAPTURE_START; i <= GET_CAPTURE_POSITION; ++i) {
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
    int choice = 0;

    system("clear");

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

    if (argv[1] == NULL || strlen(argv[1]) == 0) {
        return HDF_FAILURE;
    }

    int32_t ret = strncpy_s(g_path, PATH_LEN - 1, argv[1], strlen(argv[1]) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("copy fail");
        return HDF_FAILURE;
    }

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

    if (g_audioManager != NULL && g_audioManager->UnloadAdapter != NULL) {
        g_audioManager->UnloadAdapter(g_audioManager, g_adapterName);
        IAudioAdapterRelease(g_adapter, g_isDirect);
        g_adapter = NULL;
        IAudioManagerRelease(g_audioManager, g_isDirect);
        g_audioManager = NULL;
    }
    printf("Record file path:%s\n", g_path);
    return 0;
}
