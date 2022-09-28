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
#include "hdf_base.h"
#include "inttypes.h"
#include "audio_manager.h"
#include "framework_common.h"

#define BUFFER_LEN 256
#define ID_RIFF 0x46464952
#define ID_WAVE 0x45564157
#define ID_FMT  0x20746d66
#define ID_DATA 0x61746164
#define AUDIO_SAMPLE_RATE_8K 8000
#define AUDIO_CHANNELCOUNT 2
#define AUDIO_SAMPLE_RATE_48K 48000
#define PATH_LEN 256
#define DEEP_BUFFER_RENDER_PERIOD_SIZE 1024
#define DEEP_BUFFER_RENDER_PERIOD_COUNT 8
#define INT_32_MAX 0x7fffffff
#define PERIOD_SIZE 1024
#define ATTR_PERIOD_MIN 2048
#define EXT_PARAMS_MAXLEN 107
#define BITS_TO_FROMAT 3

enum RenderSoundCardMode {
    PRIMARY = 1,
    PRIMARY_EXT = 2,
    AUDIO_USB = 3,
    AUDIO_A2DP = 4,
};

struct StrPara {
    struct AudioRender *render;
    FILE *file;
    struct AudioSampleAttributes attrs;
    uint64_t *replyBytes;
    char *frame;
    int32_t bufferSize;
};

struct AudioRender *g_render = NULL;
struct AudioAdapter *g_adapter = NULL;
struct AudioManager *g_manager = NULL;
struct AudioDeviceDescriptor g_devDesc;
struct AudioSampleAttributes g_attrs;
struct AudioPort g_audioPort;
struct AudioHeadInfo g_wavHeadInfo;
static struct StrPara g_str;
static int32_t g_audioRouteHandle;

pthread_t g_tids;
char *g_frame = NULL;
void *g_handle;
FILE *g_file;

char g_path[256];
static int32_t g_closeEnd = 0;
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_functionCond = PTHREAD_COND_INITIALIZER;
bool g_waitSleep = false;
enum RenderMenuId {
    RENDER_START = 1,
    RENDER_STOP,
    RENDER_RESUME,
    RENDER_PAUSE,
    SET_RENDER_VOLUME,
    SET_RENDER_GAIN,
    SET_RENDER_MUTE,
    SET_RENDER_ATTRIBUTES,
    SET_RENDER_SLECET_SCENE,
    GET_RENDER_EXT_PARAMS,
    GET_RENDER_POSITION,
};

enum RenderInputType {
    INPUT_INT = 0,
    INPUT_FLOAT,
    INPUT_UINT32,
};

typedef int32_t (*AudioRenderOperation)(struct AudioRender **);

struct ProcessRenderMenuSwitchList {
    enum RenderMenuId cmd;
    AudioRenderOperation operation;
};

static int32_t CheckInputName(int type, void *val)
{
    int ret;
    int renderInputInt = 0;
    float renderInputFloat = 0.0;
    uint32_t renderInputUint = 0;
    if (val == NULL) {
        return HDF_FAILURE;
    }
    printf("\n");
    switch (type) {
        case INPUT_INT:
            ret = scanf_s("%d", &renderInputInt);
            if (renderInputInt < 0 || renderInputInt > GET_RENDER_POSITION + 1) {
                AUDIO_FUNC_LOGE("Input failure");
                return HDF_FAILURE;
            }
            *(int *)val = renderInputInt;
            break;
        case INPUT_FLOAT:
            ret = scanf_s("%f", &renderInputFloat);
            *(float *)val = renderInputFloat;
            break;
        case INPUT_UINT32:
            ret = scanf_s("%u", &renderInputUint);
            if (renderInputUint > 0xFFFFFFFF) {
                return HDF_FAILURE;
            }
            *(uint32_t *)val = renderInputUint;
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

static int32_t InitAttrs(struct AudioSampleAttributes *renderAttrs)
{
    if (renderAttrs == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    renderAttrs->format = AUDIO_FORMAT_PCM_16_BIT;
    renderAttrs->channelCount = AUDIO_CHANNELCOUNT;
    renderAttrs->sampleRate = AUDIO_SAMPLE_RATE_48K;
    renderAttrs->interleaved = 1;
    renderAttrs->type = AUDIO_IN_MEDIA;
    renderAttrs->period = ATTR_PERIOD_MIN;
    renderAttrs->frameSize = PCM_16_BIT * renderAttrs->channelCount / PCM_8_BIT;
    renderAttrs->isBigEndian = false;
    renderAttrs->isSignedData = true;
    renderAttrs->startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (renderAttrs->frameSize);
    renderAttrs->stopThreshold = INT_32_MAX;
    renderAttrs->silenceThreshold = 0;
    renderAttrs->streamId = 0;
    return HDF_SUCCESS;
}

static int32_t InitDevDesc(struct AudioDeviceDescriptor *devDesc, uint32_t portId)
{
    if (devDesc == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    devDesc->portId = portId;
    devDesc->pins = PIN_OUT_SPEAKER;
    devDesc->desc = NULL;
    return HDF_SUCCESS;
}

static int32_t WavHeadAnalysis(FILE *file, struct AudioSampleAttributes *attrs)
{
    if (file == NULL || attrs == NULL) {
        printf("params is null\n");
        return HDF_FAILURE;
    }
    size_t ret;
    const char *audioRiffIdParam = "RIFF";
    const char *audioFileFmtParam = "WAVE";
    const char *aduioDataIdParam = "data";
    ret = fread(&g_wavHeadInfo, sizeof(g_wavHeadInfo), 1, file);
    if (ret != 1) {
        return HDF_FAILURE;
    }
    uint32_t audioRiffId = StringToInt(audioRiffIdParam);
    uint32_t audioFileFmt = StringToInt(audioFileFmtParam);
    uint32_t aduioDataId = StringToInt(aduioDataIdParam);
    if (g_wavHeadInfo.riffId != audioRiffId || g_wavHeadInfo.waveType != audioFileFmt ||
        g_wavHeadInfo.dataId != aduioDataId) {
        printf("audio format error \n");
        return HDF_FAILURE;
        }
    attrs->channelCount = g_wavHeadInfo.audioChannelNum;
    attrs->sampleRate = g_wavHeadInfo.audioSampleRate;
    switch (g_wavHeadInfo.audioBitsPerSample) {
        case PCM_8_BIT: {
            attrs->format = AUDIO_FORMAT_PCM_8_BIT;
            break;
        }
        case PCM_16_BIT: {
            attrs->format = AUDIO_FORMAT_PCM_16_BIT;
            break;
        }
        case PCM_24_BIT: {
            attrs->format = AUDIO_FORMAT_PCM_24_BIT;
            break;
        }
        case PCM_32_BIT: {
            attrs->format = AUDIO_FORMAT_PCM_32_BIT;
            break;
        }
        default:
            printf("nonsupport audio format %d\n", g_wavHeadInfo.audioBitsPerSample);
            return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SwitchAdapter(struct AudioAdapterDescriptor *descs,
    const char *adapterNameCase, enum AudioPortDirection portFlag,
    struct AudioPort *renderPort, int32_t size)
{
    struct AudioAdapterDescriptor *desc = NULL;
    if (descs == NULL || adapterNameCase == NULL || renderPort == NULL) {
        return HDF_FAILURE;
    }
    uint32_t port;
    for (int32_t index = 0; index < size; index++) {
        desc = &descs[index];
        if (desc == NULL) {
            continue;
        }
        if (desc->adapterName == NULL) {
            return HDF_FAILURE;
        }
        if (strcmp(desc->adapterName, adapterNameCase)) {
            continue;
        }
        for (port = 0; port < desc->portNum; port++) {
            // Only find out the port of out in the sound card
            if (desc->ports[port].dir == portFlag) {
                *renderPort = desc->ports[port];
                return index;
            }
        }
    }
    return HDF_ERR_NOT_SUPPORT;
}

static uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs)
{
    return DEEP_BUFFER_RENDER_PERIOD_SIZE * attrs.channelCount * (PcmFormatToBits(attrs.format) >> BITS_TO_FROMAT);
}

static int32_t StopAudioFiles(struct AudioRender **renderS)
{
    if (renderS == NULL) {
        return HDF_FAILURE;
    }
    if (g_waitSleep) {
        pthread_mutex_lock(&g_mutex);
        g_waitSleep = false;
        pthread_cond_signal(&g_functionCond);
        pthread_mutex_unlock(&g_mutex);
    }
    if (!g_closeEnd) {
        g_closeEnd = true;
        usleep(100000); // sleep 100000us
    }
    struct AudioRender *render = *renderS;
    if (render == NULL) {
        AUDIO_FUNC_LOGE("render is null");
        return HDF_FAILURE;
    }
    int32_t ret = render->control.Stop((AudioHandle)render);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Stop Render!");
    }
    if (g_adapter == NULL || g_adapter->DestroyRender == NULL) {
        return HDF_FAILURE;
    }
    ret = g_adapter->DestroyRender(g_adapter, render);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Destroy Render!");
    }
    render = NULL;
    g_render = NULL;
    if (g_frame != NULL) {
        free(g_frame);
        g_frame = NULL;
    }
    FileClose(&g_file);
    printf("Stop Successful\n");
    return ret;
}

static bool PrepareStopAndUnloadAdapter(void)
{
    bool soMode = false;

    if (g_render != NULL && g_adapter != NULL) {
        StopAudioFiles(&g_render);
    }

    if (g_manager != NULL) {
        soMode = true;
        if (g_manager->UnloadAdapter != NULL) {
            g_manager->UnloadAdapter(g_manager, g_adapter);
        }
    }

    return soMode;
}

static void StopRenderBySig(int32_t sig)
{
    (void)PrepareStopAndUnloadAdapter();
    dlclose(g_handle);
    g_closeEnd = 1;

    (void)signal(sig, SIG_DFL);
    return;
}
static inline void ProcessCommonSig(void)
{
    (void)signal(SIGKILL, StopRenderBySig);
    (void)signal(SIGINT, StopRenderBySig);
    (void)signal(SIGTERM, StopRenderBySig);
    return;
}

static int32_t MmapInitFile(FILE **fp)
{
    if (fp == NULL) {
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(g_path, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    *fp = fopen(pathBuf, "rb+");
    if (*fp == NULL) {
        printf("Open file failed!\n");
        return HDF_FAILURE;
    }
    int32_t ret = fseek(*fp, 0, SEEK_END);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t FrameStartMmap(const AudioHandle param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    struct StrPara *strParam = (struct StrPara *)param;
    struct AudioRender *render = strParam->render;
    struct AudioMmapBufferDescripter desc;
    ProcessCommonSig();
    // get file length
    FILE *fp = NULL;
    if (MmapInitFile(&fp) < 0) {
        if (fp != NULL) {
            (void)fclose(fp);
            return HDF_FAILURE;
        }
    }
    int32_t reqSize = (int32_t)ftell(fp);
    if (reqSize == -1) {
        (void)fclose(fp);
        return HDF_FAILURE;
    }
    // Converts a file pointer to a device descriptor
    int fd = fileno(fp);
    if (fd == -1) {
        printf("fileno failed, fd is %d\n", fd);
        (void)fclose(fp);
        return HDF_FAILURE;
    }
    // Init param
    desc.memoryFd = fd;
    desc.isShareable = 1; // 1:Shareable ,0:Don't share
    desc.transferFrameSize = DEEP_BUFFER_RENDER_PERIOD_SIZE / 4; // One frame size 4 bit
    desc.offset = sizeof(g_wavHeadInfo);
    // start
    if (render == NULL || render->attr.ReqMmapBuffer == NULL) {
        (void)fclose(fp);
        return HDF_FAILURE;
    }
    int32_t ret = render->attr.ReqMmapBuffer(render, reqSize, &desc);
    if (ret < 0 || reqSize <= 0) {
        printf("Request map fail,please check.\n");
        (void)fclose(fp);
        return HDF_FAILURE;
    }
    munmap(desc.memoryAddress, reqSize);
    (void)fclose(fp);
    if (g_render != NULL) {
        ret = StopAudioFiles(&render);
        if (ret < 0) {
            AUDIO_FUNC_LOGE("StopAudioFiles File!");
        }
    }
    return HDF_SUCCESS;
}

static int32_t FrameStart(const AudioHandle param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    struct StrPara *strParam = (struct StrPara *)param;
    struct AudioRender *render = strParam->render;
    char *frame = strParam->frame;
    int32_t bufferSize = strParam->bufferSize;
    int32_t ret;
    size_t readSize;
    int32_t remainingDataSize = (int32_t)g_wavHeadInfo.riffSize;
    size_t numRead;
    ProcessCommonSig();
    uint64_t replyBytes;
    if (g_file == NULL) {
        return HDF_FAILURE;
    }
    if (render == NULL || render->RenderFrame == NULL || frame == NULL) {
        return HDF_FAILURE;
    }
    do {
        readSize = (size_t)((remainingDataSize > bufferSize) ? bufferSize : remainingDataSize);
        numRead = fread(frame, 1, readSize, g_file);
        if (numRead > 0) {
            ret = render->RenderFrame(render, frame, numRead, &replyBytes);
            if (ret == HDF_ERR_INVALID_OBJECT) {
                AUDIO_FUNC_LOGE("Render already stop!");
                break;
            }
            remainingDataSize -= (int32_t)numRead;
        }
        while (g_waitSleep) {
            printf("music pause now.\n");
            pthread_cond_wait(&g_functionCond, &g_mutex);
            printf("music resume now.\n");
        }
    } while (!g_closeEnd && numRead > 0 && remainingDataSize > 0);
    if (!g_closeEnd) {
        printf("\nPlay complete, please select input again\n");
        (void)StopAudioFiles(&render);
    }
    return HDF_SUCCESS;
}

static int32_t InitPlayingAudioParam(struct AudioRender *render)
{
    if (render == NULL) {
        return HDF_FAILURE;
    }
    uint32_t bufferSize = PcmFramesToBytes(g_attrs);
    g_frame = (char *)calloc(1, bufferSize);
    if (g_frame == NULL) {
        return HDF_FAILURE;
    }
    (void)memset_s(&g_str, sizeof(struct StrPara), 0, sizeof(struct StrPara));
    g_str.render = render;
    g_str.bufferSize = (int32_t)bufferSize;
    g_str.frame = g_frame;
    return HDF_SUCCESS;
}

static void PrintPlayMode(void)
{
    printf(" ============= Play Render Mode ==========\n");
    printf("| 1. Render non-mmap                     |\n");
    printf("| 2. Render mmap                         |\n");
    printf(" ======================================== \n");
}

static int32_t SelectPlayMode(int32_t *palyModeFlag)
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

static int32_t StartPlayThread(int32_t palyModeFlag)
{
    pthread_attr_t tidsAttr;
    pthread_attr_init(&tidsAttr);
    pthread_attr_setdetachstate(&tidsAttr, PTHREAD_CREATE_DETACHED);
    switch (palyModeFlag) {
        case 1: // 1. Stander Loading
            if (pthread_create(&g_tids, &tidsAttr, (void *)(&FrameStart), &g_str) != 0) {
                AUDIO_FUNC_LOGE("Create Thread Fail");
                return HDF_FAILURE;
            }
            break;
        case 2: // 2. Low latency Loading
            if (pthread_create(&g_tids, &tidsAttr, (void *)(&FrameStartMmap), &g_str) != 0) {
                AUDIO_FUNC_LOGE("Create Thread Fail");
                return HDF_FAILURE;
            }
            break;
        default:
            printf("Input error,Switched to non-mmap Mode for you,");
            SystemInputFail();
            if (pthread_create(&g_tids, &tidsAttr, (void *)(&FrameStart), &g_str) != 0) {
                AUDIO_FUNC_LOGE("Create Thread Fail");
                return HDF_FAILURE;
            }
            break;
    }
    return HDF_SUCCESS;
}
static int32_t PlayingAudioInitFile(void)
{
    if (g_file != NULL) {
        AUDIO_FUNC_LOGE("the music is playing,please stop first");
        return HDF_FAILURE;
    }
    g_closeEnd = false;
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(g_path, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    g_file = fopen(pathBuf, "rb");
    if (g_file == NULL) {
        printf("failed to open '%s'\n", g_path);
        return HDF_FAILURE;
    }
    if (WavHeadAnalysis(g_file, &g_attrs) < 0) {
        AUDIO_FUNC_LOGE("Frame test is Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
static int32_t BindRouteToRender(int32_t streamid, enum AudioPortPin outputDevice)
{
    struct AudioRouteNode source = {
        .portId = 0,
        .role = AUDIO_PORT_SOURCE_ROLE,
        .type = AUDIO_PORT_MIX_TYPE,
        .ext.mix.moduleId = 0,
        .ext.mix.streamId = streamid,
    };

    struct AudioRouteNode sink = {
        .portId = 0,
        .role = AUDIO_PORT_SINK_ROLE,
        .type = AUDIO_PORT_DEVICE_TYPE,
        .ext.device.moduleId = 0,
        .ext.device.type = outputDevice,
        .ext.device.desc = "pin_out_speaker",
    };

    struct AudioRoute route = {
        .sourcesNum = 1,
        .sources = &source,
        .sinksNum = 1,
        .sinks = &sink,
    };

    return g_adapter->UpdateAudioRoute(g_adapter, &route, &g_audioRouteHandle);
}
static int32_t PlayingAudioFiles(struct AudioRender **renderS)
{
    if (renderS == NULL || g_adapter == NULL || g_adapter->CreateRender == NULL) {
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
    struct AudioRender *render = NULL;
    int32_t ret = g_adapter->CreateRender(g_adapter, &g_devDesc, &g_attrs, &render);
    if (render == NULL || ret < 0 || render->RenderFrame == NULL) {
        AUDIO_FUNC_LOGE("AudioDeviceCreateRender failed or RenderFrame is null");
        FileClose(&g_file);
        return HDF_FAILURE;
    }

    (void)BindRouteToRender(g_attrs.streamId, g_devDesc.pins);
    // Playing audio files
    if (render->control.Start((AudioHandle)render)) {
        AUDIO_FUNC_LOGE("Start Bind Fail!");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    if (InitPlayingAudioParam(render) < 0) {
        AUDIO_FUNC_LOGE("InitPlayingAudioParam Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    if (StartPlayThread(palyModeFlag) < 0) {
        AUDIO_FUNC_LOGE("Create Thread Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    *renderS = render;
    printf("Start Successful,Music is playing\n");
    return HDF_SUCCESS;
}

static void PrintMenu0(void)
{
    printf(" ============= Play Render Sound Card Mode ==========\n");
    printf("| 1. Render Primary                                 |\n");
    printf("| 2. Render Primary_Ext                             |\n");
    printf("| 3. Render Usb                                     |\n");
    printf("| 4. Render A2dp                                    |\n");
    printf(" =================================================== \n");
}

static void PrintMenu1(void)
{
    printf(" ============== Play Render Loading Mode ===========\n");
    printf("| 1. Render Direct Loading                         |\n");
    printf("| 2. Render Service Loading                        |\n");
    printf("| Note: switching is not supported in the MPI's    |\n");
    printf("|       version.                                   |\n");
    printf(" ================================================== \n");
}

static int32_t SwitchInternalOrExternal(char *adapterNameCase, int32_t nameLen)
{
    system("clear");
    int choice = 0;
    PrintMenu0();
    printf("Please enter your choice:");
    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) return HDF_FAILURE;
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

static int32_t SelectLoadingMode(char *renderResolvedPath, int32_t pathLen)
{
    system("clear");
    int choice = 0;
    int32_t ret;
    PrintMenu1();
    printf("Please enter your choice:");
    ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("render CheckInputName failed!");
        return HDF_FAILURE;
    }
    ret = FormatLoadLibPath(renderResolvedPath, pathLen, choice);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("render FormatLoadLibPath failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static struct AudioManager *GetAudioManagerInsForRender(const char *funcString)
{
    struct AudioManager *(*getAudioManager)(void) = NULL;
    if (funcString == NULL) {
        AUDIO_FUNC_LOGE("funcString is null!");
        return NULL;
    }
    if (g_handle == NULL) {
        AUDIO_FUNC_LOGE("g_captureHandle is null!");
        return NULL;
    }
    getAudioManager = (struct AudioManager *(*)())(dlsym(g_handle, funcString));
    if (getAudioManager == NULL) {
        AUDIO_FUNC_LOGE("Get Audio Manager Funcs Fail");
        return NULL;
    }
    return getAudioManager();
}

static int32_t GetRenderManagerFunc(const char *adapterNameCase)
{
    struct AudioAdapterDescriptor *descs = NULL;
    enum AudioPortDirection port = PORT_OUT; // Set port information
    struct AudioPort renderPort;
    int32_t size = 0;
    if (adapterNameCase == NULL) {
        AUDIO_FUNC_LOGE("The Parameter is NULL");
        return HDF_FAILURE;
    }
    struct AudioManager *manager = GetAudioManagerInsForRender("GetAudioManagerFuncs");
    if (manager == NULL) {
        AUDIO_FUNC_LOGE("GetAudioManagerInsForRender Fail");
        return HDF_FAILURE;
    }
    int32_t ret = manager->GetAllAdapters(manager, &descs, &size);
    if ((size == 0) || (descs == NULL) || (ret < 0)) {
        AUDIO_FUNC_LOGE("Get All Adapters Fail");
        return HDF_ERR_NOT_SUPPORT;
    }
    int32_t index = SwitchAdapter(descs, adapterNameCase, port, &renderPort, size);
    if (index < 0) {
        AUDIO_FUNC_LOGE("Not Switch Adapter Invalid");
        return HDF_ERR_NOT_SUPPORT;
    }
    struct AudioAdapterDescriptor *desc = &descs[index];
    if (manager->LoadAdapter(manager, desc, &g_adapter) != 0) {
        AUDIO_FUNC_LOGE("Load Adapter Fail");
        return HDF_ERR_NOT_SUPPORT;
    }
    g_manager = manager;
    if (g_adapter == NULL) {
        AUDIO_FUNC_LOGE("load audio device Invalid");
        return HDF_FAILURE;
    }
    (void)g_adapter->InitAllPorts(g_adapter);
    if (InitAttrs(&g_attrs) < 0) {
        g_manager->UnloadAdapter(g_manager, g_adapter);
        return HDF_FAILURE;
    }
    // Specify a hardware device
    if (InitDevDesc(&g_devDesc, renderPort.portId) < 0) {
        g_manager->UnloadAdapter(g_manager, g_adapter);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t InitParam(void)
{
    /* Internal and external switch,begin */
    char adapterNameCase[PATH_LEN] = {0};
    if (SwitchInternalOrExternal(adapterNameCase, PATH_LEN) < 0) {
        return HDF_FAILURE;
    }
    char resolvedPath[PATH_LEN] = {0}; // Select loading mode,begin
    if (SelectLoadingMode(resolvedPath, PATH_LEN) < 0) {
        return HDF_FAILURE;
    }
    /* Select loading mode,end */
    g_audioPort.dir = PORT_OUT;
    g_audioPort.portId = 0;
    g_audioPort.portName = "AOP";
    g_handle = dlopen(resolvedPath, 1);
    if (g_handle == NULL) {
        AUDIO_FUNC_LOGE("Open so Fail, reason:%s", dlerror());
        return HDF_FAILURE;
    }
    if (GetRenderManagerFunc(adapterNameCase) < 0) {
        AUDIO_FUNC_LOGE("GetManagerFunc Failed.");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SetRenderMute(struct AudioRender **render)
{
    (void)render;
    int32_t val;
    bool isMute = false;
    int32_t ret;
    if (g_render == NULL || g_render->volume.GetMute == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->volume.GetMute((AudioHandle)g_render, &isMute);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("The current mute state was not obtained!");
    }
    printf("Now %s ,Do you need to set mute status(1/0):", isMute ? "mute" : "not mute");
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (isMute != 0 && isMute != 1) {
        AUDIO_FUNC_LOGE("Invalid value!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_render == NULL || g_render->volume.SetMute == NULL) {
        AUDIO_FUNC_LOGE("Music already stop!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (val == 1) {
        ret = g_render->volume.SetMute((AudioHandle)g_render, !isMute);
    }
    return ret;
}

static int32_t SetRenderVolume(struct AudioRender **render)
{
    (void)render;
    int32_t ret;
    float val = 0.0;
    if (g_render == NULL || g_render->volume.GetVolume == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->volume.GetVolume((AudioHandle)g_render, &val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get current volume failed!");
        SystemInputFail();
        return ret;
    }
    printf("Now the volume is %f ,Please enter the volume value you want to set (0.0-1.0):", val);
    ret = CheckInputName(INPUT_FLOAT, (void *)&val);
    if (ret < 0) return HDF_FAILURE;
    if (val < 0.0 || val > 1.0) {
        AUDIO_FUNC_LOGE("Invalid volume value!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_render == NULL || g_render->volume.SetVolume == NULL) {
        AUDIO_FUNC_LOGE("Music already stop!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_render->volume.SetVolume((AudioHandle)g_render, val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("set volume fail!");
        SystemInputFail();
    }
    return ret;
}

static int32_t GetRenderGain(struct AudioRender **render)
{
    (void)render;
    int32_t ret;
    float val = 1.0;
    if (g_render == NULL || g_render->volume.GetGain == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->volume.GetGain((AudioHandle)g_render, &val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get current gain failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("Now the gain is %f,", val);
    SystemInputFail();
    return HDF_SUCCESS;
}

static int32_t SetRenderPause(struct AudioRender **render)
{
    (void)render;
    if (g_waitSleep) {
        AUDIO_FUNC_LOGE("Already pause,not need pause again!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    int32_t ret;
    if (g_render == NULL || g_render->control.Pause == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->control.Pause((AudioHandle)g_render);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    printf("Pause success!\n");
    g_waitSleep = true;
    return HDF_SUCCESS;
}

static int32_t SetRenderResume(struct AudioRender **render)
{
    (void)render;
    if (!g_waitSleep) {
        AUDIO_FUNC_LOGE("Now is Playing,not need resume!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    int32_t ret;
    if (g_render == NULL || g_render->control.Resume == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->control.Resume((AudioHandle)g_render);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    printf("resume success!\n");
    pthread_mutex_lock(&g_mutex);
    g_waitSleep = false;
    pthread_cond_signal(&g_functionCond);
    pthread_mutex_unlock(&g_mutex);
    return HDF_SUCCESS;
}

static void PrintRenderAttributesFromat(void)
{
    printf(" ============= Render Sample Attributes Format =============== \n");
    printf("| 1. Render AUDIO_FORMAT_PCM_8_BIT                            |\n");
    printf("| 2. Render AUDIO_FORMAT_PCM_16_BIT                           |\n");
    printf("| 3. Render AUDIO_FORMAT_PCM_24_BIT                           |\n");
    printf("| 4. Render AUDIO_FORMAT_PCM_32_BIT                           |\n");
    printf(" ============================================================= \n");
}

static int32_t SelectAttributesFomat(uint32_t *renderPcmFomat)
{
    if (renderPcmFomat == NULL) {
        AUDIO_FUNC_LOGE("fomat is null!");
        return HDF_FAILURE;
    }
    PrintRenderAttributesFromat();
    printf("Please select audio format,If not selected, the default is 16bit:");
    int32_t ret;
    int val = 0;
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("CheckInputName failed!");
        return HDF_FAILURE;
    }
    ret = CheckPcmFormat(val, renderPcmFomat);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Render CheckPcmFormat failed!");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t SetRenderAttributes(struct AudioRender **render)
{
    (void)render;
    int32_t ret;
    struct AudioSampleAttributes renderAttrs;
    if (g_render == NULL || g_render->attr.GetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null!");
        return HDF_FAILURE;
    }
    ret = g_render->attr.GetSampleAttributes((AudioHandle)g_render, &renderAttrs);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("GetRenderAttributes failed!");
    } else {
        printf("Current sample attributes:\n");
        printf("audioType is %u\nfomat is %u\nsampleRate is %u\nchannalCount is"
            "%u\nperiod is %u\nframesize is %u\nbigEndian is %u\nSignedData is %u\n",
            renderAttrs.type, renderAttrs.format, renderAttrs.sampleRate,
            renderAttrs.channelCount, renderAttrs.period, renderAttrs.frameSize,
            renderAttrs.isBigEndian, renderAttrs.isSignedData);
    }
    printf("Set Sample Attributes,");
    SystemInputFail();
    system("clear");
    printf("The sample attributes you want to set,Step by step, please.\n");
    ret = SelectAttributesFomat((uint32_t *)(&renderAttrs.format));
    if (ret < 0) {
        AUDIO_FUNC_LOGE("SetRenderAttributes format failed!");
        return HDF_FAILURE;
    }
    printf("\nPlease input sample rate(48000,44100,32000...):");
    ret = CheckInputName(INPUT_UINT32, (void *)(&renderAttrs.sampleRate));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    printf("\nPlease input bigEndian(false=0/true=1):");
    ret = CheckInputName(INPUT_UINT32, (void *)(&renderAttrs.isBigEndian));
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (g_render == NULL || g_render->attr.SetSampleAttributes == NULL) {
        AUDIO_FUNC_LOGE("Music already complete,Please replay and set the attrbutes!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_render->attr.SetSampleAttributes((AudioHandle)g_render, &renderAttrs);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Set render attributes failed!");
        SystemInputFail();
    }
    return ret;
}

static int32_t SelectRenderScene(struct AudioRender **render)
{
    (void)render;
    system("clear");
    int32_t ret;
    int val = 0;
    struct AudioSceneDescriptor scene;
    printf(" =================== Select Scene ===================== \n");
    printf("0 is Speaker.                                          |\n");
    printf("1 is HeadPhones.                                       |\n");
    printf(" ====================================================== \n");
    printf("Please input your choice:\n");
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0 || (val != 0 && val != 1)) {
        AUDIO_FUNC_LOGE("Invalid value!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (val == 1) {
        scene.scene.id = 0;
        scene.desc.pins = PIN_OUT_HEADSET;
    } else {
        scene.scene.id = 0;
        scene.desc.pins = PIN_OUT_SPEAKER;
    }
    if (g_render == NULL) {
        AUDIO_FUNC_LOGE("Music already stop,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_render->scene.SelectScene == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->scene.SelectScene((AudioHandle)g_render, &scene);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Select scene fail\n");
    }
    return ret;
}

static int32_t GetExtParams(struct AudioRender **render)
{
    (void)render;
    char keyValueList[BUFFER_LEN] = {0};
    int32_t ret;
    if (g_render == NULL || g_render->attr.GetExtraParams == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->attr.GetExtraParams((AudioHandle)g_render, keyValueList, EXT_PARAMS_MAXLEN);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get EXT params failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("keyValueList = %s\n", keyValueList);
    return HDF_SUCCESS;
}

static int32_t GetRenderMmapPosition(struct AudioRender **render)
{
    (void)render;
    int32_t ret;
    if (g_render == NULL || g_render->attr.GetMmapPosition == NULL) {
        return HDF_FAILURE;
    }
    uint64_t frames = 0;
    struct AudioTimeStamp time;
    time.tvNSec = 0;
    time.tvSec = 0;
    ret = g_render->attr.GetMmapPosition((AudioHandle)g_render, &frames, &time);
    if (ret < 0) {
        AUDIO_FUNC_LOGE("Get current Mmap frames Position failed!");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("Now the Position is %"PRIu64"\n", frames);
    return HDF_SUCCESS;
}

static void PrintMenu2(void)
{
    printf(" ================== Play Render Menu ================== \n");
    printf("| 1. Render Start                                      |\n");
    printf("| 2. Render Stop                                       |\n");
    printf("| 3. Render Resume                                     |\n");
    printf("| 4. Render Pause                                      |\n");
    printf("| 5. Render SetVolume                                  |\n");
    printf("| 6. Render GetGain                                    |\n");
    printf("| 7. Render SetMute                                    |\n");
    printf("| 8. Render SetAttributes                              |\n");
    printf("| 9. Render SelectScene                                |\n");
    printf("| 10. Render getEXtParams                              |\n");
    printf("| 11. Render getMmapPosition                           |\n");
    printf("| 12.Exit                                              |\n");
    printf(" ====================================================== \n");
}

static struct ProcessRenderMenuSwitchList g_processRenderMenuSwitchList[] = {
    {RENDER_START, PlayingAudioFiles},
    {RENDER_STOP, StopAudioFiles},
    {RENDER_RESUME, SetRenderResume},
    {RENDER_PAUSE, SetRenderPause},
    {SET_RENDER_VOLUME, SetRenderVolume},
    {SET_RENDER_GAIN, GetRenderGain},
    {SET_RENDER_MUTE, SetRenderMute},
    {SET_RENDER_ATTRIBUTES, SetRenderAttributes},
    {SET_RENDER_SLECET_SCENE, SelectRenderScene},
    {GET_RENDER_EXT_PARAMS, GetExtParams},
    {GET_RENDER_POSITION, GetRenderMmapPosition},
};

static void ProcessMenu(int32_t choice)
{
    int32_t i;
    if (choice == GET_RENDER_POSITION + 1) {
        return;
    }
    if (g_render == NULL && choice != 1) {
        AUDIO_FUNC_LOGE("This render already release!");
        SystemInputFail();
        return;
    }
    for (i = RENDER_START; i <= GET_RENDER_POSITION; ++i) {
        if ((choice == (int32_t)g_processRenderMenuSwitchList[i - 1].cmd) &&
            (g_processRenderMenuSwitchList[i - 1].operation != NULL)) {
            g_processRenderMenuSwitchList[i - 1].operation(&g_render);
        }
    }
}

static void Choice(void)
{
    int32_t choice = 0;
    int ret;
    while (choice < GET_RENDER_POSITION + 1 && choice >= 0) {
        system("clear");
        PrintMenu2();
        printf("your choice is:\n");
        ret = CheckInputName(INPUT_INT, (void *)&choice);
        if (ret < 0) {
            continue;
        }
        if (choice < RENDER_START || choice > GET_RENDER_POSITION + 1) {
            AUDIO_FUNC_LOGE("You input is wrong!");
            choice = 0;
            SystemInputFail();
            continue;
        }
        ProcessMenu(choice);
    }
}

int32_t main(int32_t argc, char const *argv[])
{
    int32_t ret = 0;
    if (argc < 2 || argv == NULL || argv[0] == NULL) { // The parameter number is not greater than 2
        printf("usage:[1]sample [2]/data/test.wav\n");
        return 0;
    }
    if (argv[1] == NULL || strlen(argv[1]) == 0) {
        return HDF_FAILURE;
    }
    ret = strncpy_s(g_path, PATH_LEN, argv[1], strlen(argv[1]) + 1);
    if (ret != 0) {
        AUDIO_FUNC_LOGE("strncpy_s failed!");
        return HDF_FAILURE;
    }
    char pathBuf[PATH_MAX] = {'\0'};
    if (realpath(g_path, pathBuf) == NULL) {
        return HDF_FAILURE;
    }
    FILE *file = fopen(pathBuf, "rb");
    if (file == NULL) {
        printf("Failed to open '%s',Please enter the correct file name \n", g_path);
        return HDF_FAILURE;
    }
    (void)fclose(file);
    if (InitParam() != HDF_SUCCESS) { // init
        AUDIO_FUNC_LOGE("InitParam Fail!");
        return HDF_FAILURE;
    }

    Choice();
    (void)PrepareStopAndUnloadAdapter();
    dlclose(g_handle);
    return 0;
}
