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

#include "audio_manager.h"
#include <dlfcn.h>
#include <pthread.h>
#include <securec.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "audio_types.h"
#include "hdf_base.h"

#define LOG_FUN_INFO_TS() do { \
    printf("%s: %s: %d\n", __FILE__, __func__, __LINE__); \
} while (0)

#define LOG_FUN_ERR_TS(info) do { \
        printf("%s: %s: %d:[ERROR]:%s\n", __FILE__, __func__, __LINE__, (info)); \
} while (0)

#define LOG_PARA_INFO_TS(info) do { \
        printf("%s: %s: %d:[INFO]:%s\n", __FILE__, __func__, __LINE__, (info)); \
} while (0)

#define MAX_AUDIO_ADAPTER_NUM_T  3  // Number of sound cards supported
#define BUFFER_LEN 256
#define ID_RIFF 0x46464952
#define ID_WAVE 0x45564157
#define ID_FMT  0x20746d66
#define ID_DATA 0x61746164
#define MOVE_LEFT_NUM 8
#define AUDIO_SAMPLE_RATE_8K 8000
#define AUDIO_CHANNELCOUNT 2
#define AUDIO_SAMPLE_RATE_48K 48000
#define PATH_LEN 256
#define DEEP_BUFFER_RENDER_PERIOD_SIZE 4096
#define DEEP_BUFFER_RENDER_PERIOD_COUNT 8
#define INT_32_MAX 0x7fffffff
#define PERIOD_SIZE 1024

enum AudioPCMBit {
    PCM_8_BIT  = 8,       /**< 8-bit PCM */
    PCM_16_BIT = 16,       /**< 16-bit PCM */
    PCM_24_BIT = 24,       /**< 24-bit PCM */
    PCM_32_BIT = 32,       /**< 32-bit PCM */
};

struct AudioHeadInfo {
    uint32_t testFileRiffId;
    uint32_t testFileRiffSize;
    uint32_t testFileFmt;
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
struct StrPara g_str;

pthread_t g_tids;
char *g_frame = NULL;
void *g_handle;
FILE *g_file;

char g_path[256];
static int32_t g_closeEnd = 0;
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_functionCond = PTHREAD_COND_INITIALIZER;
int g_waitSleep = 0;

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
int32_t CheckInputName(int type, void *val)
{
    int ret;
    int inputInt = 0;
    float inputFloat = 0.0;
    uint32_t inputUint = 0;
    switch (type) {
        case INPUT_INT:
            ret = scanf_s("%d", &inputInt);
            if (inputInt < 0 || inputInt > SET_RENDER_SLECET_SCENE + 1) {
                printf("Input failure\n");
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
        fflush(stdin);
    } else if (ret == EOF) {
        printf("Input failure occurs!\n");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void SystemInputFail()
{
    printf("please ENTER to go on...");
    while (getchar() != '\n') {
        continue;
    }
    printf("%c", getchar());
}

int32_t InitAttrs(struct AudioSampleAttributes *attrs)
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
    attrs->period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs->frameSize = PCM_16_BIT * attrs->channelCount / PCM_8_BIT;
    attrs->isBigEndian = false;
    attrs->isSignedData = true;
    attrs->startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs->frameSize);
    attrs->stopThreshold = INT_32_MAX;
    attrs->silenceThreshold = 0;
    return HDF_SUCCESS;
}

int32_t InitAttrsAgain(struct AudioSampleAttributes *attrs)
{
    if (attrs == NULL) {
        return HDF_FAILURE;
    }
    /* Initialization of audio parameters for playback */
    attrs->format = AUDIO_FORMAT_PCM_8_BIT;
    attrs->channelCount = 1;
    attrs->sampleRate = AUDIO_SAMPLE_RATE_8K;
    attrs->interleaved = 0;
    attrs->type = AUDIO_IN_MEDIA;
    return HDF_SUCCESS;
}

int32_t InitDevDesc(struct AudioDeviceDescriptor *devDesc, uint32_t portId)
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

uint32_t StringToInt(char *flag)
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
int32_t WavHeadAnalysis(FILE *file, struct AudioSampleAttributes *attrs)
{
    if (file == NULL || attrs == NULL) {
        return HDF_FAILURE;
    }
    int32_t ret;
    char *audioRiffIdParam = "RIFF";
    char *audioFileFmtParam = "WAVE";
    char *aduioDataIdParam = "data";
    ret = fread(&g_wavHeadInfo, sizeof(g_wavHeadInfo), 1, file);
    if (ret != 1) {
        return HDF_FAILURE;
    }
    uint32_t audioRiffId = StringToInt(audioRiffIdParam);
    uint32_t audioFileFmt = StringToInt(audioFileFmtParam);
    uint32_t aduioDataId = StringToInt(aduioDataIdParam);
    if (g_wavHeadInfo.testFileRiffId != audioRiffId || g_wavHeadInfo.testFileFmt != audioFileFmt ||
        g_wavHeadInfo.dataId != aduioDataId) {
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
            return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SwitchAdapter(struct AudioAdapterDescriptor *descs,
    const char *adapterNameCase, enum AudioPortDirection portFlag,
    struct AudioPort *renderPort, int32_t size)
{
    if (descs == NULL || adapterNameCase == NULL || renderPort == NULL) {
        return HDF_FAILURE;
    }
    for (int32_t index = 0; index < size; index++) {
        struct AudioAdapterDescriptor *desc = &descs[index];
        if (strcmp(desc->adapterName, adapterNameCase)) {
            continue;
        }
        for (uint32_t port = 0; ((desc != NULL) && (port < desc->portNum)); port++) {
            // Only find out the port of out in the sound card
            if (desc->ports[port].dir == portFlag) {
                *renderPort = desc->ports[port];
                return index;
            }
        }
    }
    return HDF_ERR_NOT_SUPPORT;
}

void StreamClose(int32_t sig)
{
    /* allow the stream to be closed gracefully */
    signal(sig, SIG_IGN);
    g_closeEnd = 1;
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

uint32_t PcmFramesToBytes(const struct AudioSampleAttributes attrs)
{
    return DEEP_BUFFER_RENDER_PERIOD_SIZE * attrs.channelCount * (PcmFormatToBits(attrs.format) >> 3);
}

int32_t StopAudioFiles(struct AudioRender **renderS)
{
    if (renderS == NULL) {
        return HDF_FAILURE;
    }
    if (g_waitSleep) {
        pthread_mutex_lock(&g_mutex);
        g_waitSleep = 0;
        pthread_cond_signal(&g_functionCond);
        pthread_mutex_unlock(&g_mutex);
    }
    if (!g_closeEnd) {
        g_closeEnd = true;
        pthread_join(g_tids, NULL);
    }
    struct AudioRender *render = *renderS;
    if (render == NULL) {
        LOG_PARA_INFO_TS("render is null");
        return HDF_FAILURE;
    }
    int32_t ret = render->control.Stop((AudioHandle)render);
    if (ret < 0) {
        printf("Stop Render!\n");
    }
    if (g_adapter == NULL) {
        return HDF_FAILURE;
    }
    ret = g_adapter->DestroyRender(g_adapter, render);
    if (ret < 0) {
        printf("Destroy Render!\n");
    }
    render = NULL;
    g_render = NULL;
    if (g_frame != NULL) {
        free(g_frame);
        g_frame = NULL;
    }
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    return ret;
}

int32_t FrameStart(void *param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    struct StrPara *strParam = (struct StrPara *)param;
    struct AudioRender *render = strParam->render;
    char *frame = strParam->frame;
    int32_t bufferSize = strParam->bufferSize;
    int32_t ret;
    int32_t readSize;
    int32_t remainingDataSize = g_wavHeadInfo.testFileRiffSize;
    int32_t numRead;
    signal(SIGINT, StreamClose);
    uint64_t replyBytes;
    do {
        readSize = (remainingDataSize > bufferSize) ? bufferSize : remainingDataSize;
        numRead = fread(frame, 1, readSize, g_file);
        if (numRead > 0) {
            ret = render->RenderFrame(render, frame, numRead, &replyBytes);
            if (ret == HDF_ERR_INVALID_OBJECT) {
                printf("Render already stop!\n");
                break;
            }
            remainingDataSize -= numRead;
        }
        while (g_waitSleep) {
            printf("music pause now.\n");
            pthread_cond_wait(&g_functionCond, &g_mutex);
            printf("music resume now.\n");
        }
    } while (!g_closeEnd && numRead > 0 && remainingDataSize > 0);
    if (!g_closeEnd) {
        printf("\nPlay complete, please select input again\n");
        StopAudioFiles(&render);
    }
    return HDF_SUCCESS;
}

void FileClose(FILE **file)
{
    if ((file != NULL) || ((*file) != NULL)) {
        fclose(*file);
        *file = NULL;
    }
    return;
}

int32_t PlayingAudioFiles(struct AudioRender **renderS)
{
    if (renderS == NULL || g_adapter == NULL) {
        return HDF_FAILURE;
    }
    if (g_file != NULL) {
        printf("the music is playing,please stop first\n");
        return HDF_FAILURE;
    }
    g_closeEnd = false;
    struct AudioRender *render;
    g_file = fopen(g_path, "rb");
    if (g_file == NULL) {
        printf("failed to open '%s'\n", g_path);
        return HDF_FAILURE;
    }
    if (WavHeadAnalysis(g_file, &g_attrs) < 0) {
        LOG_FUN_ERR_TS("fream test is Fail");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    int32_t ret = g_adapter->CreateRender(g_adapter, &g_devDesc, &g_attrs, &render);
    if (render == NULL || ret < 0 || render->RenderFrame == NULL) {
        LOG_FUN_ERR_TS("AudioDeviceCreateRender failed or RenderFrame is null");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    // Playing audio files
    if (render->control.Start((AudioHandle)render)) {
        LOG_FUN_ERR_TS("Start Bind Fail!");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    uint32_t bufferSize = PcmFramesToBytes(g_attrs);
    g_frame = (char *)calloc(1, bufferSize);
    if (g_frame == NULL) {
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    memset_s(&g_str, sizeof(struct StrPara), 0, sizeof(struct StrPara));
    g_str.render = render;
    g_str.bufferSize = bufferSize;
    g_str.frame = g_frame;
    if (pthread_create(&g_tids, NULL, (void *)(&FrameStart), &g_str) != 0) {
        LOG_FUN_ERR_TS("Create Thread Fail\n");
        FileClose(&g_file);
        return HDF_FAILURE;
    }
    *renderS = render;
    printf("Start Successful,Music is playing\n");
    return HDF_SUCCESS;
}

void PrintMenu0()
{
    printf(" ============= Play Render Sound Card Mode ==========\n");
    printf("| 1. Render Acodec                                  |\n");
    printf("| 2. Render SmartPA                                 |\n");
    printf(" =================================================== \n");
}

void PrintMenu1()
{
    printf(" ============== Play Render Loading Mode ===========\n");
    printf("| 1. Render Direct Loading                         |\n");
    printf("| 2. Render Service Loading                        |\n");
    printf("| Note: switching is not supported in the MPI's    |\n");
    printf("|       version.                                   |\n");
    printf(" ================================================== \n");
}

int32_t SwitchInternalOrExternal(char *adapterNameCase)
{
    system("clear");
    int choice = 0;
    PrintMenu0();
    printf("Please enter your choice:");
    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) return HDF_FAILURE;
    switch (choice) {
        case 1:
            snprintf_s(adapterNameCase, PATH_LEN, PATH_LEN - 1, "%s", "usb");
            break;
        case 2: // 2. Render SmartPA
            snprintf_s(adapterNameCase, PATH_LEN, PATH_LEN - 1, "%s", "hdmi");
            break;
        default:
            printf("Input error,Switched to Acodec in for you,");
            SystemInputFail();
            snprintf_s(adapterNameCase, PATH_LEN, PATH_LEN - 1, "%s", "usb");
            break;
    }
    return HDF_SUCCESS;
}

int32_t SelectLoadingMode(char *resolvedPath, char *func)
{
    system("clear");
    int choice = 0;
    PrintMenu1();
    printf("Please enter your choice:");
    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    switch (choice) {
        case 1:
            snprintf_s(resolvedPath, PATH_LEN, PATH_LEN - 1, "%s", "/system/lib/libhdi_audio.z.so");
            snprintf_s(func, PATH_LEN, PATH_LEN - 1, "%s", "GetAudioManagerFuncs");
            break;
        case 2: // 2. Render Service Loading
            snprintf_s(resolvedPath, PATH_LEN, PATH_LEN - 1, "%s", "/system/lib/libaudio_hdi_proxy_server.z.so");
            snprintf_s(func, PATH_LEN, PATH_LEN - 1, "%s", "GetAudioProxyManagerFuncs");
            break;
        default:
            printf("Input error,Switched to direct loading in for you,");
            SystemInputFail();
            snprintf_s(resolvedPath, PATH_LEN, PATH_LEN - 1, "%s", "/system/lib/libhdi_audio.z.so");
            snprintf_s(func, PATH_LEN, PATH_LEN - 1, "%s", "GetAudioManagerFuncs");
            break;
    }
    return HDF_SUCCESS;
}

int32_t InitParamSplit(struct AudioAdapterDescriptor *descs, struct AudioManager *manager,
    const char *adapterNameCase, int size)
{
    if (descs == NULL || manager == NULL || adapterNameCase == NULL) {
        return HDF_FAILURE;
    }
    int32_t index;
    struct AudioPort renderPort;
    /* Set sound card information */
    enum AudioPortDirection port = PORT_OUT; // Set port information
    /* Get qualified sound card and port */
    index = SwitchAdapter(descs, adapterNameCase, port, &renderPort, size);
    if (index < 0) {
        LOG_FUN_ERR_TS("Not Switch Adapter Fail");
        return HDF_ERR_NOT_SUPPORT;
    }
    struct AudioAdapterDescriptor *desc = &descs[index];
    if (manager->LoadAdapter(manager, desc, &g_adapter) != 0) {
        LOG_FUN_ERR_TS("Load Adapter Fail");
        return HDF_ERR_NOT_SUPPORT;
    }
    g_manager = manager;
    if (g_adapter == NULL) {
        LOG_FUN_ERR_TS("load audio device failed");
        return HDF_FAILURE;
    }
    // Initialization port information, can fill through mode and other parameters
    (void)g_adapter->InitAllPorts(g_adapter);
    // User needs to set
    if (InitAttrs(&g_attrs) < 0) {
        return HDF_FAILURE;
    }
    // Specify a hardware device
    if (InitDevDesc(&g_devDesc, renderPort.portId) < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t InitParam()
{
    LOG_FUN_INFO_TS();
    struct AudioAdapterDescriptor *descs = NULL;
    struct AudioManager *manager;
    int32_t ret;
    int32_t size = 0;
    /* Internal and external switch,begin */
    char adapterNameCase[PATH_LEN] = {0};
    if (SwitchInternalOrExternal(adapterNameCase) < 0) {
        return HDF_FAILURE;
    }
    // audio port init
    g_audioPort.dir = PORT_OUT;
    g_audioPort.portId = 0;
    g_audioPort.portName = "AOP";
    /* Internal and external switch,end */
    /* Select loading mode,begin */
    char resolvedPath[PATH_LEN] = {0};
    char func[PATH_LEN] = {0};
    if (SelectLoadingMode(resolvedPath, func) < 0) {
        return HDF_FAILURE;
    }
    /* Select loading mode,end */
    struct AudioManager *(*getAudioManager)() = NULL;
    g_handle = dlopen(resolvedPath, 1);
    if (g_handle == NULL) {
        LOG_FUN_ERR_TS("Open so Fail");
        return HDF_FAILURE;
    }
    getAudioManager = (struct AudioManager *(*)())(dlsym(g_handle, func));
    manager = getAudioManager();
    if (manager == NULL) {
        LOG_FUN_ERR_TS("Get Audio Manager Funcs Fail");
        return HDF_FAILURE;
    }
    ret = manager->GetAllAdapters(manager, &descs, &size);
    int32_t check = size > MAX_AUDIO_ADAPTER_NUM_T || size == 0 || descs == NULL || ret < 0;
    if (check) {
        LOG_FUN_ERR_TS("Get All Adapters Fail");
        return HDF_ERR_NOT_SUPPORT;
    }
    ret = InitParamSplit(descs, manager, adapterNameCase, size);
    if (ret < 0) {
        return ret;
    }
    return HDF_SUCCESS;
}

int32_t SetRenderMute()
{
    int32_t val;
    bool isMute = false;
    int32_t ret;
    if (g_render == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->volume.GetMute((AudioHandle)g_render, &isMute);
    if (ret < 0) {
        printf("The current mute state was not obtained!");
    }
    printf("Now %s ,Do you need to set mute status(1/0):", isMute ? "mute" : "not mute");
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (isMute != 0 && isMute != 1) {
        printf("Invalid value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_render == NULL) {
        printf("Music already stop,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (val == 1) {
        ret = g_render->volume.SetMute((AudioHandle)g_render, !isMute);
    }
    return ret;
}

int32_t SetRenderVolume()
{
    int32_t ret;
    float val = 0.0;
    if (g_render == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->volume.GetVolume((AudioHandle)g_render, &val);
    if (ret < 0) {
        printf("Get current volume failed,");
        SystemInputFail();
        return ret;
    }
    printf("Now the volume is %f ,Please enter the volume value you want to set (0.0-1.0):", val);
    ret = CheckInputName(INPUT_FLOAT, (void *)&val);
    if (ret < 0) return HDF_FAILURE;
    if (val < 0.0 || val > 1.0) {
        printf("Invalid volume value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_render == NULL) {
        printf("Music already stop,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_render->volume.SetVolume((AudioHandle)g_render, val);
    if (ret < 0) {
        printf("set volume fail,");
        SystemInputFail();
    }
    return ret;
}

int32_t GetRenderGain()
{
    int32_t ret;
    float val = 1.0;
    if (g_render == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->volume.GetGain((AudioHandle)g_render, &val);
    if (ret < 0) {
        printf("Get current gain failed,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    printf("Now the gain is %f,", val);
    SystemInputFail();
    return HDF_SUCCESS;
}

int32_t SetRenderPause()
{
    if (g_waitSleep) {
        printf("Already pause,not need pause again,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    int32_t ret;
    if (g_render == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->control.Pause((AudioHandle)g_render);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    printf("Pause success!\n");
    g_waitSleep = 1;
    return HDF_SUCCESS;
}
int32_t SetRenderResume()
{
    if (!g_waitSleep) {
        printf("Now is Playing,not need resume,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    int32_t ret;
    if (g_render == NULL) {
        return HDF_FAILURE;
    }
    ret = g_render->control.Resume((AudioHandle)g_render);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    printf("resume success!\n");
    pthread_mutex_lock(&g_mutex);
    g_waitSleep = 0;
    pthread_cond_signal(&g_functionCond);
    pthread_mutex_unlock(&g_mutex);
    return HDF_SUCCESS;
}
void PrintAttributesFromat()
{
    printf(" ============= Sample Attributes Fromat =============== \n");
    printf("| 1. AUDIO_FORMAT_PCM_8_BIT                            |\n");
    printf("| 2. AUDIO_FORMAT_PCM_16_BIT                           |\n");
    printf("| 3. AUDIO_FORMAT_PCM_24_BIT                           |\n");
    printf("| 4. AUDIO_FORMAT_PCM_32_BIT                           |\n");
    printf(" ====================================================== \n");
}
int32_t SelectAttributesFomat(uint32_t *fomat)
{
    PrintAttributesFromat();
    printf("Please select audio format,If not selected, the default is 16bit:");
    uint32_t ret;
    int val = 0;
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) return HDF_FAILURE;
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
int32_t SetRenderAttributes()
{
    int32_t ret;
    struct AudioSampleAttributes attrs;
    ret = g_render->attr.GetSampleAttributes((AudioHandle)g_render, &attrs);
    if (ret < 0) {
        LOG_FUN_ERR_TS("GetRenderAttributes failed\n");
    } else {
        printf("Current sample attributes:\n");
        printf("audioType is %u\nfomat is %u\nsampleRate is %u\nchannalCount is"
            "%u\nperiod is %u\nframesize is %u\nbigEndian is %u\nSignedData is %u\n",
            attrs.type, attrs.format, attrs.sampleRate,
            attrs.channelCount, attrs.period, attrs.frameSize,
            attrs.isBigEndian, attrs.isSignedData);
    }
    printf("Set Sample Attributes,");
    SystemInputFail();
    system("clear");
    printf("The sample attributes you want to set,Step by step, please.\n");
    ret = SelectAttributesFomat((uint32_t *)(&attrs.format));
    if (ret < 0) {
        LOG_FUN_ERR_TS("SetRenderAttributes format failed\n");
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
    if (g_render == NULL) {
        printf("Music already complete,Please replay and set the attrbutes,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_render->attr.SetSampleAttributes((AudioHandle)g_render, &attrs);
    if (ret < 0) {
        printf("\nSet render attributes failed,");
        SystemInputFail();
    }
    return ret;
}

int32_t SelectRenderScene()
{
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
        printf("Invalid value,");
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
        printf("Music already stop,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_render->scene.SelectScene((AudioHandle)g_render, &scene);
    if (ret < 0) {
        printf("Select scene fail\n");
    }
    return ret;
}
void PrintMenu2()
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
    printf("| 10.Exit                                              |\n");
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
};

void ProcessMenu(int32_t choice)
{
    int32_t i;
    if (choice == SET_RENDER_SLECET_SCENE + 1) {
        printf("Exit from application program!\n");
        return;
    }
    if (g_render == NULL && choice != 1) {
        printf("This render already release,");
        SystemInputFail();
        return;
    }
    for (i = RENDER_START; i <= SET_RENDER_SLECET_SCENE; ++i) {
        if ((choice == (int32_t)g_processRenderMenuSwitchList[i - 1].cmd) &&
            (g_processRenderMenuSwitchList[i - 1].operation != NULL)) {
            g_processRenderMenuSwitchList[i - 1].operation(&g_render);
        }
    }
}

int32_t main(int32_t argc, char const *argv[])
{
    if (argc < 2) {
        printf("usage:[1]%s [2]%s\n", argv[0], "/test/test.wav");
        return 0;
    }
    strncpy_s(g_path, PATH_LEN - 1, argv[1], strlen(argv[1]) + 1);
    FILE *file = fopen(g_path, "rb");
    if (file == NULL) {
        printf("Failed to open '%s',Please enter the correct file name \n", g_path);
        return HDF_FAILURE;
    }
    fclose(file);
    int32_t choice = 0;
    int ret;
    if (InitParam()) { // init
        LOG_FUN_ERR_TS("InitParam Fail\n");
        return HDF_FAILURE;
    }
    while (choice < SET_RENDER_SLECET_SCENE + 1 && choice >= 0) {
        system("clear");
        PrintMenu2();
        printf("your choice is:\n");
        ret = CheckInputName(INPUT_INT, (void *)&choice);
        if (ret < 0) {
            continue;
        }
        if (choice < RENDER_START || choice > SET_RENDER_SLECET_SCENE + 1) {
            printf("You input is wrong,");
            choice = 0;
            SystemInputFail();
            continue;
        }
        ProcessMenu(choice);
    }
    if (g_render != NULL && g_adapter != NULL) {
        StopAudioFiles(&g_render);
    }
    if (g_manager != NULL) {
        g_manager->UnloadAdapter(g_manager, g_adapter);
    }
    dlclose(g_handle);
    return 0;
}
