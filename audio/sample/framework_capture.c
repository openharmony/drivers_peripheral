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

#define AUDIO_CHANNELCOUNT 2
#define AUDIO_SAMPLE_RATE_48K 48000
#define PATH_LEN 256

#define DEEP_BUFFER_RENDER_PERIOD_SIZE 4096
#define DEEP_BUFFER_RENDER_PERIOD_COUNT 8
#define INT_32_MAX 0x7fffffff
#define PERIOD_SIZE 1024
#define AUDIO_BUFF_SIZE (1024 * 16)
#define PCM_8_BIT 8
#define PCM_16_BIT 16
#define AUDIO_TOTALSIZE_15M (1024 * 15)
#define AUDIO_RECORD_INTERVAL_512KB 512

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
struct StrParaCapture g_str;

pthread_t g_tids;
FILE *g_file;
char *g_frame;
void *g_handle;
char g_path[256];

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
#define LOG_FUN_INFO_TS() do { \
    printf("%s: %s: %d\n", __FILE__, __func__, __LINE__); \
} while (0)

#define LOG_FUN_ERR_TS(info) do { \
        printf("%s: %s: %d:[ERROR]:%s\n", __FILE__, __func__, __LINE__, (info)); \
} while (0)

#define LOG_PARA_INFO_TS(info) do { \
        printf("%s: %s: %d:[INFO]:%s\n", __FILE__, __func__, __LINE__, (info)); \
} while (0)

int32_t CheckInputName(int type, void *val)
{
    if (val == NULL) {
        return HDF_FAILURE;
    }
    int ret;
    int inputInt = 0;
    float inputFloat = 0.0;
    uint32_t inputUint = 0;
    switch (type) {
        case INPUT_INT:
            ret = scanf_s("%d", &inputInt);
            if (inputInt < 0 || inputInt > SET_CAPTURE_SLECET_SCENE + 1) {
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
    attrs->period = DEEP_BUFFER_RENDER_PERIOD_SIZE;
    attrs->frameSize = PCM_16_BIT * attrs->channelCount / PCM_8_BIT;
    attrs->isBigEndian = false;
    attrs->isSignedData = true;
    attrs->startThreshold = DEEP_BUFFER_RENDER_PERIOD_SIZE / (attrs->frameSize);
    attrs->stopThreshold = INT_32_MAX;
    attrs->silenceThreshold = AUDIO_BUFF_SIZE;
    return 0;
}

int32_t InitDevDescCapture(struct AudioDeviceDescriptor *devDesc,
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

int32_t StopButtonCapture(struct AudioCapture **captureS)
{
    if (captureS == NULL) {
        return HDF_FAILURE;
    }
    if (!g_closeEnd) {
        g_closeEnd = true;
        pthread_join(g_tids, NULL);
    }
    struct AudioCapture *capture = *captureS;
    if (capture == NULL) {
        return HDF_FAILURE;
    }
    int ret = capture->control.Stop((AudioHandle)capture);
    if (ret < 0) {
        printf("Stop capture!\n");
    }
    if (g_adapter == NULL) {
        return HDF_FAILURE;
    }
    ret = g_adapter->DestroyCapture(g_adapter, capture);
    if (ret < 0) {
        printf("Capture already destroy!\n");
    }
    capture = NULL;
    g_capture = NULL;
    if (g_frame != NULL) {
        free(g_frame);
        g_frame = NULL;
    }
    if (g_file != NULL) {
        fclose(g_file);
        g_file = NULL;
    }
    printf("Stop Successful\n");
    return HDF_SUCCESS;
}

int32_t FrameStartCapture(void *param)
{
    if (param == NULL) {
        return HDF_FAILURE;
    }
    struct StrParaCapture *strParam = (struct StrParaCapture *)param;
    struct AudioCapture *capture = strParam->capture;
    FILE *file = strParam->file;
    int32_t ret;
    uint32_t bufferSize = AUDIO_BUFF_SIZE;   // 16 * 1024 = 16KB, it needs to be calculated by audio parameters
    uint64_t replyBytes = 0;
    uint64_t totalSize = 0;
    uint64_t requestBytes = AUDIO_BUFF_SIZE; // 16 * 1024 = 16KB
    char *frame = NULL;
    frame = (char *)calloc(1, bufferSize);
    if (frame == NULL) {
        return HDF_FAILURE;
    }
    do {
        ret = capture->CaptureFrame(capture, frame, requestBytes, &replyBytes);
        if (ret < 0) {
            if (ret == HDF_ERR_INVALID_OBJECT) {
                printf("Record already stop!\n");
                break;
            }
            continue;
        }
        fwrite(frame, replyBytes, 1, file);
        totalSize += (replyBytes / PERIOD_SIZE); // 1024 = 1Kb
        if (totalSize % AUDIO_RECORD_INTERVAL_512KB == 0) { // 512KB
            printf("\nRecording,the audio file size is %lluKb\n", totalSize);
        }
    } while ((totalSize <= AUDIO_TOTALSIZE_15M) && (!g_closeEnd)); // 15 * 1024 = 15M
    if (frame != NULL) {
        free(frame);
        frame = NULL;
    }
    printf("Record end\n");
    if (!g_closeEnd) {
        StopButtonCapture(&g_capture);
    }
    return HDF_SUCCESS;
}

int32_t StartButtonCapture(struct AudioCapture **captureS)
{
    if (captureS == NULL) {
        return HDF_FAILURE;
    }
    if (g_file != NULL) {
        printf("the capture is playing,please stop first\n");
        return HDF_FAILURE;
    }
    g_closeEnd = false;
    struct AudioCapture *capture;
    int32_t ret = g_adapter->CreateCapture(g_adapter, &g_devDesc, &g_attrs, &capture);
    if (capture == NULL || ret < 0) {
        return HDF_FAILURE;
    }
    g_file = fopen(g_path, "wb+");
    if (g_file == NULL) {
        printf("failed to open '%s'\n", g_path);
        return HDF_FAILURE;
    }
    ret = capture->control.Start((AudioHandle)capture);
    if (ret < 0) {
        if (g_file != NULL) {
            fclose(g_file);
            g_file = NULL;
        }
        return HDF_FAILURE;
    }
    uint32_t bufferSize = PcmFramesToBytes(g_attrs);
    g_frame = (char *)calloc(1, bufferSize);
    if (g_frame == NULL) {
        return HDF_FAILURE;
    }
    memset_s(&g_str, sizeof(struct StrParaCapture), 0, sizeof(struct StrParaCapture));
    g_str.capture = capture;
    g_str.file = g_file;
    g_str.attrs = g_attrs;
    g_str.frame = g_frame;
    ret = pthread_create(&g_tids, NULL, (void *)(&FrameStartCapture), &g_str);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    *captureS = capture;
    printf("Start Successful\n");
    return HDF_SUCCESS;
}

int32_t SwitchAdapterCapture(struct AudioAdapterDescriptor *descs, const char *adapterNameCase,
    enum AudioPortDirection portFlag, struct AudioPort *capturePort, const int32_t size)
{
    if (descs == NULL || adapterNameCase == NULL || capturePort == NULL) {
        return HDF_FAILURE;
    }
    for (int32_t index = 0; index < size; index++) {
        struct AudioAdapterDescriptor *desc = &descs[index];
        if (strcmp(desc->adapterName, adapterNameCase)) {
            printf("adapter name case = %s\n", adapterNameCase);
            continue;
        }
        for (uint32_t port = 0; ((desc != NULL) && (port < desc->portNum)); port++) {
            // Only find out the port of out in the sound card
            if (desc->ports[port].dir == portFlag) {
                *capturePort = desc->ports[port];
                return index;
            }
        }
    }
    return HDF_FAILURE;
}
void PrintMenu1()
{
    printf(" ============== Play Capture Loading Mode ===========\n");
    printf("| 1. Capture Direct Loading                         |\n");
    printf("| 2. Capture Service Loading                        |\n");
    printf("| Note: switching is not supported in the MPI's     |\n");
    printf("|       version.                                    |\n");
    printf(" =================================================== \n");
}
int32_t SelectLoadingMode(char *resolvedPath, char *func)
{
    system("clear");
    int choice = 0;
    PrintMenu1();
    printf("Please enter your choice:");
    int32_t ret = CheckInputName(INPUT_INT, (void *)&choice);
    if (ret < 0) return HDF_FAILURE;
    switch (choice) {
        case 1:
            snprintf_s(resolvedPath, PATH_LEN, PATH_LEN - 1, "%s", "/system/lib/libhdi_audio.z.so");
            snprintf_s(func, PATH_LEN, PATH_LEN - 1, "%s", "GetAudioManagerFuncs");
            break;
        case 2: // 2. Capture Service Loading
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

int32_t InitParam()
{
    int32_t ret;
    int32_t index;
    int32_t size = 0;
    char resolvedPath[PATH_LEN] = {0};
    char func[PATH_LEN] = {0};
    if (SelectLoadingMode(resolvedPath, func) < 0) {
        return HDF_FAILURE;
    }
    void *handle = dlopen(resolvedPath, 1);
    struct AudioPort audioPort;
    struct AudioAdapterDescriptor *descs = NULL;
    struct AudioPort capturePort;
    struct AudioManager *(*getAudioManager)() = NULL;
    getAudioManager = (struct AudioManager *(*)())(dlsym(handle, func));
    audioPort.dir = PORT_IN;
    audioPort.portId = 0;
    audioPort.portName = "AOP";
    struct AudioManager *manager = getAudioManager();
    if (manager == NULL) {
        return HDF_FAILURE;
    }
    ret = manager->GetAllAdapters(manager, &descs, &size);
    // adapters is 0~3
    int32_t check = size > 3 || size == 0 || descs == NULL || ret < 0;
    if (check) {
        return HDF_ERR_NOT_SUPPORT;
    }
    char adapterNameCase[PATH_LEN] = "usb";
    index = SwitchAdapterCapture(descs, adapterNameCase, audioPort.dir, &capturePort, size);
    if (index < 0) {
        return HDF_ERR_NOT_SUPPORT;
    }
    struct AudioAdapterDescriptor *desc = &descs[index];
    if (manager->LoadAdapter(manager, desc, &g_adapter) != 0) {
        return HDF_ERR_NOT_SUPPORT;
    }
    g_manager = manager;
    if (g_adapter == NULL) {
        return HDF_FAILURE;
    }
    // Initialization port information, can fill through mode and other parameters
    (void)g_adapter->InitAllPorts(g_adapter);
    // User needs to set
    if (InitAttrsCapture(&g_attrs) < 0) {
        return HDF_FAILURE;
    }
    // Specify a hardware device
    if (InitDevDescCapture(&g_devDesc, capturePort.portId) < 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SetCaptureMute()
{
    int32_t val = 0;
    bool isMute = false;
    int32_t ret;
    if (g_capture == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->volume.GetMute((AudioHandle)g_capture, &isMute);
    if (ret < 0) {
        printf("The current mute state was not obtained!");
    }
    printf("Now %s ,Do you need to set mute status(1/0):\n", isMute ? "mute" : "not mute");
    ret = CheckInputName(INPUT_INT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (isMute != 0 && isMute != 1) {
        printf("Invalid value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture == NULL) {
        printf("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (val == 1) {
        ret = g_capture->volume.SetMute((AudioHandle)g_capture, !isMute);
    }
    return ret;
}

int32_t SetCaptureVolume()
{
    int32_t ret;
    float val = 0.5;
    if (g_capture == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->volume.GetVolume((AudioHandle)g_capture, &val);
    if (ret < 0) {
        printf("Get current volume failed,");
        SystemInputFail();
        return ret;
    }
    printf("Now the volume is %f ,Please enter the volume value you want to set (0.0-1.0):\n", val);
    ret = CheckInputName(INPUT_FLOAT, (void *)&val);
    if (ret < 0) {
        return HDF_FAILURE;
    }
    if (val < 0.0 || val > 1.0) {
        printf("Invalid volume value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture == NULL) {
        printf("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_capture->volume.SetVolume((AudioHandle)g_capture, val);
    if (ret < 0) {
        printf("set volume fail,");
        SystemInputFail();
    }
    return ret;
}

int32_t SetCaptureGain()
{
    int32_t ret;
    float val = 1.0;
    if (g_capture == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->volume.GetGain((AudioHandle)g_capture, &val);
    if (ret < 0) {
        LOG_FUN_ERR_TS("Get current gain failed,");
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
        printf("Invalid gain value,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    if (g_capture == NULL) {
        printf("Record already complete,Please record againand,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_capture->volume.SetGain((AudioHandle)g_capture, val);
    if (ret < 0) {
        printf("Set capture gain failed,");
        SystemInputFail();
    }
    return ret;
}

int32_t SetCaptyrePause()
{
    int32_t ret;
    if (g_capture == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->control.Pause((AudioHandle)g_capture);
    if (ret != 0) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SetCaptureResume()
{
    int32_t ret;
    if (g_capture == NULL) {
        return HDF_FAILURE;
    }
    ret = g_capture->control.Resume((AudioHandle)g_capture);
    if (ret != 0) {
        return HDF_FAILURE;
    }
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

int32_t SetCaptureAttributes()
{
    int32_t ret;
    struct AudioSampleAttributes attrs;
    ret = g_capture->attr.GetSampleAttributes((AudioHandle)g_capture, &attrs);
    if (ret < 0) {
        LOG_FUN_ERR_TS("GetCaptureAttributes failed\n");
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
        LOG_FUN_ERR_TS("SetCaptureAttributes format failed\n");
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
    if (g_capture == NULL) {
        printf("Record already complete,Please record againand set the attrbutes,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_capture->attr.SetSampleAttributes((AudioHandle)g_capture, &attrs);
    if (ret < 0) {
        printf("\nSet capture attributes failed,");
        SystemInputFail();
    }
    return ret;
}

int32_t SelectCaptureScene()
{
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
        printf("Invalid value,");
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
        printf("Record already stop,");
        SystemInputFail();
        return HDF_FAILURE;
    }
    ret = g_capture->scene.SelectScene((AudioHandle)g_capture, &scene);
    if (ret < 0) {
        printf("Select scene fail\n");
    }
    return ret;
}

void PrintMenu2()
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
    printf("| 10.Exit                                               |\n");
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
};

void ProcessMenu(int32_t choice)
{
    int32_t i;
    if (choice == SET_CAPTURE_SLECET_SCENE + 1) {
        printf("Exit from application program!\n");
        return;
    }
    if (g_capture == NULL && choice != 1) {
        printf("this capture already release,");
        SystemInputFail();
        return;
    }
    for (i = CAPTURE_START; i <= SET_CAPTURE_SLECET_SCENE; ++i) {
        if ((choice == (int32_t)g_processCaptureMenuSwitchList[i - 1].cmd) &&
            (g_processCaptureMenuSwitchList[i - 1].operation != NULL)) {
            g_processCaptureMenuSwitchList[i - 1].operation(&g_capture);
        }
    }
}

int32_t main(int32_t argc, char const *argv[])
{
    if (argc < 2) {
        printf("usage:[1]%s [2]%s\n", argv[0], "/data/test.wav");
        return 0;
    }
    strncpy_s(g_path, PATH_LEN - 1, argv[1], strlen(argv[1]) + 1);
    FILE *file = fopen(g_path, "wb+");
    if (file == NULL) {
        printf("failed to open '%s',Please enter the correct file name \n", g_path);
        return HDF_FAILURE;
    }
    fclose(file);
    int32_t choice = 0;
    int ret;
    if (InitParam()) { // init
        LOG_FUN_ERR_TS("InitParam Fail\n");
        return HDF_FAILURE;
    }
    while (choice < SET_CAPTURE_SLECET_SCENE + 1 && choice >= 0) {
        system("clear");
        PrintMenu2();
        printf("your choice is:\n");
        ret = CheckInputName(INPUT_INT, (void *)&choice);
        if (ret < 0) {
            continue;
        }
        if (choice < CAPTURE_START || choice > SET_CAPTURE_SLECET_SCENE + 1) {
            printf("You input is wrong,");
            choice = 0;
            SystemInputFail();
            continue;
        }
        ProcessMenu(choice);
    }
    if (g_capture != NULL && g_adapter != NULL) {
        StopButtonCapture(&g_capture);
    }
    if (g_manager != NULL) {
        g_manager->UnloadAdapter(g_manager, g_adapter);
    }
    dlclose(g_handle);
    printf("Record file path:%s\n", g_path);
    return 0;
}

