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

#ifndef AUDIO_INTERNAL_H
#define AUDIO_INTERNAL_H

#include <inttypes.h>
#include <pthread.h>
#include "hdf_base.h"
#include "hdf_remote_service.h"
#include "hdf_sbuf.h"
#include "v1_0/iaudio_adapter.h"
#include "v1_0/iaudio_callback.h"
#include "v1_0/iaudio_capture.h"
#include "v1_0/iaudio_manager.h"
#include "v1_0/iaudio_render.h"
#include "v1_0/audio_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LOG_ENABLE            0
#define LOGV_ENABLE           0
#define NAME_LEN              64
#define BIT_NUM_32            32
#define BIT_NUM_24            24
#define BIT_NUM_16            16
#define BIT_NUM_8             8
#define PERIOD_COUNT          2
#define FRAME_DATA            (8192 * 2)
#define PATHPLAN_LEN          64
#define PATHPLAN_COUNT        32
#define PATH_NAME_LEN         128
#define VOLUME_CHANGE         100
#define SEC_TO_NSEC           1000000000
#define MAP_MAX               100
#define FORMAT_ONE            "%-5d  %-10d  %-20" PRIu64 " %-15s  %s\n"
#define FORMAT_TWO            "%-5d  %-10d  %s\n"
#define ERROR_LOG_MAX_NUM     8
#define ERROR_REASON_DESC_LEN 64
#define RANGE_MAX             5
#define RANGE_MIN             4
#define EXTPARAM_LEN          32
#define KEY_VALUE_LIST_LEN    128

#define HDF_AUDIO_CODEC_PRIMARY_DEV "hdf_audio_codec_primary_dev"
#define HDF_AUDIO_CODEC_USB_DEV     "hdf_audio_codec_usb_dev"
#define HDF_AUDIO_CODEC_A2DP_DEV    "hdf_audio_codec_a2dp_dev"
#define PRIMARY                     "primary"
#define USB                         "usb"
#define A2DP                        "a2dp"

typedef void *AudioHandle;

/**
 * @brief Enumerates HAL return value types.
 */
typedef enum {
    AUDIO_SUCCESS = 0,
    AUDIO_ERR_INTERNAL = -1,       /* audio system internal errors */
    AUDIO_ERR_NOT_SUPPORT = -2,    /* operation is not supported */
    AUDIO_ERR_INVALID_PARAM = -3,  /* parameter is invaild */
    AUDIO_ERR_INVALID_OBJECT = -4, /* Invalid object */
    AUDIO_ERR_MALLOC_FAIL = -6,    /* Memory allocation fails */
    AUDIO_ERR_NOTREADY = -7001,    /* audio adapter is not ready */
    AUDIO_ERR_AI_BUSY = -7002,     /* audio capture is busy now */
    AUDIO_ERR_AO_BUSY = -7003,     /* audio render is busy now */
} AUDIO_UHDF_ERR_CODE;

typedef enum {
    TELHPONE_RATE = 8000,
    BROADCAST_AM_RATE = 11025,
    BROADCAST_FM_RATE = 22050,
    MINI_CAM_DV_RATE = 32000,
    MUSIC_RATE = 44100,
    HIGHT_MUSIC_RATE = 48000,
    AUDIO_SAMPLE_RATE_12000 = 12000,
    AUDIO_SAMPLE_RATE_16000 = 16000,
    AUDIO_SAMPLE_RATE_24000 = 24000,
    AUDIO_SAMPLE_RATE_64000 = 64000,
    AUDIO_SAMPLE_RATE_96000 = 96000
} AUDIO_SAMPLE_RATE;

#ifndef UT_TEST
#define STATIC_T static
#else
#define STATIC_T
#endif

#define ADAPTER_NAME_LEN 32

#define USECASE_AUDIO_RENDER_DEEP_BUFFER "deep-buffer-render"
#define USECASE_AUDIO_RENDER_LOW_LATENCY "low-latency-render"

#define AUDIO_ATTR_PARAM_ROUTE         "attr-route"
#define ROUTE_SAMPLE                   "attr-route=x;"
#define AUDIO_ATTR_PARAM_FORMAT        "attr-format"
#define FORMAT_SAMPLE                  "attr-format=xx;"
#define AUDIO_ATTR_PARAM_CHANNELS      "attr-channels"
#define CHANNELS_SAMPLE                "attr-channels=x;"
#define AUDIO_ATTR_PARAM_FRAME_COUNT   "attr-frame-count"
#define FRAME_COUNT_SAMPLE             "attr-frame-count=xxxxxxxxxxxxxxxxxxxx;"
#define AUDIO_ATTR_PARAM_SAMPLING_RATE "attr-sampling-rate"
#define SAMPLING_RATE_SAMPLE           "attr-sampling-rate=xxxxx"
#define AUDIO_ATTR_PARAM_CONNECT       "usb-connect"
#define AUDIO_ATTR_PARAM_DISCONNECT    "usb-disconnect"
#define SUPPORT_ADAPTER_NUM_MAX        8

typedef int32_t (*CallbackProcessFunc)(AudioHandle handle, enum AudioCallbackType callBackType);

enum AudioTurnStandbyMode {
    AUDIO_TURN_STANDBY_LATER = 0,
    AUDIO_TURN_STANDBY_NOW,
    AUDIO_TURN_STANDBY_BUTT,
};

struct DevHandleCapture {
    void *object;
};

struct DevHandle {
    void *object;
};

struct AudioPortAndCapability {
    struct AudioPort port;
    struct AudioPortCapability capability;
    enum AudioPortPassthroughMode mode;
};

struct AudioFrameRenderMode {
    uint64_t frames;
    struct AudioTimeStamp time;
    struct AudioSampleAttributes attrs;
    enum AudioChannelMode mode;
    uint32_t byteRate;
    uint32_t periodSize;
    uint32_t periodCount;
    uint32_t startThreshold;
    uint32_t stopThreshold;
    uint32_t silenceThreshold;
    uint32_t silenceSize;
    char *buffer;
    uint64_t bufferFrameSize;
    uint64_t bufferSize;
    struct IAudioCallback callback;
    void *cookie;
    CallbackProcessFunc callbackProcess;
    AudioHandle renderhandle;
    struct AudioMmapBufferDescripter mmapBufDesc;
};

struct AudioGain {
    float gain;
    float gainMin;
    float gainMax;
};

struct AudioVol {
    int volMin;
    int volMax;
};

struct AudioCtlParam {
    bool mute;
    bool pause;
    bool stop;
    bool mutexFlag;
    float volume;
    float speed;
    pthread_mutex_t mutex;
    pthread_cond_t functionCond;
    struct AudioVol volThreshold;
    struct AudioGain audioGain;
    enum AudioTurnStandbyMode turnStandbyStatus;
};

enum PathRoute {
    DEEP_BUFF = 0,
    RECORD,
    RECORD_LOW_LATRNCY,
    LOW_LATRNCY,
};

struct PathPlan {
    char pathPlanName[PATHPLAN_LEN];
    int value;
};

struct PathDeviceSwitch {
    char deviceSwitch[PATHPLAN_LEN];
    int32_t value;
};

struct PathDeviceInfo {
    char deviceType[NAME_LEN];
    int32_t deviceNum;
    struct PathDeviceSwitch deviceSwitchs[PATHPLAN_COUNT];
};

struct PathSelect {
    char useCase[NAME_LEN];
    struct PathDeviceInfo deviceInfo;
    int useCaseDeviceNum;
    struct PathPlan pathPlan[PATHPLAN_COUNT];
};

struct HwInfo {
    uint32_t card;
    uint32_t device;
    char cardServiceName[NAME_LEN];
    int flags;
    bool callBackEnable;
    char adapterName[NAME_LEN];
    struct AudioPort portDescript;
    struct AudioDeviceDescriptor deviceDescript;
    enum PathRoute pathroute;
    struct PathSelect pathSelect;
};

struct AudioHwRenderMode {
    struct AudioCtlParam ctlParam;
    struct HwInfo hwInfo;
};

struct AudioHwRenderParam {
    struct AudioHwRenderMode renderMode;
    struct AudioFrameRenderMode frameRenderMode;
};

struct ErrorDump {
    int32_t errorCode;
    int32_t count;
    uint64_t frames;
    char *reason; // Specific reasons for failure
    char *currentTime;
};

struct ErrorLog {
    uint32_t totalErrors;
    uint32_t iter;
    struct ErrorDump errorDump[ERROR_LOG_MAX_NUM];
};

struct AudioHwRender {
    struct IAudioRender common;
    struct HdfRemoteService *remote;
    struct HdfRemoteDispatcher dispatcher;
    struct AudioHwRenderParam renderParam;
    struct DevHandle *devDataHandle;            // Bind Data handle
    struct DevHandle *devCtlHandle;             // Bind Ctl handle
    struct HdfRemoteService *proxyRemoteHandle; // proxyPriRemoteHandle
    struct ErrorLog errorLog;
};

struct AudioHwCaptureMode {
    struct AudioCtlParam ctlParam;
    struct HwInfo hwInfo;
};

struct AudioFrameCaptureMode {
    uint64_t frames;
    struct AudioTimeStamp time;
    struct AudioSampleAttributes attrs;
    enum AudioChannelMode mode;
    uint32_t byteRate;
    uint32_t periodSize;
    uint32_t periodCount;
    uint32_t startThreshold;
    uint32_t stopThreshold;
    uint32_t silenceThreshold;
    uint32_t silenceSize;
    char *buffer;
    uint64_t bufferFrameSize;
    uint64_t bufferSize;
    struct AudioMmapBufferDescripter mmapBufDesc;
};

struct AudioHwCaptureParam {
    struct AudioHwCaptureMode captureMode;
    struct AudioFrameCaptureMode frameCaptureMode;
};

struct AudioHwCapture {
    struct IAudioCapture common;
    struct HdfRemoteService *proxyRemoteHandle;
    struct HdfRemoteDispatcher dispatcher;
    struct AudioHwCaptureParam captureParam;
    struct DevHandleCapture *devDataHandle; // Bind Data handle
    struct DevHandleCapture *devCtlHandle;  // Bind Ctl handle
    struct ErrorLog errorLog;
};

struct AudioRenderAndCaptureInfo {
    struct AudioHwRender *renderServicePtr;
    struct AudioHwCapture *captureServicePtr;
};

struct AudioHwAdapter {
    struct IAudioAdapter common;
    struct HdfRemoteService *proxyRemoteHandle;
    struct HdfRemoteDispatcher dispatcher;
    struct AudioAdapterDescriptor adapterDescriptor;
    struct AudioPortAndCapability *portCapabilitys;
    struct AudioRenderAndCaptureInfo infos;
};

struct AudioAdapterInfo {
    char adapterName[ADAPTER_NAME_LEN];
    struct AudioHwAdapter *adapterServicePtr;
};

struct AudioHwManager {
    struct IAudioManager interface;
    int32_t (*OnRemoteRequest)(
        struct IAudioManager *serviceImpl, int code, struct HdfSBuf *data, struct HdfSBuf *reply);
    struct AudioAdapterInfo adapterInfos[SUPPORT_ADAPTER_NUM_MAX];
};

struct ParamValMap {
    char key[EXTPARAM_LEN];
    char value[EXTPARAM_LEN];
};

struct ExtraParams {
    int32_t route;
    int32_t format;
    uint32_t channels;
    uint64_t frames;
    uint32_t sampleRate;
    bool flag;
};

enum AudioAddrType {
    AUDIO_ADAPTER_ADDR = 0, /** Record the address of the adapter for FUZZ. */
    AUDIO_RENDER_ADDR,      /** Record the address of the render for FUZZ. */
    AUDIO_CAPTURE_ADDR,     /** Record the address of the capturef or FUZZ. */
    AUDIO_INVALID_ADDR,     /** Invalid value. */
};

struct AudioAddrDB { // Record the address of the adapter Mgr for FUZZ.
    void *addrValue;
    const char *adapterName;
    enum AudioAddrType addrType;
};

enum ErrorDumpCode {
    WRITE_FRAME_ERROR_CODE = -5,
};

enum AudioAdaptType {
    INVAILD_PATH_SELECT = -1,
    RENDER_PATH_SELECT,
    CAPTURE_PATH_SELECT,
    CHECKSCENE_PATH_SELECT,
    CHECKSCENE_PATH_SELECT_CAPTURE,
};

enum AudioServiceNameType {
    AUDIO_SERVICE_IN = 0,
    AUDIO_SERVICE_OUT,
    AUDIO_SERVICE_MAX,
};

/* dispatch cmdId */
enum AudioInterfaceLibParaCmdList {
    AUDIO_DRV_PCM_IOCTL_HW_PARAMS = 0,
    AUDIO_DRV_PCM_IOCTL_PREPARE,
    AUDIO_DRV_PCM_IOCTL_PREPARE_CAPTURE,
    AUDIO_DRV_PCM_IOCTL_WRITE,
    AUDIO_DRV_PCM_IOCTL_READ,
    AUDIO_DRV_PCM_IOCTRL_START,
    AUDIO_DRV_PCM_IOCTRL_STOP,
    AUDIO_DRV_PCM_IOCTRL_START_CAPTURE,
    AUDIO_DRV_PCM_IOCTRL_STOP_CAPTURE,
    AUDIO_DRV_PCM_IOCTRL_PAUSE,
    AUDIO_DRV_PCM_IOCTRL_PAUSE_CAPTURE,
    AUDIO_DRV_PCM_IOCTRL_RESUME,
    AUDIO_DRV_PCM_IOCTRL_RESUME_CAPTURE,
    AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER,
    AUDIO_DRV_PCM_IOCTL_MMAP_BUFFER_CAPTURE,
    AUDIO_DRV_PCM_IOCTL_MMAP_POSITION,
    AUDIO_DRV_PCM_IOCTL_MMAP_POSITION_CAPTURE,
    AUDIO_DRV_PCM_IOCTRL_RENDER_OPEN,
    AUDIO_DRV_PCM_IOCTRL_RENDER_CLOSE,
    AUDIO_DRV_PCM_IOCTRL_CAPTURE_OPEN,
    AUDIO_DRV_PCM_IOCTRL_CAPTURE_CLOSE,
    AUDIO_DRV_PCM_IOCTL_BUTT,
};

enum AudioStreamType {
    AUDIO_CAPTURE_STREAM = 0,
    AUDIO_RENDER_STREAM,
};

typedef struct DevHandle *(*BindServiceRenderPassthrough)(const char *);
typedef int32_t (*InterfaceLibModeRenderPassthrough)(struct DevHandle *, struct AudioHwRenderParam *, int);
typedef void (*CloseServiceRenderPassthrough)(struct DevHandle *);

typedef struct DevHandleCapture *(*BindServiceCapturePassthrough)(const char *);
typedef int32_t (*InterfaceLibModeCapturePassthrough)(struct DevHandleCapture *, struct AudioHwCaptureParam *, int);
typedef void (*CloseServiceCapturePassthrough)(struct DevHandleCapture *);

typedef int32_t (*PathSelGetConfToJsonObj)(void);
typedef int32_t (*PathSelAnalysisJson)(void *adapterParam, enum AudioAdaptType adaptType);

BindServiceRenderPassthrough *AudioPassthroughGetBindServiceRender(void);
InterfaceLibModeRenderPassthrough *AudioPassthroughGetInterfaceLibModeRender(void);
CloseServiceRenderPassthrough *AudioPassthroughGetCloseServiceRender(void);

BindServiceCapturePassthrough *AudioPassthroughGetBindServiceCapture(void);
InterfaceLibModeCapturePassthrough *AudioPassthroughGetInterfaceLibModeCapture(void);
CloseServiceCapturePassthrough *AudioPassthroughGetCloseServiceCapture(void);

#ifndef AUDIO_HAL_NOTSUPPORT_PATHSELECT
PathSelGetConfToJsonObj *AudioPassthroughGetPathSelGetConfToJsonObj(void);
PathSelAnalysisJson *AudioPassthroughGetPathSelAnalysisJson(void);
#endif

int32_t CheckParaDesc(const struct AudioDeviceDescriptor *desc, const char *type);
int32_t CheckParaAttr(const struct AudioSampleAttributes *attrs);
int32_t AttrFormatToBit(const struct AudioSampleAttributes *attrs, int32_t *format);
int32_t InitHwRenderParam(struct AudioHwRender *hwRender, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs);
int32_t InitForGetPortCapability(struct AudioPort portIndex, struct AudioPortCapability *capabilityIndex);
void AudioAdapterReleaseCapSubPorts(const struct AudioPortAndCapability *portCapabilitys, int32_t num);
int32_t AudioAdapterInitAllPorts(struct IAudioAdapter *adapter);
void AudioReleaseRenderHandle(struct AudioHwRender *hwRender);
int32_t AudioAdapterCreateRenderPre(struct AudioHwRender *hwRender, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, const struct AudioHwAdapter *hwAdapter);
int32_t AudioAdapterBindServiceRender(struct AudioHwRender *hwRender);
int32_t AudioAdapterCreateRender(struct IAudioAdapter *self, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct IAudioRender **render);
int32_t AudioAdapterDestroyRender(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc);
int32_t GetAudioCaptureFunc(struct AudioHwCapture *hwCapture);
int32_t InitHwCaptureParam(struct AudioHwCapture *hwCapture, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs);
void AudioReleaseCaptureHandle(struct AudioHwCapture *hwCapture);
int32_t AudioAdapterCreateCapturePre(struct AudioHwCapture *hwCapture, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct AudioHwAdapter *hwAdapter);
int32_t AudioAdapterInterfaceLibModeCapture(struct AudioHwCapture *hwCapture);
int32_t AudioAdapterCreateCapture(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc,
    const struct AudioSampleAttributes *attrs, struct IAudioCapture **capture);
int32_t AudioAdapterDestroyCapture(struct IAudioAdapter *adapter, const struct AudioDeviceDescriptor *desc);
int32_t AudioAdapterGetPortCapability(
    struct IAudioAdapter *self, const struct AudioPort *port, struct AudioPortCapability *capability);
int32_t AudioAdapterSetPassthroughMode(
    struct IAudioAdapter *self, const struct AudioPort *port, enum AudioPortPassthroughMode mode);
int32_t AudioAdapterGetPassthroughMode(
    struct IAudioAdapter *adapter, const struct AudioPort *port, enum AudioPortPassthroughMode *mode);
int32_t AudioAdapterGetDeviceStatus(struct IAudioAdapter *adapter, struct AudioDeviceStatus *status);
int32_t PcmBytesToFrames(const struct AudioFrameRenderMode *frameRenderMode, uint64_t bytes, uint32_t *frameCount);
int32_t AudioRenderStart(struct IAudioRender *self);
int32_t AudioRenderStop(struct IAudioRender *self);
int32_t AudioRenderPause(struct IAudioRender *self);
int32_t AudioRenderResume(struct IAudioRender *self);
int32_t AudioRenderFlush(struct IAudioRender *self);
int32_t AudioRenderGetFrameSize(struct IAudioRender *self, uint64_t *size);
int32_t AudioRenderGetFrameCount(struct IAudioRender *self, uint64_t *count);
int32_t AudioRenderSetSampleAttributes(struct IAudioRender *self, const struct AudioSampleAttributes *attrs);
int32_t AudioRenderGetSampleAttributes(struct IAudioRender *self, struct AudioSampleAttributes *attrs);
int32_t AudioRenderGetCurrentChannelId(struct IAudioRender *self, uint32_t *channelId);
int32_t AudioRenderCheckSceneCapability(
    struct IAudioRender *self, const struct AudioSceneDescriptor *scene, bool *supported);
int32_t AudioRenderSelectScene(struct IAudioRender *self, const struct AudioSceneDescriptor *scene);
int32_t AudioRenderSetMute(struct IAudioRender *self, bool mute);
int32_t AudioRenderGetMute(struct IAudioRender *self, bool *mute);
int32_t AudioRenderSetVolume(struct IAudioRender *self, float volume);
int32_t AudioRenderGetVolume(struct IAudioRender *self, float *volume);
int32_t AudioRenderGetGainThreshold(struct IAudioRender *self, float *min, float *max);
int32_t AudioRenderGetGain(struct IAudioRender *self, float *gain);
int32_t AudioRenderSetGain(struct IAudioRender *self, float gain);
int32_t AudioRenderGetLatency(struct IAudioRender *self, uint32_t *ms);
int32_t AudioRenderRenderFrame(struct IAudioRender *self, const int8_t *frame, uint32_t frameLen, uint64_t *replyBytes);
int32_t AudioRenderGetRenderPosition(struct IAudioRender *self, uint64_t *frames, struct AudioTimeStamp *time);
int32_t AudioRenderSetRenderSpeed(struct IAudioRender *self, float speed);
int32_t AudioRenderGetRenderSpeed(struct IAudioRender *self, float *speed);
int32_t AudioRenderSetChannelMode(struct IAudioRender *self, enum AudioChannelMode mode);
int32_t AudioRenderGetChannelMode(struct IAudioRender *self, enum AudioChannelMode *mode);
int32_t AudioRenderSetExtraParams(struct IAudioRender *self, const char *keyValueList);
int32_t AudioRenderGetExtraParams(struct IAudioRender *self, char *keyValueList, uint32_t keyValueListLen);
int32_t AudioRenderReqMmapBuffer(
    struct IAudioRender *self, int32_t reqSize, const struct AudioMmapBufferDescripter *desc);
int32_t AudioRenderGetMmapPosition(struct IAudioRender *self, uint64_t *frames, struct AudioTimeStamp *time);
int32_t AudioRenderTurnStandbyMode(struct IAudioRender *self);
int32_t AudioRenderAudioDevDump(struct IAudioRender *self, int32_t range, int32_t fd);
int32_t AudioRenderRegCallback(struct IAudioRender *self, struct IAudioCallback *audioCallback, int8_t cookie);
int32_t AudioRenderDrainBuffer(struct IAudioRender *self, enum AudioDrainNotifyType *type);
int32_t AudioCaptureStart(struct IAudioCapture *self);
int32_t AudioCaptureStop(struct IAudioCapture *self);
int32_t AudioCapturePause(struct IAudioCapture *self);
int32_t AudioCaptureResume(struct IAudioCapture *self);
int32_t AudioCaptureFlush(struct IAudioCapture *self);
int32_t AudioCaptureGetFrameSize(struct IAudioCapture *self, uint64_t *size);
int32_t AudioCaptureGetFrameCount(struct IAudioCapture *self, uint64_t *count);
int32_t AudioCaptureSetSampleAttributes(struct IAudioCapture *self, const struct AudioSampleAttributes *attrs);
int32_t AudioCaptureGetSampleAttributes(struct IAudioCapture *self, struct AudioSampleAttributes *attrs);
int32_t AudioCaptureGetCurrentChannelId(struct IAudioCapture *self, uint32_t *channelId);
int32_t AudioCaptureCheckSceneCapability(
    struct IAudioCapture *self, const struct AudioSceneDescriptor *scene, bool *supported);
int32_t AudioCaptureSelectScene(struct IAudioCapture *self, const struct AudioSceneDescriptor *scene);
int32_t AudioCaptureSetMute(struct IAudioCapture *self, bool mute);
int32_t AudioCaptureGetMute(struct IAudioCapture *self, bool *mute);
int32_t AudioCaptureSetVolume(struct IAudioCapture *self, float volume);
int32_t AudioCaptureGetVolume(struct IAudioCapture *self, float *volume);
int32_t AudioCaptureGetGainThreshold(struct IAudioCapture *self, float *min, float *max);
int32_t AudioCaptureGetGain(struct IAudioCapture *self, float *gain);
int32_t AudioCaptureSetGain(struct IAudioCapture *self, float gain);
int32_t AudioCaptureCaptureFrame(struct IAudioCapture *self, int8_t *frame, uint32_t *frameLen, uint64_t requestBytes);
int32_t AudioCaptureGetCapturePosition(struct IAudioCapture *self, uint64_t *frames, struct AudioTimeStamp *time);
int32_t AudioCaptureSetExtraParams(struct IAudioCapture *self, const char *keyValueList);
int32_t AudioCaptureGetExtraParams(struct IAudioCapture *self, char *keyValueList, uint32_t keyValueListLen);
int32_t AudioCaptureReqMmapBuffer(
    struct IAudioCapture *self, int32_t reqSize, const struct AudioMmapBufferDescripter *desc);
int32_t AudioCaptureGetMmapPosition(struct IAudioCapture *self, uint64_t *frames, struct AudioTimeStamp *time);
int32_t AudioCaptureTurnStandbyMode(struct IAudioCapture *self);
int32_t AudioCaptureAudioDevDump(struct IAudioCapture *self, int32_t range, int32_t fd);
int32_t CallbackProcessing(AudioHandle handle, enum AudioCallbackType callBackType);

#ifdef __cplusplus
}
#endif
#endif
