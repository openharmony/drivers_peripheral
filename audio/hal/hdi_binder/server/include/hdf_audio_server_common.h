/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef HDF_AUDIO_SERVER_COMMON_H
#define HDF_AUDIO_SERVER_COMMON_H

#include "audio_events.h"
#include "audio_internal.h"
#include "hdf_audio_server.h"
#include "hdf_device_desc.h"
#include "hdf_log.h"

#define STR_MAX 512
#define CHECK_NULL_PTR_RETURN_VALUE(ptr, ret) do { \
    if ((ptr) == NULL) { \
        HDF_LOGE("%{public}s:line:%{public}d pointer is null, ret = %{public}d", __func__, __LINE__, ret); \
        return (ret); \
    } \
} while (0)

enum AudioServerType {
    AUDIO_SERVER_PRIMARY,
    AUDIO_SERVER_USB,
    AUDIO_SERVER_A2DP,
    AUDIO_SERVER_BOTTOM
};

typedef int32_t (*AudioAllfunc)(const struct HdfDeviceIoClient *client, struct HdfSBuf *data, struct HdfSBuf *reply);
struct HdiServiceDispatchCmdHandleList {
    enum AudioHdiServerCmdId cmd;
    AudioAllfunc func;
};

int32_t HdiServiceRenderCaptureReadData(struct HdfSBuf *data,
    const char **adapterName, uint32_t *pid);
int32_t AudioAdapterListCheckAndGetRender(struct AudioRender **render, struct HdfSBuf *data);
int32_t AudioAdapterListCheckAndGetCapture(struct AudioCapture **capture, struct HdfSBuf *data);
int32_t ReadAudioSapmleAttrbutes(struct HdfSBuf *data, struct AudioSampleAttributes *attrs);
int32_t WriteAudioSampleAttributes(struct HdfSBuf *reply, const struct AudioSampleAttributes *attrs);

int32_t HdiServicePositionWrite(struct HdfSBuf *reply,
    uint64_t frames, struct AudioTimeStamp time);
int32_t HdiServiceReqMmapBuffer(struct AudioMmapBufferDescriptor *desc, struct HdfSBuf *data);

int32_t HdiServiceGetFuncs();
void AudioHdiServerRelease(void);
int32_t HdiServiceGetAllAdapter(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceLoadAdapter(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceInitAllPorts(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceUnloadAdapter(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceGetPortCapability(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceSetPassthroughMode(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceGetPassthroughMode(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t HdiServiceGetDevStatusByPNP(const struct HdfDeviceIoClient *client,
    struct HdfSBuf *data, struct HdfSBuf *reply);
int32_t AudioServiceStateChange(struct HdfDeviceObject *device,
    struct AudioEvent *audioSrvEvent);

enum AudioServerType AudioHdiGetLoadServerFlag(void);
void AudioHdiSetLoadServerFlag(enum AudioServerType serverType);
void AudioHdiClearLoadServerFlag(void);

int32_t HdiServiceDispatch(struct HdfDeviceIoClient *client, int cmdId, struct HdfSBuf *data,
    struct HdfSBuf *reply);
#endif
