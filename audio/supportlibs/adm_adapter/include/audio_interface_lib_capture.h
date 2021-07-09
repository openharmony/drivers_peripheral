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

#ifndef AUDIO_INTERFACE_LIB_CAPTURE_H
#define AUDIO_INTERFACE_LIB_CAPTURE_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "securec.h"
#include "audio_internal.h"
#include "audio_adapter.h"
#include "osal_mem.h"
#include "hdf_io_service_if.h"
#include "hdf_sbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTRL_CMD_CAPTURE "control"            // For Bind control service
#define CAPTURE_CMD "capture"                 // For Bind capture service
#define SERVIC_NAME_MAX_LEN 32
#define CTRL_NUM 100

enum AudioCriBuffStatusCapture {
    CIR_BUFF_NORMAL = 1,
    CIR_BUFF_EMPTY = 3,
};

enum AudioInterfaceLibCaptureCtrl {
    AUDIODRV_CTL_IOCTL_ELEM_INFO_CAPTURE = CTRL_NUM, // Ctrl
    AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE,
    AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE,
    AUDIODRV_CTL_IOCTL_MUTE_READ_CAPTURE,     // mute
    AUDIODRV_CTL_IOCTL_MUTE_WRITE_CAPTURE,
    AUDIODRV_CTL_IOCTL_PAUSE_READ_CAPTURE,    // pause
    AUDIODRV_CTL_IOCTL_PAUSE_WRITE_CAPTURE,
    AUDIODRV_CTL_IOCTL_ELEM_BUTT_CAPTURE,
    AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE,     // gain
    AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE,
    AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE, // scene selsect
    AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE, // scene threshold
    AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE, // scene threshold
};

struct DevHandleCapture *AudioBindServiceCapture(const char *name);
void AudioCloseServiceCapture(struct DevHandleCapture *handle);
int32_t AudioInterfaceLibModeCapture(struct DevHandleCapture *handle,
                                     struct AudioHwCaptureParam *handleData,
                                     int cmdId);
int32_t AudioOutputCaptureHwParams(struct DevHandleCapture *handle,
                                   int cmdId,
                                   struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureRead(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureStop(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureStartPrepare(struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetVolume(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetVolume(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetMuteStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetMuteStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetPauseStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetGainStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetGainStu(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSceneSelect(struct DevHandleCapture *handle, int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetGainThreshold(struct DevHandleCapture *handle,
                                        int cmdId,
                                        struct AudioHwCaptureParam *handleData);

int32_t AudioCtlCaptureGetVolThreshold(struct DevHandleCapture *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
#ifdef __cplusplus
}
#endif
#endif /* AUDIO_INTERFACE_LIB_CAPTURE_H */
