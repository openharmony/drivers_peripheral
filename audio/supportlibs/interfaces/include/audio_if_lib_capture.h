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
#ifndef AUDIO_IF_LIB_CAPTURE_H
#define AUDIO_IF_LIB_CAPTURE_H

#include "audio_if_lib_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAPTURE_CMD "capture"   // For Bind capture service

enum AudioInterfaceLibCaptureCtrl {
    AUDIODRV_CTL_IOCTL_ELEM_INFO_CAPTURE = CTRL_NUM, // Ctrl
    AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE,
    AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE,
    AUDIODRV_CTL_IOCTL_ELEM_LIST_CAPTURE,
    AUDIODRV_CTL_IOCTL_ELEM_CARD_CAPTURE,
    AUDIODRV_CTL_IOCTL_ELEM_HDMI_CAPTURE,
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

int32_t AudioOutputCaptureOpen(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCapturePrepare(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureStart(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureClose(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureGetMmapPosition(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioInterfaceLibModeCapture(const struct DevHandle *handle,
    struct AudioHwCaptureParam *handleData, int cmdId);
int32_t AudioOutputCaptureHwParams(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureRead(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureStop(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureStartPrepare(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetVolume(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetVolume(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetMuteStu(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetMuteStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetPauseStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSetGainStu(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetGainStu(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureSceneSelect(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetGainThreshold(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioCtlCaptureGetVolThreshold(const struct DevHandle *handle,
    int cmdId, struct AudioHwCaptureParam *handleData);
int32_t AudioOutputCaptureReqMmapBuffer(const struct DevHandle *handle,
    int cmdId, const struct AudioHwCaptureParam *handleData);

#ifdef __cplusplus
}
#endif
#endif /* AUDIO_IF_LIB_CAPTURE_H */

