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

#ifndef OHOS_DAUDIO_EVENTS_H
#define OHOS_DAUDIO_EVENTS_H

namespace OHOS {
namespace DistributedHardware {
typedef enum AudioEventType {
    HDF_AUDIO_DEVICE_ADD        = 0x1,
    HDF_AUDIO_DEVICE_REMOVE     = 0x2,
    HDF_AUDIO_LOAD_SUCCESS      = 0x3,
    HDF_AUDIO_LOAD_FAILURE      = 0x4,
    HDF_AUDIO_UNLOAD            = 0x5,
    HDF_AUDIO_SERVICE_VALID     = 0x7,
    HDF_AUDIO_SERVICE_INVALID   = 0x8,
    HDF_AUDIO_CAPTURE_THRESHOLD = 0x9,
    HDF_AUDIO_EVENT_TYPE_UNKNOWN,
} EVENT_TYPE;

typedef enum AudioDeviceType {
    HDF_AUDIO_LINEOUT        = 0x1,
    HDF_AUDIO_HEADPHONE      = 0x2,
    HDF_AUDIO_HEADSET        = 0x4,
    HDF_AUDIO_USB_HEADSET    = 0x8,
    HDF_AUDIO_USB_HEADPHONE  = 0x10,
    HDF_AUDIO_USBA_HEADSET   = 0x20,
    HDF_AUDIO_USBA_HEADPHONE = 0x40,
    HDF_AUDIO_PRIMARY_DEVICE = 0x80,
    HDF_AUDIO_USB_DEVICE     = 0x100,
    HDF_AUDIO_A2DP_DEVICE    = 0x200,
    HDF_AUDIO_DEVICE_UNKNOWN,
} DEVICE_TYPE;

typedef enum AudioExtParamEvent {
    HDF_AUDIO_EVENT_PARAM_UNKNOWN = 0,
    HDF_AUDIO_EVENT_VOLUME_SET = 1,
    HDF_AUDIO_EVENT_VOLUME_GET = 2,
    HDF_AUDIO_EVENT_VOLUME_CHANGE = 3,
    HDF_AUDIO_EVENT_OPEN_SPK_RESULT = 4,
    HDF_AUDIO_EVENT_CLOSE_SPK_RESULT = 5,
    HDF_AUDIO_EVENT_OPEN_MIC_RESULT = 6,
    HDF_AUDIO_EVENT_CLOSE_MIC_RESULT = 7,
    HDF_AUDIO_EVENT_SPK_CLOSED = 8,
    HDF_AUDIO_EVENT_MIC_CLOSED = 9,
    HDF_AUDIO_EVENT_FOCUS_CHANGE = 10,
    HDF_AUDIO_EVENT_RENDER_STATE_CHANGE = 11,
    HDF_AUDIO_EVNET_MUTE_SET = 12,
    HDF_AUDIO_EVENT_CHANGE_PLAY_STATUS = 13,
    HDF_AUDIO_EVENT_MMAP_START = 14,
    HDF_AUDIO_EVENT_MMAP_STOP = 15,
    HDF_AUDIO_EVENT_MMAP_START_MIC = 16,
    HDF_AUDIO_EVENT_MMAP_STOP_MIC = 17,
    HDF_AUDIO_EVENT_START = 18,
    HDF_AUDIO_EVENT_STOP = 19,
    HDF_AUDIO_EVENT_SPK_DUMP = 20,
    HDF_AUDIO_EVENT_MIC_DUMP = 21,
    HDF_AUDIO_EVENT_FLUSH = 22,
    HDF_AUDIO_EVENT_FULL = 23,
    HDF_AUDIO_EVENT_NEED_DATA = 24,
    HDF_AUDIO_EVENT_SPEED_CHANGE = 25,
} EXT_PARAM_EVENT;

typedef enum AudioVolumeEvent {
    VOLUME_EVENT_UNKNOWN = 0,
    VOLUME_EVENT_BASE = 1,
    VOLUME_EVENT_MIN = 2,
    VOLUME_EVENT_MAX = 3,
    VOLUME_EVENT_MUTE = 4,
} VOL_EVENT;
} // DistributedHardware
} // OHOS
#endif // OHOS_DAUDIO_EVENTS_H