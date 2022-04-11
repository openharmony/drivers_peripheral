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

/**
 * @addtogroup Audio
 * @{
 *
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a driver adapter, and rendering and capturing audios.
 *
 * @since 1.0
 * @version 1.0
 */

/**
 * @file audio_events.h
 *
 * @brief Defines the type of audio event used by the media service
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef AUDIO_EVENTS_H
#define AUDIO_EVENTS_H

#include <stdint.h>

typedef enum AudioEventType {
    HDF_AUDIO_DEVICE_ADD        = 0x1,
    HDF_AUDIO_DEVICE_REMOVE     = 0x2,
    HDF_AUDIO_LOAD_SUCCESS      = 0x3,
    HDF_AUDIO_LOAD_FAILURE      = 0x4,
    HDF_AUDIO_UNLOAD            = 0x5,
    HDF_AUDIO_SERVICE_VALID     = 0x7,
    HDF_AUDIO_SERVICE_INVALID   = 0x8,
    HDF_AUDIO_CAPTURE_THRESHOLD = 0x9,
    HDF_AUDIO_EVENT_UNKOWN,
} EVENT_TYPE;

typedef enum AudioEventType EVENT_LOAD_TYPE;
typedef enum AudioEventType EVENT_SERVICE_TYPE;

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
    HDF_AUDIO_DEVICE_UNKOWN,
} DEVICE_TYPE;

struct AudioEvent {
    uint32_t eventType;
    uint32_t deviceType;
};

#endif /* AUDIO_EVENTS_H */
/** @} */
