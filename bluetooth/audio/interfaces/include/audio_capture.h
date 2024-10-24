/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 * @file audio_capture.h
 *
 * @brief Declares APIs for audio capturing.
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef AUDIO_CAPTURE_H
#define AUDIO_CAPTURE_H

#include "audio_control.h"
#include "audio_volume.h"
namespace OHOS::HDI::Audio_Bluetooth {
/**
 * @brief Provides capabilities for audio capturing, including controlling the capturing, setting audio attributes,
 * scenes, and volume, obtaining hardware latency, and capturing audio frames.
 *
 * @see AudioControl
 * @see AudioAttribute
 * @since 1.0
 * @version 1.0
 */
struct AudioRender {
    /**
     * @brief Defines the audio control. For details, see {@link AudioControl}.
     */
    struct AudioControl control;
    /**
     * @brief Defines audio volume. For details, see {@link AudioVolume}.
     */
    struct AudioVolume volume;

    /**
     * @brief Reads a frame of intput data (uplink data) into the audio driver for capturing.
     *
     * @param capture Indicates the pointer to the <b>AudioCapture</b> object to operate.
     * @param frame Indicates the pointer to the frame to read.
     * @param requestBytes Indicates the size of the frame, in bytes.
     * @param replyBytes Indicates the pointer to the actual length (in bytes) of the audio data to read.
     * @return Returns <b>0</b> if the data is read successfully; returns a negative value otherwise.
     */
    int32_t (*CaptureFrame)(struct AudioCapture *capture, void *frame, uint64_t requestBytes, uint64_t *replyBytes);
}
#endif
