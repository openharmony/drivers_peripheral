/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef AUDIO_CAPTURE_VDI_H
#define AUDIO_CAPTURE_VDI_H

#include "iaudio_capture_vdi.h"
#include "v4_0/iaudio_capture.h"

struct IAudioCapture *AudioCreateCaptureByIdVdi(const struct AudioSampleAttributes *attrs, uint32_t *captureId,
    struct IAudioCaptureVdi *vdiCapture, const struct AudioDeviceDescriptor *desc);
void AudioDestroyCaptureByIdVdi(uint32_t captureId);
struct IAudioCaptureVdi *AudioGetVdiCaptureByIdVdi(uint32_t captureId);
uint32_t DecreaseCaptureUsrCount(uint32_t captureId);

#endif // AUDIO_CAPTURE_VDI_H
