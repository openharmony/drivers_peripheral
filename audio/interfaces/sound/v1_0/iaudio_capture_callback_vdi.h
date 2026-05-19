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

#ifndef OHOS_VDI_AUDIO_V1_0_IAUDIOCAPTURECALLBACK_H
#define OHOS_VDI_AUDIO_V1_0_IAUDIOCAPTURECALLBACK_H

#include <stdbool.h>
#include <stdint.h>
#include "audio_types_vdi.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IAUDIO_CAPTURE_VDI_CALLBACK_MAJOR_VERSION 1
#define IAUDIO_CAPTURE_VDI_CALLBACK_MINOR_VERSION 0

struct IAudioCaptureCallbackVdi {
    int32_t (*CaptureCallback)(
        struct IAudioCaptureCallbackVdi *self,
        enum AudioCallbackTypeVdi type,
        int8_t *data, int8_t len);
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_VDI_AUDIO_V1_0_IAUDIOCAPTURECALLBACK_H */