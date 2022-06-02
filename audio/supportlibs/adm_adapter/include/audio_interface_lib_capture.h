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

#include "audio_if_lib_capture.h"
#include "audio_interface_lib_common.h"

#ifdef __cplusplus
extern "C" {
#endif

enum AudioCriBuffStatusCapture {
    CIR_BUFF_NORMAL = 1,
    CIR_BUFF_EMPTY = 3,
};

#ifdef __cplusplus
}
#endif
#endif /* AUDIO_INTERFACE_LIB_CAPTURE_H */
