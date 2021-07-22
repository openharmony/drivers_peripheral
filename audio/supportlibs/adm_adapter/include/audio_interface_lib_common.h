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

#ifndef AUDIO_INTERFACE_LIB_COMMON_H
#define AUDIO_INTERFACE_LIB_COMMON_H

#include "audio_interface_lib_render.h"
#include "audio_interface_lib_capture.h"

#define AUDIODRV_CTL_ELEM_IFACE_GAIN 2
#define AUDIO_MIN_DEVICENUM 1

struct HdfIoService *HdfIoServiceBindName(const char *serviceName);

#endif /* AUDIO_INTERFACE_LIB_COMMON_H */
