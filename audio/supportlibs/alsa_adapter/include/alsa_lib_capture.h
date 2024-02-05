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

#ifndef ALSA_LIB_CAPTURE_H
#define ALSA_LIB_CAPTURE_H

#include "alsa_lib_common.h"
#include "audio_if_lib_capture.h"
#ifdef NON_STANDARD_CODEC
enum DataBitWidth {
    DATA_BIT_WIDTH8  =  8,      /* 8 bit witdth */
    DATA_BIT_WIDTH16 =  16,     /* 16 bit witdth */
    DATA_BIT_WIDTH18 =  18,     /* 18 bit witdth */
    DATA_BIT_WIDTH20 =  20,     /* 20 bit witdth */
    DATA_BIT_WIDTH24 =  24,     /* 24 bit witdth */
    DATA_BIT_WIDTH32 =  32,     /* 32 bit witdth */
};
#endif

#endif /* ALSA_LIB_CAPTURE_H */
