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

#ifndef AUDIO_IF_LIB_COMMON_H
#define AUDIO_IF_LIB_COMMON_H

#include "audio_internal.h"

#define CTRL_NUM    100
#define CTRL_CMD    "control"   /* For Bind control service */

struct AudioPcmHwParams {
    enum AudioStreamType streamType;
    enum AudioFormat format;
    uint32_t channels;
    uint32_t rate;
    uint32_t periodSize;
    uint32_t periodCount;
    uint32_t period;
    uint32_t frameSize;
    uint32_t startThreshold;
    uint32_t stopThreshold;
    uint32_t silenceThreshold;
    bool isBigEndian;
    bool isSignedData;
    char *cardServiceName;
};
#endif /* AUDIO_IF_LIB_COMMON_H */
