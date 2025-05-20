/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef AUDIO_PATHSELECT_H
#define AUDIO_PATHSELECT_H

#include "audio_internal.h"
#ifdef IDL_MODE
#include "v5_0/audio_types.h"
#else
#include "audio_types.h"
#endif

#ifdef ALSA_LIB_MODE
    #define CJSONFILE_CONFIG_PATH HDF_CONFIG_DIR"/alsa_paths.json"
#else
    #define CJSONFILE_CONFIG_PATH HDF_CONFIG_DIR"/audio_paths.json"
#endif

int32_t AudioPathSelGetConfToJsonObj(void);
int32_t AudioPathSelAnalysisJson(const AudioHandle adapterParam, enum AudioAdaptType adaptType);

#endif
