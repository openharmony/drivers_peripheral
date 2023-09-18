/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HCS_CONFIG_PARAMS_HEADER_H
#define HCS_CONFIG_PARAMS_HEADER_H

#include <stdint.h>

struct HdfConfigStreamInfo {
    uint8_t id;
    const char* name;
};

struct HdfConfigSceneInfo {
    uint8_t id;
    const char* name;
};

struct HdfConfigRoot {
    const char* module;
    const struct HdfConfigStreamInfo* streamInfo;
    uint16_t streamInfoSize;
    const struct HdfConfigSceneInfo* sceneInfo;
    uint16_t sceneInfoSize;
};

#endif // HCS_CONFIG_PARAMS_HEADER_H
