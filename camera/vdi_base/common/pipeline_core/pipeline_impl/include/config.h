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

#ifndef HCS_CONFIG_CONFIG_HEADER_H
#define HCS_CONFIG_CONFIG_HEADER_H

#include <stdint.h>

struct HdfConfigPipelineSpecsPortSpec {
    const char* name;
    const char* peerPortName;
    const char* peerPortNodeName;
    uint8_t direction;
    uint8_t width;
    uint8_t height;
    uint8_t format;
    uint64_t usage;
    uint8_t needAllocation;
    uint8_t bufferCount;
};

struct HdfConfigPipelineSpecsNodeSpec {
    const char* name;
    const char* status;
    const char* streamType;
    const struct HdfConfigPipelineSpecsPortSpec* portSpec;
    uint16_t portSpecSize;
};

struct HdfConfigPipelineSpecsPipelineSpec {
    const char* name;
    const struct HdfConfigPipelineSpecsNodeSpec* nodeSpec;
    uint16_t nodeSpecSize;
};

struct HdfConfigPipelineSpecsRoot {
    const char* module;
    const struct HdfConfigPipelineSpecsPipelineSpec* pipelineSpec;
    uint16_t pipelineSpecSize;
};

#endif // HCS_CONFIG_CONFIG_HEADER_H
