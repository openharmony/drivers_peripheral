/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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

#ifndef HDI_OMXCOMPONENTTYPESTUB_H
#define HDI_OMXCOMPONENTTYPESTUB_H

#include "codec_component_if.h"
#include "codec_internal.h"
#include "codec_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct CodecComponentTypeStub {
    struct CodecComponentType service;
    struct OmxComponentManager managerService;
    void *dlHandler;
    OMX_HANDLETYPE componentHandle;
};

int32_t CodecComponentTypeServiceOnRemoteRequest(struct CodecComponentTypeStub *service,
    int32_t cmdId, struct HdfSBuf *data, struct HdfSBuf *reply);

struct CodecComponentTypeStub* CodecComponentTypeStubGetInstance(void);

void CodecComponentTypeStubRelease(struct CodecComponentTypeStub *instance);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // HDI_OMXCOMPONENTTYPESTUB_H