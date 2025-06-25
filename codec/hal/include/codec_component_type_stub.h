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

#include <hdf_remote_service.h>
#include <hdf_sbuf.h>
#include "codec_component_if.h"
#include "codec_internal.h"
#include "codec_types.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct CodecComponentTypeStub {
    struct CodecComponentType interface;
    struct HdfRemoteService *remote;
    struct HdfRemoteDispatcher dispatcher;
};

bool CodecComponentTypeStubConstruct(struct CodecComponentTypeStub *stub);

void CodecComponentTypeStubRelease(struct CodecComponentTypeStub *stub);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // HDI_OMXCOMPONENTTYPESTUB_H