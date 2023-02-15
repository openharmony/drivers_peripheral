/*
 * Copyright (c) 2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HDI_CODECDFXESERVICE_H
#define HDI_CODECDFXESERVICE_H

#include <hdf_remote_service.h>
#include "codec_adapter_interface.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t CleanMapperOfDiedService(struct HdfRemoteService *remote, uint32_t *comps, uint32_t *size);

bool RegisterService(struct CodecCallbackType *callbacks, uint32_t componentId, struct CodecComponentNode *codecNode);

void RemoveDestoryedComponent(uint32_t componentId);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // CODEC_DFX_SERVICE_H
