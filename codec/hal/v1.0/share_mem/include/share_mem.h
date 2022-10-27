/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SHARE_MEM_H
#define SHARE_MEM_H

#include <hdf_base.h>
#include "codec_type.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
    int32_t id;
    int32_t fd;         /**< Transmit fd through ipc for sharing memory */
    int32_t size;
    uint8_t *virAddr;   /**< Virtual address */
    BufferType type;
} ShareMemory;

int32_t CreateFdShareMemory(ShareMemory *shareMemory);
int32_t OpenFdShareMemory(ShareMemory *shareMemory);
int32_t ReleaseFdShareMemory(ShareMemory *shareMemory);

#ifdef __cplusplus
}
#endif
#endif  // SHARE_MEM_H
