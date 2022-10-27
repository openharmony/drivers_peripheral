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

#ifndef DISPLAY_GRALLOC_WRAPPER_H
#define DISPLAY_GRALLOC_WRAPPER_H

#include "share_mem.h"

#ifdef __cplusplus
extern "C"
{
#endif

int32_t GrAllocatorInit(void);
int32_t CreateGrShareMemory(BufferHandle **bufferHandle, AllocInfo *alloc, ShareMemory *shareMemory);
int32_t DestroyGrShareMemory(BufferHandle *bufferHandle);
int32_t OpenGrShareMemory(BufferHandle *bufferHandle, ShareMemory *shareMemory);
int32_t ReleaseGrShareMemory(BufferHandle *bufferHandle, ShareMemory *shareMemory);

#ifdef __cplusplus
}
#endif

#endif  // DISPLAY_GRALLOC_WRAPPER_H
