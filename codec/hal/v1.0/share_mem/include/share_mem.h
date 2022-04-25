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

#ifdef __cplusplus
extern "C"
{
#endif

#define STREAM_PACKET_BUFFER_NUM    4
#define MEDIA_FRAME_BUFFER_NUM      10

#define MEM_NAME_LEN    128

typedef struct {
    char memName[MEM_NAME_LEN];
    int32_t id;
    int32_t fd;             /**< Transmit fd through ipc for sharing memory */
    int32_t size;
    uint8_t *virAddr;   /**< Virtual address */
} ShareMemory;

int32_t CreateShareMemory(ShareMemory *shareMemory);
int32_t OpenShareMemory(ShareMemory *shareMemory);
int32_t ReleaseShareMemory(ShareMemory *shareMemory);

#ifdef __cplusplus
}
#endif
#endif  // SHARE_MEM_H
