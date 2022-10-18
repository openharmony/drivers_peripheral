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

#ifndef COMMON_MSGPROC_H
#define COMMON_MSGPROC_H

#include <buffer_handle.h>
#include <hdf_sbuf.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

bool PackBufferHandle(struct HdfSBuf *data, BufferHandle *handle);
bool ParseBufferHandle(struct HdfSBuf *data, BufferHandle **handle);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // COMMON_MSGPROC_H
