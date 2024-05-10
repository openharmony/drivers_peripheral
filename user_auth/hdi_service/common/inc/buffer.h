/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef COMMON_BUFFER_H
#define COMMON_BUFFER_H

#include <stdbool.h>
#include <stdint.h>
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *buf;
    uint32_t contentSize;
    uint32_t maxSize;
} Buffer;

bool IsBufferValid(const Buffer *buffer);
Buffer GetTmpBuffer(uint8_t *buf, uint32_t contentSize, uint32_t maxSize);
Buffer *CreateBufferBySize(const uint32_t size);
void DestoryBuffer(Buffer *buffer);
Buffer *CopyBuffer(const Buffer *buffer);
bool CompareBuffer(const Buffer *buffer1, const Buffer *buffer2);
Buffer *CreateBufferByData(const uint8_t *data, const uint32_t dataSize);
ResultCode GetBufferData(const Buffer *buffer, uint8_t *data, uint32_t *dataSize);
bool CheckBufferWithSize(const Buffer *buffer, const uint32_t size);
Buffer *MergeBuffers(const Buffer *buffer1, const Buffer *buffer2);

#ifdef __cplusplus
}
#endif

#endif
