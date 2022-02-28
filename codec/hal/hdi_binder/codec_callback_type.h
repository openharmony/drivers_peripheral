/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CODEC_CALLBACK_TYPE_H
#define CODEC_CALLBACK_TYPE_H

#include <stdint.h>
#include "codec_types.h"
#include "codec_component_type.h"
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum {
    CMD_EVENT_HANDLER,
    CMD_EMPTY_BUFFER_DONE,
    CMD_FILL_BUFFER_DONE,
};

struct CodecCallbackType {
    struct HdfRemoteService *remote;

    int32_t (*EventHandler)(struct CodecCallbackType *self, int8_t *appData, uint32_t appDataLen,
        enum OMX_EVENTTYPE eEvent, uint32_t data1, uint32_t data2, int8_t *eventData, uint32_t eventDataLen);

    int32_t (*EmptyBufferDone)(struct CodecCallbackType *self, int8_t *appData,
        uint32_t appDataLen, const struct OmxCodecBuffer *buffer);

    int32_t (*FillBufferDone)(struct CodecCallbackType *self, int8_t* appData,
        uint32_t appDataLen, struct OmxCodecBuffer* buffer);
};

struct CodecCallbackType *CodecCallbackTypeGet(struct HdfRemoteService *remote);

void CodecCallbackTypeRelease(struct CodecCallbackType *instance);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // CODEC_CALLBACK_TYPE_H