/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef HDI_CODEC_CALLBACK_CODECCALLBACK_H
#define HDI_CODEC_CALLBACK_CODECCALLBACK_H
#include "codec_type.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CODEC_CALLBACK_DESC "ohos.hdi.codec_callback_service"

struct HdfRemoteService;

enum {
    CMD_CODEC_ON_EVENT,
    CMD_CODEC_INPUT_BUFFER_AVAILABLE,
    CMD_CODEC_OUTPUT_BUFFER_AVAILABLE,
};

struct ICodecCallback {
    struct HdfRemoteService *remote;
    CodecCallback callback;
};

struct ICodecCallbackProxy {
    struct HdfRemoteService *remote;
    int32_t (*OnEvent)(struct ICodecCallbackProxy *self, UINTPTR userData,
        EventType event, uint32_t length, int32_t eventData[]);
    int32_t (*InputBufferAvailable)(struct ICodecCallbackProxy *self, UINTPTR userData,
        CodecBuffer *inBuf, int32_t *acquireFd);
    int32_t (*OutputBufferAvailable)(struct ICodecCallbackProxy *self, UINTPTR userData,
        CodecBuffer *outBuf, int32_t *acquireFd);
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // HDI_CODEC_CALLBACK_CODECCALLBACK_H