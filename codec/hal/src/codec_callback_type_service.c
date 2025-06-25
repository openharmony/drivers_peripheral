/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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

#include "codec_callback_type_service.h"
#include <hdf_base.h>
#include "codec_log_wrapper.h"

static int32_t CodecCallbackTypeEventHandler(struct CodecCallbackType *self, enum OMX_EVENTTYPE eEvent,
                                             struct EventInfo *info)
{
    CODEC_LOGI("callback service impl");
    return HDF_SUCCESS;
}

static int32_t CodecCallbackTypeEmptyBufferDone(struct CodecCallbackType *self, int64_t appData,
                                                const struct OmxCodecBuffer *buffer)
{
    CODEC_LOGI("callback service impl");
    return HDF_SUCCESS;
}

static int32_t CodecCallbackTypeFillBufferDone(struct CodecCallbackType *self, int64_t appData,
                                               const struct OmxCodecBuffer *buffer)
{
    CODEC_LOGI("callback service impl");
    return HDF_SUCCESS;
}

void CodecCallbackTypeServiceConstruct(struct CodecCallbackType *instance)
{
    instance->EventHandler = CodecCallbackTypeEventHandler;
    instance->EmptyBufferDone = CodecCallbackTypeEmptyBufferDone;
    instance->FillBufferDone = CodecCallbackTypeFillBufferDone;
}
