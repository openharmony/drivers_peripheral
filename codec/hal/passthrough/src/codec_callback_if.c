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

#include "codec_callback_if.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <osal_mem.h>

#define HDF_LOG_TAG codec_hdi_passthrough

static int32_t CodecCallbackTypeEventHandler(
    struct CodecCallbackType *self, enum OMX_EVENTTYPE eEvent, struct EventInfo *info)
{
    HDF_LOGI("%{public}s, callback service impl", __func__);
    return HDF_SUCCESS;
}

static int32_t CodecCallbackTypeEmptyBufferDone(
    struct CodecCallbackType *self, int64_t appData, const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("%{public}s, callback service impl", __func__);
    return HDF_SUCCESS;
}

static int32_t CodecCallbackTypeFillBufferDone(
    struct CodecCallbackType *self, int64_t appData, const struct OmxCodecBuffer *buffer)
{
    HDF_LOGI("%{public}s, callback service impl", __func__);
    return HDF_SUCCESS;
}

static void CodecCallbackTypeConstruct(struct CodecCallbackType *instance)
{
    instance->EventHandler = CodecCallbackTypeEventHandler;
    instance->EmptyBufferDone = CodecCallbackTypeEmptyBufferDone;
    instance->FillBufferDone = CodecCallbackTypeFillBufferDone;
}

struct CodecCallbackType *CodecCallbackTypeGet(struct HdfRemoteService *remote)
{
    struct CodecCallbackType *instance = (struct CodecCallbackType *)OsalMemAlloc(sizeof(struct CodecCallbackType));
    if (instance == NULL) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed!", __func__);
        return NULL;
    }
    CodecCallbackTypeConstruct(instance);
    return instance;
}

void CodecCallbackTypeRelease(struct CodecCallbackType *instance)
{
    if (instance == NULL) {
        HDF_LOGE("%{public}s: instance is null", __func__);
        return;
    }
    OsalMemFree(instance);
    instance = NULL;
}
