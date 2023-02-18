/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "audio_adapter_vendor.h"

#include <hdf_base.h>
#include <hdf_log.h>
#include "audio_uhdf_log.h"
#include "i_audio_adapter.h"
#include "osal_mem.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

struct AudioAdapterInfo {
    struct AudioHwiAdapter *hwiAdapter;
    struct IAudioAdapter *adapter;
};

struct AudioHwiAdapterPriv {
    struct AudioAdapterInfo adapterInfo[AUDIO_HW_ADAPTER_NUM_MAX];
};

static struct AudioHwiAdapterPriv g_AudioHwiManager;

static struct AudioHwiAdapterPriv *GetAudioHwiAdapterPriv(void)
{
    return &g_AudioHwiManager;
}

struct AudioHwiAdapter *AudioHwiGetHwiAdapterByDescIndex(uint32_t descIndex)
{
    struct AudioHwiAdapterPriv *priv = GetAudioHwiAdapterPriv();

    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("get hwiAdapter error, descIndex=%{public}d", descIndex);
        return NULL;
    }

    return priv->adapterInfo[descIndex].hwiAdapter;
}

struct AudioHwiAdapter *AudioHwiGetHwiAdapter(struct IAudioAdapter *adapter)
{
    struct AudioHwiAdapterPriv *priv = GetAudioHwiAdapterPriv();

    for (uint32_t i = 0; i < AUDIO_HW_ADAPTER_NUM_MAX; i++) {
        if (adapter == priv->adapterInfo[i].adapter) {
            return priv->adapterInfo[i].hwiAdapter;
        }
    }

    AUDIO_FUNC_LOGE("audio get hwiadapter fail");
    return NULL;
}

int32_t AudioHwiInitAllPorts(struct IAudioAdapter *adapter)
{
    struct AudioHwiAdapter *hwiAdapter = AudioHwiGetHwiAdapter(adapter);
    if (hwiAdapter == NULL) {
        AUDIO_FUNC_LOGE("audio hwiAdapter is null");
        return HDF_ERR_INVALID_PARAM;
    }

    if (hwiAdapter->InitAllPorts == NULL) {
        AUDIO_FUNC_LOGE("audio hwiAdapter InitAllPorts is null");
        return HDF_ERR_INVALID_PARAM;
    }

    int32_t ret = hwiAdapter->InitAllPorts(hwiAdapter);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio hwiAdapter InitAllPorts fail, ret=%{public}d", ret);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

static void AudioHwiInitAdapterInstance(struct IAudioAdapter *adapter)
{
    adapter->InitAllPorts = AudioHwiInitAllPorts;
}

struct IAudioAdapter *AudioHwiCreateAdapter(uint32_t descIndex, struct AudioHwiAdapter *hwiAdapter)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("create adapter error, descIndex=%{public}d", descIndex);
        return NULL;
    }

    if (hwiAdapter == NULL) {
        AUDIO_FUNC_LOGE("audio hwiAdapter is null");
        return NULL;
    }

    struct AudioHwiAdapterPriv *priv = GetAudioHwiAdapterPriv();
    struct IAudioAdapter *adapter = priv->adapterInfo[descIndex].adapter;
    if (adapter != NULL) {
        return adapter;
    }

    adapter = (struct IAudioAdapter *)OsalMemCalloc(sizeof(struct IAudioAdapter));
    if (adapter == NULL) {
        AUDIO_FUNC_LOGE("OsalMemCalloc adapter fail");
        return NULL;
    }

    AudioHwiInitAdapterInstance(adapter);

    priv->adapterInfo[descIndex].hwiAdapter = hwiAdapter;
    priv->adapterInfo[descIndex].adapter = adapter;

    return adapter;
}

void AudioHwiReleaseAdapter(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("adapter release fail descIndex=%{public}d", descIndex);
        return;
    }

    struct AudioHwiAdapterPriv *priv = GetAudioHwiAdapterPriv();

    OsalMemFree(priv->adapterInfo[descIndex].adapter);
    priv->adapterInfo[descIndex].adapter = NULL;
    priv->adapterInfo[descIndex].hwiAdapter = NULL;
}