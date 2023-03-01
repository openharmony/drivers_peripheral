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

#include "audio_render_vendor.h"

#include <hdf_base.h>
#include <limits.h>
#include "audio_common_vendor.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

struct AudioRenderInfo {
    struct AudioDeviceDescriptor desc;
    struct IAudioRender *render;
    struct AudioHwiRender *hwiRender;
};

struct AudioHwiRenderPriv {
    struct AudioRenderInfo *renderInfos[AUDIO_HW_ADAPTER_NUM_MAX];
    struct IAudioCallback *callback;
    int8_t cookie;
    bool isRegCb;
};

static struct AudioHwiRenderPriv g_audioHwiRenderPriv;

static struct AudioHwiRenderPriv *AudioHwiRenderGetPriv(void)
{
    return &g_audioHwiRenderPriv;
}

struct AudioHwiRender *AudioHwiGetHwiRender(struct IAudioRender *render)
{
    if (render == NULL) {
        AUDIO_FUNC_LOGE("audio render desc null");
        return NULL;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    for (uint32_t i = 0; i < AUDIO_HW_ADAPTER_NUM_MAX; i++) {
        if (priv->renderInfos[i] == NULL) {
            continue;
        }
        for (uint32_t j = 0; j < AUDIO_HW_STREAM_NUM_MAX; j++) {
            if (render == priv->renderInfos[i][j].render) {
                return priv->renderInfos[i][j].hwiRender;
            }
        }
    }

    AUDIO_FUNC_LOGE("audio get render fail");
    return NULL;
}

struct AudioHwiRender *AudioHwiGetHwiRenderByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc)
{
    if (desc == NULL) {
        AUDIO_FUNC_LOGE("audio render get hwiRender fail, desc null");
        return NULL;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX || priv->renderInfos[descIndex] == NULL) {
        AUDIO_FUNC_LOGE("audio render get hwiRender fail, descIndex=%{public}d", descIndex);
        return NULL;
    }

    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((desc->portId == priv->renderInfos[descIndex][i].desc.portId) &&
            (desc->pins == priv->renderInfos[descIndex][i].desc.pins) &&
            (strcmp(desc->desc, priv->renderInfos[descIndex][i].desc.desc) == 0)) {
            return priv->renderInfos[descIndex][i].hwiRender;
        }
    }

    AUDIO_FUNC_LOGE("audio get hwiRender fail");
    return NULL;
}

int32_t AudioHwiGetLatency(struct IAudioRender *render, uint32_t *ms)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(ms, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->GetLatency, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->GetLatency(hwiRender, ms);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio GetLatency fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderFrame(struct IAudioRender *render, const int8_t *frame, uint32_t frameLen, uint64_t *replyBytes)
{
    CHECK_NULL_PTR_RETURN_VALUE(render, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frame, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(replyBytes, HDF_ERR_INVALID_PARAM);

    struct AudioHwiRender *hwiRender = AudioHwiGetHwiRender(render);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiRender->RenderFrame, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiRender->RenderFrame(hwiRender, frame, frameLen, replyBytes);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio render frame fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiRenderGetVersion(struct IAudioRender *render, uint32_t *majorVer, uint32_t *minorVer)
{
    (void)render;
    CHECK_NULL_PTR_RETURN_VALUE(majorVer, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(minorVer, HDF_ERR_INVALID_PARAM);

    *majorVer = IAUDIO_RENDER_MAJOR_VERSION;
    *minorVer = IAUDIO_RENDER_MINOR_VERSION;

    return HDF_SUCCESS;
}

static void AudioHwiInitRenderInstance(struct IAudioRender *render)
{
    render->GetLatency = AudioHwiGetLatency;
    render->RenderFrame = AudioHwiRenderFrame;
    render->GetVersion = AudioHwiRenderGetVersion;
}

int32_t AudioHwiRenderInit(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender init fail, descIndex=%{public}d", descIndex);
        return HDF_ERR_INVALID_PARAM;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    if (priv->renderInfos[descIndex] != NULL) {
        AUDIO_FUNC_LOGW("audio HwiRender renderInfos already init");
        return HDF_SUCCESS;
    }

    priv->renderInfos[descIndex] =
        (struct AudioRenderInfo *)OsalMemCalloc(sizeof(struct AudioRenderInfo) * AUDIO_HW_STREAM_NUM_MAX);
    if (priv->renderInfos[descIndex] == NULL) {
        AUDIO_FUNC_LOGE("audio HwiRender malloc renderInfos fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    return HDF_SUCCESS;
}

void AudioHwiRenderDeinit(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender deinit fail, descIndex=%{public}d", descIndex);
        return;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();

    OsalMemFree((void *)priv->renderInfos[descIndex]);
    priv->renderInfos[descIndex] = NULL;
}

struct IAudioRender *AudioHwiCreateRenderByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc,
    struct AudioHwiRender *hwiRender)
{
    if (desc == NULL || hwiRender == NULL) {
        AUDIO_FUNC_LOGE("audio render is null");
        return NULL;
    }

    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender create render index fail, descIndex=%{public}d", descIndex);
        return NULL;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    struct AudioRenderInfo *infos = priv->renderInfos[descIndex];
    if (infos == NULL) {
        AUDIO_FUNC_LOGE("audio hwiRender render not init");
        return NULL;
    }

    uint32_t nullRenderIndex = AUDIO_HW_STREAM_NUM_MAX;
    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((infos[i].render != NULL) && (desc->portId == infos[i].desc.portId) && (desc->pins == infos[i].desc.pins) &&
            (strcmp(desc->desc, infos[i].desc.desc) == 0)) {
            return infos[i].render;
        }

        if ((infos[i].render == NULL) && (nullRenderIndex == AUDIO_HW_STREAM_NUM_MAX)) {
            nullRenderIndex = i;
        }
    }

    if (nullRenderIndex == AUDIO_HW_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender render not space");
        return NULL;
    }

    struct IAudioRender *render = (struct IAudioRender *)OsalMemCalloc(sizeof(struct IAudioRender));
    if (render == NULL) {
        AUDIO_FUNC_LOGE("audio hwiRender render malloc fail");
        return NULL;
    }
    infos[nullRenderIndex].render = render;
    infos[nullRenderIndex].hwiRender = hwiRender;
    infos[nullRenderIndex].desc.portId = desc->portId;
    infos[nullRenderIndex].desc.pins = desc->pins;
    infos[nullRenderIndex].desc.desc = strdup(desc->desc);
    AudioHwiInitRenderInstance(render);

    return render;
};

void AudioHwiDestroyRenderByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc)
{
    CHECK_NULL_PTR_RETURN(desc);

    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiRender destroy render index fail, descIndex=%{public}d", descIndex);
        return;
    }

    struct AudioHwiRenderPriv *priv = AudioHwiRenderGetPriv();
    struct AudioRenderInfo *infos = priv->renderInfos[descIndex];
    CHECK_NULL_PTR_RETURN(infos);

    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((infos[i].render != NULL) && (desc->portId == infos[i].desc.portId) && (desc->pins == infos[i].desc.pins) &&
            (strcmp(desc->desc, infos[i].desc.desc) == 0)) {
            OsalMemFree((void *)infos[i].render);
            OsalMemFree((void *)infos[i].desc.desc);
            infos[i].render = NULL;
            infos[i].hwiRender = NULL;
            infos[i].desc.desc = NULL;
            infos[i].desc.portId = UINT_MAX;
            infos[i].desc.pins = PIN_NONE;
            return;
        }
    }
    AUDIO_FUNC_LOGE("audio hwiRender not destroy render by desc");
}
