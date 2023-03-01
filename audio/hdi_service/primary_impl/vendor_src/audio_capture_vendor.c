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

#include "audio_capture_vendor.h"

#include <hdf_base.h>
#include <limits.h>
#include "audio_common_vendor.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG    HDF_AUDIO_PRIMARY_IMPL

struct AudioCaptureInfo {
    struct AudioDeviceDescriptor desc;
    struct IAudioCapture *capture;
    struct AudioHwiCapture *hwiCapture;
};

struct AudioHwiCapturePriv {
    struct AudioCaptureInfo *captureInfos[AUDIO_HW_ADAPTER_NUM_MAX];
};

static struct AudioHwiCapturePriv g_audioHwiCapturePriv;

static struct AudioHwiCapturePriv *AudioHwiCaptureGetPriv(void)
{
    return &g_audioHwiCapturePriv;
}

struct AudioHwiCapture *AudioHwiGetHwiCapture(struct IAudioCapture *capture)
{
    if (capture == NULL) {
        AUDIO_FUNC_LOGE("audio HwiCapture get HwiCapture fail, capture null");
        return NULL;
    }

    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();

    for (uint32_t i = 0; i < AUDIO_HW_ADAPTER_NUM_MAX; i++) {
        if (priv->captureInfos[i] == NULL) {
            continue;
        }
        for (uint32_t j = 0; j < AUDIO_HW_STREAM_NUM_MAX; j++) {
            if (capture == priv->captureInfos[i][j].capture) {
                return priv->captureInfos[i][j].hwiCapture;
            }
        }
    }

    AUDIO_FUNC_LOGE("audio get capture fail");
    return NULL;
}

struct AudioHwiCapture *AudioHwiGetHwiCaptureByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc)
{
    if (desc == NULL) {
        AUDIO_FUNC_LOGE("audio HwiCapture get HwiCapture fail, desc null");
        return NULL;
    }

    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX || priv->captureInfos[descIndex] == NULL) {
        AUDIO_FUNC_LOGE("audio hwiCapture get hwiCapture fail, descIndex=%{public}d", descIndex);
        return NULL;
    }

    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((desc->portId == priv->captureInfos[descIndex][i].desc.portId) &&
            (desc->pins == priv->captureInfos[descIndex][i].desc.pins) &&
            (strcmp(desc->desc, priv->captureInfos[descIndex][i].desc.desc) == 0)) {
            return priv->captureInfos[descIndex][i].hwiCapture;
        }
    }

    AUDIO_FUNC_LOGE("audio get hwuCapture fail");
    return NULL;
}

int32_t AudioHwiCaptureFrame(struct IAudioCapture *capture, int8_t *frame, uint32_t *frameLen, uint64_t *replyBytes)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frame, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frameLen, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(replyBytes, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->CaptureFrame, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->CaptureFrame(hwiCapture, frame, *frameLen, replyBytes);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture frame fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiGetCapturePosition(struct IAudioCapture *capture, uint64_t *frames, struct AudioTimeStamp *time)
{
    CHECK_NULL_PTR_RETURN_VALUE(capture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(frames, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(time, HDF_ERR_INVALID_PARAM);

    struct AudioHwiCapture *hwiCapture = AudioHwiGetHwiCapture(capture);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(hwiCapture->GetCapturePosition, HDF_ERR_INVALID_PARAM);

    int32_t ret = hwiCapture->GetCapturePosition(hwiCapture, frames, (struct AudioHwiTimeStamp *)time);
    if (ret != HDF_SUCCESS) {
        AUDIO_FUNC_LOGE("audio capture get position fail, ret=%{pubilc}d", ret);
        return ret;
    }

    return HDF_SUCCESS;
}

int32_t AudioHwiCaptureGetVersion(struct IAudioCapture *capture, uint32_t *majorVer, uint32_t *minorVer)
{
    (void)capture;
    CHECK_NULL_PTR_RETURN_VALUE(majorVer, HDF_ERR_INVALID_PARAM);
    CHECK_NULL_PTR_RETURN_VALUE(minorVer, HDF_ERR_INVALID_PARAM);

    *majorVer = IAUDIO_CAPTURE_MAJOR_VERSION;
    *minorVer = IAUDIO_CAPTURE_MINOR_VERSION;

    return HDF_SUCCESS;
}

static void AudioHwiInitCaptureInstance(struct IAudioCapture *capture)
{
    capture->CaptureFrame = AudioHwiCaptureFrame;
    capture->GetCapturePosition = AudioHwiGetCapturePosition;
    capture->GetVersion = AudioHwiCaptureGetVersion;
}

int32_t AudioHwiCaptureInit(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiCapture init fail, descIndex=%{public}d", descIndex);
        return HDF_ERR_INVALID_PARAM;
    }

    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();
    if (priv->captureInfos[descIndex] != NULL) {
        AUDIO_FUNC_LOGW("audio HwiCapture captureInfos already init");
        return HDF_SUCCESS;
    }

    priv->captureInfos[descIndex] =
        (struct AudioCaptureInfo *)OsalMemCalloc(sizeof(struct AudioCaptureInfo) * AUDIO_HW_STREAM_NUM_MAX);
    if (priv->captureInfos[descIndex] == NULL) {
        AUDIO_FUNC_LOGE("audio HwiCapture malloc captureInfos fail");
        return HDF_ERR_MALLOC_FAIL;
    }

    return HDF_SUCCESS;
}

void AudioHwiCaptureDeinit(uint32_t descIndex)
{
    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiCapture deinit fail, descIndex=%{public}d", descIndex);
        return;
    }

    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();

    OsalMemFree((void *)priv->captureInfos[descIndex]);
    priv->captureInfos[descIndex] = NULL;
}

struct IAudioCapture *AudioHwiCreateCaptureByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc,
    struct AudioHwiCapture *hwiCapture)
{
    if (desc == NULL || hwiCapture == NULL) {
        AUDIO_FUNC_LOGE("audio capture is null");
        return NULL;
    }

    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiCapture create capture index fail, descIndex=%{public}d", descIndex);
        return NULL;
    }

    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();
    struct AudioCaptureInfo *infos = priv->captureInfos[descIndex];
    if (infos == NULL) {
        AUDIO_FUNC_LOGE("audio hwiCapture capture not init");
        return NULL;
    }

    uint32_t nullCaptureIndex = AUDIO_HW_STREAM_NUM_MAX;
    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((infos[i].capture != NULL) && (desc->portId == infos[i].desc.portId) &&
            (desc->pins == infos[i].desc.pins) && (strcmp(desc->desc, infos[i].desc.desc) == 0)) {
            return infos[i].capture;
        }

        if ((infos[i].capture == NULL) && (nullCaptureIndex == AUDIO_HW_STREAM_NUM_MAX)) {
            nullCaptureIndex = i;
        }
    }

    if (nullCaptureIndex == AUDIO_HW_STREAM_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiCapture capture not space");
        return NULL;
    }

    struct IAudioCapture *capture = (struct IAudioCapture *)OsalMemCalloc(sizeof(struct IAudioCapture));
    if (capture == NULL) {
        AUDIO_FUNC_LOGE("audio hwiCapture capture malloc fail");
        return NULL;
    }
    infos[nullCaptureIndex].capture = capture;
    infos[nullCaptureIndex].hwiCapture = hwiCapture;
    infos[nullCaptureIndex].desc.portId = desc->portId;
    infos[nullCaptureIndex].desc.pins = desc->pins;
    infos[nullCaptureIndex].desc.desc = strdup(desc->desc);
    AudioHwiInitCaptureInstance(capture);

    return capture;
};

void AudioHwiDestroyCaptureByDesc(uint32_t descIndex, const struct AudioDeviceDescriptor *desc)
{
    CHECK_NULL_PTR_RETURN(desc);

    if (descIndex >= AUDIO_HW_ADAPTER_NUM_MAX) {
        AUDIO_FUNC_LOGE("audio hwiCapture destroy capture index fail, descIndex=%{public}d", descIndex);
        return;
    }

    struct AudioHwiCapturePriv *priv = AudioHwiCaptureGetPriv();
    struct AudioCaptureInfo *infos = priv->captureInfos[descIndex];
    CHECK_NULL_PTR_RETURN(infos);

    for (uint32_t i = 0; i < AUDIO_HW_STREAM_NUM_MAX; i++) {
        if ((infos[i].capture != NULL) && (desc->portId == infos[i].desc.portId) &&
            (desc->pins == infos[i].desc.pins) && (strcmp(desc->desc, infos[i].desc.desc) == 0)) {
            OsalMemFree((void *)infos[i].capture);
            OsalMemFree((void *)infos[i].desc.desc);
            infos[i].capture = NULL;
            infos[i].hwiCapture = NULL;
            infos[i].desc.desc = NULL;
            infos[i].desc.portId = UINT_MAX;
            infos[i].desc.pins = PIN_NONE;
            return;
        }
    }
    AUDIO_FUNC_LOGE("audio hwiCapture not destroy capture by desc");
}