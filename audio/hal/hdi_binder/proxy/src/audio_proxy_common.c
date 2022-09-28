/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "audio_proxy_common.h"
#include <servmgr_hdi.h>
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_PROXY

#define AUDIO_HDF_SBUF_IPC 1
#define PROXY_VOLUME_CHANGE 100

struct HdfSBuf *AudioProxyObtainHdfSBuf(void)
{
    enum HdfSbufType bufType;
#ifdef AUDIO_HDF_SBUF_IPC
    bufType = SBUF_IPC;
#else
    bufType = SBUF_RAW;
#endif
    return HdfSbufTypedObtain(bufType);
}

int32_t AudioProxyDispatchCall(struct HdfRemoteService *self,
    int32_t id, struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data == NULL || reply == NULL || self == NULL) {
        AUDIO_FUNC_LOGE("AudioProxyDispatchCall parameter is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (self->dispatcher == NULL || self->dispatcher->Dispatch == NULL) {
        AUDIO_FUNC_LOGE("AudioProxyDispatchCall Remote obj is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return self->dispatcher->Dispatch(self, id, data, reply);
}

int32_t AudioProxyAdapterGetRemoteHandle(struct AudioProxyManager *proxyManager, struct AudioHwAdapter *hwAdapter,
    const char *adapterName)
{
    if (proxyManager == NULL || hwAdapter == NULL || adapterName == NULL) {
        AUDIO_FUNC_LOGE("AudioProxyAdapterGetRemoteHandle parameter is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (strncmp(adapterName, PRIMARY, strlen(PRIMARY)) == 0) {
        hwAdapter->proxyRemoteHandle = proxyManager->remote;
    } else if (strncmp(adapterName, USB, strlen(USB)) == 0) {
        hwAdapter->proxyRemoteHandle = proxyManager->usbRemote;
    } else if (strncmp(adapterName, A2DP, strlen(A2DP)) == 0) {
        hwAdapter->proxyRemoteHandle = proxyManager->a2dpRemote;
    } else {
        AUDIO_FUNC_LOGE("Remote not found!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

void AudioProxyBufReplyRecycle(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    if (data != NULL) {
        HdfSbufRecycle(data);
    }
    if (reply != NULL) {
        HdfSbufRecycle(reply);
    }
    return;
}

int32_t AudioProxyPreprocessSBuf(struct HdfSBuf **data, struct HdfSBuf **reply)
{
    if (data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    *data = AudioProxyObtainHdfSBuf();
    if (*data == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain data");
        return HDF_FAILURE;
    }
    *reply = AudioProxyObtainHdfSBuf();
    if (*reply == NULL) {
        AUDIO_FUNC_LOGE("Failed to obtain reply");
        HdfSbufRecycle(*data);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyPreprocessRender(struct AudioHwRender *render, struct HdfSBuf **data, struct HdfSBuf **reply)
{
    struct AudioHwRender *hwRender = render;
    if (hwRender == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint32_t renderPid = (uint32_t)getpid();
    const char *adapterName = hwRender->renderParam.renderMode.hwInfo.adapterName;
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("adapterName is NULL");
        return HDF_FAILURE;
    }
    if (AudioProxyPreprocessSBuf(data, reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(render->proxyRemoteHandle, *data)) {
        AUDIO_FUNC_LOGE("write interface token failed");
        AudioProxyBufReplyRecycle(*data, *reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteString(*data, adapterName)) {
        AUDIO_FUNC_LOGE("write adapterName failed");
        AudioProxyBufReplyRecycle(*data, *reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(*data, renderPid)) {
        AUDIO_FUNC_LOGE("write renderPid failed");
        AudioProxyBufReplyRecycle(*data, *reply);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyPreprocessCapture(struct AudioHwCapture *capture, struct HdfSBuf **data, struct HdfSBuf **reply)
{
    struct AudioHwCapture *hwCapture = capture;
    if (hwCapture == NULL || data == NULL || reply == NULL) {
        return HDF_FAILURE;
    }
    uint32_t capturePid = (uint32_t)getpid();
    const char *adapterName = hwCapture->captureParam.captureMode.hwInfo.adapterName;
    if (adapterName == NULL) {
        AUDIO_FUNC_LOGE("The pointer is null");
        return HDF_FAILURE;
    }
    if (AudioProxyPreprocessSBuf(data, reply) < 0) {
        return HDF_FAILURE;
    }
    if (!HdfRemoteServiceWriteInterfaceToken(capture->proxyRemoteHandle, *data)) {
        AUDIO_FUNC_LOGE("write interface token failed");
        AudioProxyBufReplyRecycle(*data, *reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteString(*data, adapterName)) {
        AUDIO_FUNC_LOGE("write adapterName failed");
        AudioProxyBufReplyRecycle(*data, *reply);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(*data, capturePid)) {
        AUDIO_FUNC_LOGE("write capturePid failed");
        AudioProxyBufReplyRecycle(*data, *reply);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyWriteSampleAttributes(struct HdfSBuf *data, const struct AudioSampleAttributes *attrs)
{
    if (data == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("data or attrs is null!");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)attrs->type)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)attrs->interleaved)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)attrs->format)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->sampleRate)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->channelCount)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->period)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->frameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)(attrs->isBigEndian))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)(attrs->isSignedData))) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->startThreshold)) {
        AUDIO_FUNC_LOGE("write startThreshold failed");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->stopThreshold)) {
        AUDIO_FUNC_LOGE("write stopThreshold failed");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, attrs->silenceThreshold)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyReadSapmleAttrbutes(struct HdfSBuf *reply, struct AudioSampleAttributes *attrs)
{
    if (reply == NULL || attrs == NULL) {
        AUDIO_FUNC_LOGE("reply or attrs is null!");
        return HDF_FAILURE;
    }
    uint32_t tempType = 0;
    if (!HdfSbufReadUint32(reply, &tempType)) {
        return HDF_FAILURE;
    }
    attrs->type = (enum AudioCategory)tempType;
    uint32_t tempInterleaved = 0;
    if (!HdfSbufReadUint32(reply, &tempInterleaved)) {
        return HDF_FAILURE;
    }
    attrs->interleaved = (bool)tempInterleaved;
    uint32_t tempFormat = 0;
    if (!HdfSbufReadUint32(reply, &tempFormat)) {
        return HDF_FAILURE;
    }
    attrs->format = (enum AudioFormat)tempFormat;
    if (!HdfSbufReadUint32(reply, &attrs->sampleRate)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &attrs->channelCount)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &attrs->period)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &attrs->frameSize)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &tempInterleaved)) {
        return HDF_FAILURE;
    }
    attrs->isBigEndian = (bool)tempInterleaved;
    if (!HdfSbufReadUint32(reply, &tempInterleaved)) {
        return HDF_FAILURE;
    }
    attrs->isSignedData = (bool)tempInterleaved;
    if (!HdfSbufReadUint32(reply, &attrs->startThreshold) ||
        !HdfSbufReadUint32(reply, &attrs->stopThreshold) ||
        !HdfSbufReadUint32(reply, &attrs->silenceThreshold)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyCommonSetRenderCtrlParam(int cmId, AudioHandle handle, float param)
{
    AUDIO_FUNC_LOGI();
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)handle;
    if (hwRender == NULL || hwRender->proxyRemoteHandle == NULL) {
        AUDIO_FUNC_LOGE("The hwRender parameter is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (param < 0) {
        AUDIO_FUNC_LOGE("Set param is invalid, Please check param!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (cmId == AUDIO_HDI_RENDER_SET_VOLUME) {
        if (param > 1.0) {
            AUDIO_FUNC_LOGE("volume param Is error!");
            return AUDIO_HAL_ERR_INVALID_PARAM;
        }
        param = param * PROXY_VOLUME_CHANGE;
    }
    if (AudioProxyPreprocessRender(hwRender, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    uint32_t tempParam = (uint32_t)param;
    if (!HdfSbufWriteUint32(data, tempParam)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioProxyDispatchCall(hwRender->proxyRemoteHandle, cmId, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCommonGetRenderCtrlParam(int cmId, AudioHandle handle, float *param)
{
    AUDIO_FUNC_LOGI();
    if (param == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    struct AudioHwRender *hwRender = (struct AudioHwRender *)handle;
    if (hwRender == NULL || hwRender->proxyRemoteHandle == NULL) {
        AUDIO_FUNC_LOGE("The pointer is empty");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessRender(hwRender, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioProxyDispatchCall(hwRender->proxyRemoteHandle, cmId, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    uint32_t tempParam = 0;
    if (!HdfSbufReadUint32(reply, &tempParam)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (cmId == AUDIO_HDI_RENDER_GET_VOLUME) {
        *param = (float)tempParam / PROXY_VOLUME_CHANGE;
    } else {
        *param = (float)tempParam;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyCommonSetCaptureCtrlParam(int cmId, AudioHandle handle, float param)
{
    AUDIO_FUNC_LOGI();
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || hwCapture->proxyRemoteHandle == NULL) {
        AUDIO_FUNC_LOGE("The hwCapture parameter is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (param < 0) {
        AUDIO_FUNC_LOGE("Set param is invalid, Please check param!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (cmId == AUDIO_HDI_CAPTURE_SET_VOLUME) {
        if (param > 1.0) {
            AUDIO_FUNC_LOGE("volume param Is error!");
            return AUDIO_HAL_ERR_INVALID_PARAM;
        }
        param = param * PROXY_VOLUME_CHANGE;
    }
    if (AudioProxyPreprocessCapture(hwCapture, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    uint32_t tempParam = (uint32_t)param;
    if (!HdfSbufWriteUint32(data, tempParam)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioProxyDispatchCall(hwCapture->proxyRemoteHandle, cmId, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCommonGetCaptureCtrlParam(int cmId, AudioHandle handle, float *param)
{
    AUDIO_FUNC_LOGI();
    if (param == NULL) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct HdfSBuf *data = NULL;
    struct HdfSBuf *reply = NULL;
    struct AudioHwCapture *hwCapture = (struct AudioHwCapture *)handle;
    if (hwCapture == NULL || hwCapture->proxyRemoteHandle == NULL) {
        AUDIO_FUNC_LOGE("The hwCapture parameter is invalid");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessCapture(hwCapture, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    int32_t ret = AudioProxyDispatchCall(hwCapture->proxyRemoteHandle, cmId, data, reply);
    if (ret < 0) {
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    uint32_t tempParam = 0;
    if (!HdfSbufReadUint32(reply, &tempParam)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (cmId == AUDIO_HDI_CAPTURE_GET_VOLUME) {
        *param = (float)tempParam / PROXY_VOLUME_CHANGE;
    } else {
        *param = (float)tempParam;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}

int32_t AudioProxyGetMmapPositionRead(struct HdfSBuf *reply, uint64_t *frames, struct AudioTimeStamp *time)
{
    if (reply == NULL || frames == NULL || time == NULL) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint64(reply, frames)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt64(reply, &time->tvSec)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt64(reply, &time->tvNSec)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t AudioProxyReqMmapBufferWrite(struct HdfSBuf *data, int32_t reqSize,
    const struct AudioMmapBufferDescripter *desc)
{
    if (data == NULL || desc == NULL) {
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(data, reqSize)) {
        AUDIO_FUNC_LOGE("write reqSize failed");
        return HDF_FAILURE;
    }
    uint64_t memAddr = (uint64_t)(uintptr_t)desc->memoryAddress;
    if (!HdfSbufWriteUint64(data, memAddr)) {
        AUDIO_FUNC_LOGE("write memoryAddress failed");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteFileDescriptor(data, desc->memoryFd)) {
        AUDIO_FUNC_LOGE("write memoryFd failed");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(data, desc->totalBufferFrames)) {
        AUDIO_FUNC_LOGE("write totalBufferFrames failed");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(data, desc->transferFrameSize)) {
        AUDIO_FUNC_LOGE("write transferFrameSize failed");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(data, desc->isShareable)) {
        AUDIO_FUNC_LOGE("write isShareable failed");
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, desc->offset)) {
        AUDIO_FUNC_LOGE("write offset failed");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static bool AudioDevExtInfoBlockMarshalling(struct HdfSBuf *data, const struct AudioDevExtInfo *dataBlock)
{
    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf or data block", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, dataBlock->moduleId)) {
        HDF_LOGE("%{public}s: write dataBlock->moduleId failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->type)) {
        HDF_LOGE("%{public}s: write dataBlock->type failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteString(data, dataBlock->desc)) {
        HDF_LOGE("%{public}s: write dataBlock->desc failed!", __func__);
        return false;
    }

    return true;
}

static bool AudioMixExtInfoBlockMarshalling(struct HdfSBuf *data, const struct AudioMixExtInfo *dataBlock)
{
    if (data == NULL || dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf or data block", __func__);
        return false;
    }

    if (!HdfSbufWriteUnpadBuffer(data, (const uint8_t *)dataBlock, sizeof(struct AudioMixExtInfo))) {
        HDF_LOGE("%{public}s: failed to write buffer data", __func__);
        return false;
    }
    return true;
}

static bool AudioSessionExtInfoBlockMarshalling(struct HdfSBuf *data, const struct AudioSessionExtInfo *dataBlock)
{
    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf or data block", __func__);
        return false;
    }

    if (!HdfSbufWriteUnpadBuffer(data, (const uint8_t *)dataBlock, sizeof(struct AudioSessionExtInfo))) {
        HDF_LOGE("%{public}s: failed to write buffer data", __func__);
        return false;
    }
    return true;
}

static inline bool AudioInfoBlockMarshalling(enum AudioPortType type, struct HdfSBuf *data, RouteExtInfo *dataBlock)
{
    if (data == NULL || dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf or data block", __func__);
        return false;
    }
    bool ret = true;
    switch (type) {
        case AUDIO_PORT_DEVICE_TYPE:
            if (!AudioDevExtInfoBlockMarshalling(data, &dataBlock->device)) {
                HDF_LOGE("%{public}s: write dataBlock->device failed!", __func__);
                ret = false;
            }
            break;
        case AUDIO_PORT_MIX_TYPE:
            if (!AudioMixExtInfoBlockMarshalling(data, &dataBlock->mix)) {
                HDF_LOGE("%{public}s: write dataBlock->mix failed!", __func__);
                ret = false;
            }
            break;
        case AUDIO_PORT_SESSION_TYPE:
            if (!AudioSessionExtInfoBlockMarshalling(data, &dataBlock->session)) {
                HDF_LOGE("%{public}s: write dataBlock->session failed!", __func__);
                ret = false;
            }
            break;
        case AUDIO_PORT_UNASSIGNED_TYPE:
        default:
            ret = false;
            break;
    }

    return ret;
}

static bool AudioRouteNodeBlockMarshalling(struct HdfSBuf *data, const struct AudioRouteNode *dataBlock)
{
    if (data == NULL || dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf or data block", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, dataBlock->portId)) {
        HDF_LOGE("%{public}s: write dataBlock->portId failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->role)) {
        HDF_LOGE("%{public}s: write dataBlock->role failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->type)) {
        HDF_LOGE("%{public}s: write dataBlock->type failed!", __func__);
        return false;
    }

    if (!AudioInfoBlockMarshalling(dataBlock->type, data, (RouteExtInfo*)&dataBlock->ext)) {
        HDF_LOGE("%{public}s: write dataBlock->ext failed!", __func__);
        return false;
    }

    return true;
}

bool AudioRouteBlockMarshalling(struct HdfSBuf *data, const struct AudioRoute *dataBlock)
{
    if (data == NULL || dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf or data block", __func__);
        return false;
    }

    if (!HdfSbufWriteUint32(data, dataBlock->sourcesNum)) {
        HDF_LOGE("%{public}s: write dataBlock->sourcesLen failed!", __func__);
        return false;
    }
    for (uint32_t i = 0; i < dataBlock->sourcesNum; i++) {
        if (!AudioRouteNodeBlockMarshalling(data, &(dataBlock->sources)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->sources)[i] failed!", __func__);
            return false;
        }
    }

    if (!HdfSbufWriteUint32(data, dataBlock->sinksNum)) {
        HDF_LOGE("%{public}s: write dataBlock->sinksLen failed!", __func__);
        return false;
    }
    for (uint32_t i = 0; i < dataBlock->sinksNum; i++) {
        if (!AudioRouteNodeBlockMarshalling(data, &(dataBlock->sinks)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->sinks)[i] failed!", __func__);
            return false;
        }
    }
    return true;
}