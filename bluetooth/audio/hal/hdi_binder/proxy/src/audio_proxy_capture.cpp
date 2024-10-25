/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <cinttypes>
#include <hdf_log.h>
#include "audio_proxy_common.h"

namespace OHOS::HDI::Audio_Bluetooth {
int32_t AudioProxyCaptureCtrl(int cmId, AudioHandle handle)
{
    struct HdfSBuf *data = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct AudioHwCapture *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == nullptr || hwCapture->proxyRemoteHandle == nullptr) {
        HDF_LOGE("The hwCapture parameter is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessCapture(hwCapture, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioProxyDispatchCall(hwCapture->proxyRemoteHandle, cmId, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCaptureStart(AudioHandle handle)
{
    HDF_LOGI("%{public}s", __func__);
    return AudioProxyCaptureCtrl(AUDIO_HDI_CAPTURE_START, handle);
}

int32_t AudioProxyCaptureStop(AudioHandle handle)
{
    HDF_LOGI("%{public}s", __func__);
    return AudioProxyCaptureCtrl(AUDIO_HDI_CAPTURE_STOP, handle);
}

int32_t AudioProxyCapturePause(AudioHandle handle)
{
    HDF_LOGI("%{public}s", __func__);
    return AudioProxyCaptureCtrl(AUDIO_HDI_CAPTURE_PAUSE, handle);
}

int32_t AudioProxyCaptureResume(AudioHandle handle)
{
    HDF_LOGI("%{public}s", __func__);
    return AudioProxyCaptureCtrl(AUDIO_HDI_CAPTURE_RESUME, handle);
}

int32_t AudioProxyCaptureFlush(AudioHandle handle)
{
    struct AudioHwCapture *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    return AUDIO_HAL_ERR_NOT_SUPPORT;
}

int32_t AudioProxyCaptureSetMute(const AudioHandle handle, bool mute)
{
    (void)mute;
    struct HdfSBuf *data = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct AudioHwCapture *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == NULL || hwCapture->proxyRemoteHandle == NULL) {
        HDF_LOGE("The pointer is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessCapture(hwCapture, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    uint32_t tempMute = (uint32_t)mute;
    if (!HdfSbufWriteUint32(data, tempMute)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioProxyDispatchCall(hwCapture->proxyRemoteHandle, AUDIO_HDI_CAPTURE_SET_MUTE, data, reply);
    AudioProxyBufReplyRecycle(data, reply);
    return ret;
}

int32_t AudioProxyCaptureGetMute(const AudioHandle handle, bool *mute)
{
    if (mute == nullptr) {
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct HdfSBuf *data = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct AudioHwCapture *hwCapture = reinterpret_cast<struct AudioHwCapture *>(handle);
    if (hwCapture == nullptr || hwCapture->proxyRemoteHandle == nullptr) {
        HDF_LOGE("The parameter is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessCapture(hwCapture, &data, &reply) < 0) {
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioProxyDispatchCall(hwCapture->proxyRemoteHandle, AUDIO_HDI_CAPTURE_GET_MUTE, data, reply);
    uint32_t tempMute = 0;
    if (!HdfSbufReadUint32(reply, &tempMute)) {
        AudioProxyBufReplyRecycle(data, reply);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    *mute = (bool)tempMute;
    AudioProxyBufReplyRecycle(data, reply);
    LOG_PARA_INFO("GetMute SUCCESS!");
    return ret;
}

int32_t AudioProxyCaptureCaptureFrame(struct AudioCapture *capture, void *frame,
                                    uint64_t requestBytes, uint64_t *replyBytes)
{
    HDF_LOGD("%{public}s", __func__);
    if (frame == nullptr || replyBytes == nullptr) {
        HDF_LOGE("Capture Frame Paras is NULL!");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    struct HdfSBuf *data = nullptr;
    struct HdfSBuf *reply = nullptr;
    struct AudioHwCapture *hwCapture = reinterpret_cast<struct AudioHwCapture *>(capture);
    if (hwCapture == nullptr || hwCapture->proxyRemoteHandle == nullptr) {
        HDF_LOGE("The hwCapture parameter is null");
        return AUDIO_HAL_ERR_INVALID_PARAM;
    }
    if (AudioProxyPreprocessCapture(hwCapture, &data, &reply) < 0) {
        HDF_LOGE("AudioProxyPreprocessCapture FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (!HdfSbufWriteUint64(data, requestBytes)) {
        AudioProxyBufReplyRecycle(data, reply);
        HDF_LOGE("HdfSbufWriteUint64 FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    int32_t ret = AudioProxyDispatchCall(hwCapture->proxyRemoteHandle, AUDIO_HDI_CAPTURE_CAPTURE_FRAME, data, reply);
    if (ret < 0) {
        if (ret != AUDIO_HAL_ERR_INVALID_OBJECT) {
            HDF_LOGE("AudioCaptureCaptureFrame FAIL");
        }
        AudioProxyBufReplyRecycle(data, reply);
        return ret;
    }
    if (!HdfSbufReadUint64(reply, replyBytes)) {
        AudioProxyBufReplyRecycle(data, reply);
        HDF_LOGE("HdfSbufReadUint64 FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    const void *rBuf = nullptr;
    uint32_t rLen;
    if (!HdfSbufReadBuffer(reply, &rBuf, &rLen)) {
        AudioProxyBufReplyRecycle(data, reply);
        HDF_LOGE("HdfSbufReadBuffer FAIL");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (*replyBytes != rLen) {
        AudioProxyBufReplyRecycle(data, reply);
        HDF_LOGE("%{public}s: read error, size %{public}" PRIu64 ",rLen %{public}u", __func__, *replyBytes, rLen);
        return AUDIO_HAL_ERR_INTERNAL;
    }
    if (memcpy_s(frame, requestBytes, rBuf, rLen) != EOK) {
        AudioProxyBufReplyRecycle(data, reply);
        HDF_LOGE("memcpy rBuf failed");
        return AUDIO_HAL_ERR_INTERNAL;
    }
    AudioProxyBufReplyRecycle(data, reply);
    return AUDIO_HAL_SUCCESS;
}
}