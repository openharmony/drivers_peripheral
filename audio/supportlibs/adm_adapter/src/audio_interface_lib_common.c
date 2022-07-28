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

#include "audio_interface_lib_common.h"
#include "audio_uhdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_HAL_LIB

struct HdfIoService *HdfIoServiceBindName(const char *serviceName)
{
    if (serviceName == NULL) {
        AUDIO_FUNC_LOGE("service name NULL!");
        return NULL;
    }
    if (strcmp(serviceName, "hdf_audio_control") == 0) {
        return (HdfIoServiceBind("hdf_audio_control"));
    }
    if (strcmp(serviceName, "hdf_audio_render") == 0) {
        return (HdfIoServiceBind("hdf_audio_render"));
    }
    if (strcmp(serviceName, "hdf_audio_capture") == 0) {
        return (HdfIoServiceBind("hdf_audio_capture"));
    }
    AUDIO_FUNC_LOGE("service name not support!");
    return NULL;
}

void AudioBufReplyRecycle(struct HdfSBuf *sBuf, struct HdfSBuf *reply)
{
    if (sBuf != NULL) {
        HdfSbufRecycle(sBuf);
        sBuf = NULL;
    }
    if (reply != NULL) {
        HdfSbufRecycle(reply);
        reply = NULL;
    }
}

void AudioSbufRecycle(struct HdfSBuf *sBuf)
{
    if (sBuf != NULL) {
        HdfSbufRecycle(sBuf);
        sBuf = NULL;
    }
}

int32_t AudioServiceDispatch(struct HdfIoService *service,
    int cmdId, struct HdfSBuf *sBuf, struct HdfSBuf *reply)
{
    if (service == NULL || service->dispatcher == NULL ||
        service->dispatcher->Dispatch == NULL || sBuf == NULL) {
        AUDIO_FUNC_LOGE("param is null!");
        return HDF_FAILURE;
    }

    return service->dispatcher->Dispatch(&(service->object), cmdId, sBuf, reply);
}

struct HdfSBuf *AudioObtainHdfSBuf(void)
{
#ifdef AUDIO_HDF_SBUF_IPC
    return HdfSbufTypedObtain(SBUF_IPC);
#else
    return HdfSbufTypedObtain(SBUF_RAW);
#endif
}

int32_t AudioCtlGetVolThresholdRead(struct HdfSBuf *reply, struct AudioCtrlElemInfo *volThreshold)
{
    if (reply == NULL || volThreshold == NULL) {
        AUDIO_FUNC_LOGE("reply or volThreshold is null!");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold->type)) {
        AUDIO_FUNC_LOGE("Failed to Get Volume sBuf!");
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold->max)) {
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &volThreshold->min)) {
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}
