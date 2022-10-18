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
#include "proxy_msgproc.h"
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>
#include "common_msgproc.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define HDF_LOG_TAG codec_hdi_proxy

static bool CodecCapabilityBaseUnmarshalling(struct HdfSBuf *reply, CodecCapability *cap)
{
    if (!HdfSbufReadUint32(reply, (uint32_t*)&cap->mime)) {
        HDF_LOGE("%{public}s: read cap->mime failed!", __func__);
        return false;
    }
    if (!HdfSbufReadUint32(reply, (uint32_t*)&cap->type)) {
        HDF_LOGE("%{public}s: read cap->type failed!", __func__);
        return false;
    }
    for (uint32_t i = 0; i < NAME_LENGTH; i++) {
        if (!HdfSbufReadUint8(reply, (uint8_t *)&(cap->name)[i])) {
            HDF_LOGE("%{public}s: read name[i] failed!", __func__);
            return false;
        }
    }
    for (uint32_t j = 0; j < PROFILE_NUM; j++) {
        if (!HdfSbufReadInt32(reply, &(cap->supportProfiles)[j])) {
            HDF_LOGE("%{public}s: read supportProfiles[i] failed!", __func__);
            return false;
        }
    }
    if (!HdfSbufReadInt8(reply, (int8_t *)&cap->isSoftwareCodec)) {
        HDF_LOGE("%{public}s: read cap->isSoftwareCodec failed!", __func__);
        return false;
    }
    if (!HdfSbufReadInt32(reply, &cap->processModeMask)) {
        HDF_LOGE("%{public}s: read cap->processModeMask failed!", __func__);
        return false;
    }
    if (!HdfSbufReadUint32(reply, &cap->capsMask)) {
        HDF_LOGE("%{public}s: read cap->capsMask failed!", __func__);
        return false;
    }
    if (!HdfSbufReadUint32(reply, &cap->allocateMask)) {
        HDF_LOGE("%{public}s: read cap->allocateMask failed!", __func__);
        return false;
    }
    return true;
}

static bool CodecCapabilityRangeValueUnmarshalling(struct HdfSBuf *reply, RangeValue *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }
    if (!HdfSbufReadInt32(reply, &dataBlock->min)) {
        HDF_LOGE("%{public}s: read dataBlock->min failed!", __func__);
        return false;
    }
    if (!HdfSbufReadInt32(reply, &dataBlock->max)) {
        HDF_LOGE("%{public}s: read dataBlock->max failed!", __func__);
        return false;
    }
    return true;
}

static bool CodecCapabilityPortUnmarshalling(struct HdfSBuf *reply, CodecCapability *cap)
{
    int32_t ret;
    if (cap->type < AUDIO_DECODER) {
        const VideoPortCap *video = (const VideoPortCap *)HdfSbufReadUnpadBuffer(reply, sizeof(VideoPortCap));
        if (video == NULL) {
            HDF_LOGE("%{public}s: read video failed!", __func__);
            return false;
        }
        ret = memcpy_s(&cap->port, sizeof(VideoPortCap), video, sizeof(VideoPortCap));
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memcpy_s video failed, error code: %{public}d", __func__, ret);
            return false;
        }
    } else if (cap->type < INVALID_TYPE) {
        const AudioPortCap *audio = (const AudioPortCap *)HdfSbufReadUnpadBuffer(reply, sizeof(AudioPortCap));
        if (audio == NULL) {
            HDF_LOGE("%{public}s: read audio failed!", __func__);
            return false;
        }
        ret = memcpy_s(&cap->port, sizeof(AudioPortCap), audio, sizeof(AudioPortCap));
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memcpy_s audio failed, error code: %{public}d", __func__, ret);
            return false;
        }
    } else {
        ret = memset_s(&cap->port, sizeof(cap->port), 0, sizeof(cap->port));
        if (ret != EOK) {
            HDF_LOGE("%{public}s: memset_s cap->port failed, error code: %{public}d", __func__, ret);
            return false;
        }
    }
    return true;
}

int32_t CodecProxyParseGottenCapability(struct HdfSBuf *reply, CodecCapability *cap)
{
    if (reply == NULL || cap == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    if (!CodecCapabilityBaseUnmarshalling(reply, cap)) {
        return HDF_FAILURE;
    }
    if (!CodecCapabilityRangeValueUnmarshalling(reply, &cap->inputBufferNum)) {
        HDF_LOGE("%{public}s: read &cap->inputBufferNum failed!", __func__);
        return HDF_FAILURE;
    }
    if (!CodecCapabilityRangeValueUnmarshalling(reply, &cap->outputBufferNum)) {
        HDF_LOGE("%{public}s: read &cap->outputBufferNum failed!", __func__);
        return HDF_FAILURE;
    }
    if (!CodecCapabilityRangeValueUnmarshalling(reply, &cap->bitRate)) {
        HDF_LOGE("%{public}s: read &cap->bitRate failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &cap->inputBufferSize)) {
        HDF_LOGE("%{public}s: read cap->inputBufferSize failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt32(reply, &cap->outputBufferSize)) {
        HDF_LOGE("%{public}s: read cap->outputBufferSize failed!", __func__);
        return HDF_FAILURE;
    }
    if (!CodecCapabilityPortUnmarshalling(reply, cap)) {
        HDF_LOGE("%{public}s: read cap->port failed!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t CodecProxyPackParam(struct HdfSBuf *data, const Param *param)
{
    if (data == NULL || param == NULL) {
        HDF_LOGE("%{public}s: params NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)param->key)) {
        HDF_LOGE("%{public}s: write param->key failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, param->size)) {
        HDF_LOGE("%{public}s: write param->size failed!", __func__);
        return false;
    }
    for (int32_t i = 0; i < param->size; i++) {
        if (!HdfSbufWriteInt8(data, ((int8_t*)(param->val))[i])) {
            HDF_LOGE("%{public}s: write (param->val)[i] failed!", __func__);
            return false;
        }
    }

    return HDF_SUCCESS;
}

int32_t CodecProxyParseParam(struct HdfSBuf *reply, Param *param)
{
    if (reply == NULL || param == NULL) {
        HDF_LOGE("%{public}s: params NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufReadInt32(reply, (int32_t*)&param->key)) {
        HDF_LOGE("%{public}s: read param->key failed!", __func__);
        return HDF_FAILURE;
    }

    int8_t* valCp = NULL;
    int32_t valCpLen = 0;
    if (!HdfSbufReadInt32(reply, &valCpLen)) {
        HDF_LOGE("%{public}s: read size failed!", __func__);
        return HDF_FAILURE;
    }
    if (valCpLen > 0) {
        valCp = (int8_t*)OsalMemCalloc(sizeof(int8_t) * valCpLen);
        if (valCp == NULL) {
            HDF_LOGE("%{public}s: alloc mem failed!", __func__);
            return HDF_FAILURE;
        }
        for (int32_t i = 0; i < valCpLen; i++) {
            if (!HdfSbufReadInt8(reply, &valCp[i])) {
                HDF_LOGE("%{public}s: read valCp[i] failed!", __func__);
                OsalMemFree(valCp);
                return HDF_FAILURE;
            }
        }
    }
    param->val = (void*)valCp;
    param->size = valCpLen;

    return HDF_SUCCESS;
}

static int32_t CodecProxyPackBufferInfo(struct HdfSBuf *data, const CodecBufferInfo *buffer)
{
    if (data == NULL || buffer == NULL) {
        HDF_LOGE("%{public}s: params NULL!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, (uint32_t)buffer->type)) {
        HDF_LOGE("%{public}s: Write BufferType failed!", __func__);
        return HDF_FAILURE;
    }
    if (buffer->type == BUFFER_TYPE_VIRTUAL) {
        if (!HdfSbufWriteBuffer(data, (void *)buffer->buf, buffer->length)) {
            HDF_LOGE("%{public}s: Write addr failed!", __func__);
            return HDF_FAILURE;
        }
    } else if (buffer->type == BUFFER_TYPE_FD) {
        if (!HdfSbufWriteFileDescriptor(data, (int32_t)buffer->buf)) {
            HDF_LOGE("%{public}s: Write fd failed!", __func__);
            return HDF_FAILURE;
        }
    } else if (buffer->type == BUFFER_TYPE_HANDLE) {
        if (!PackBufferHandle(data, (BufferHandle *)buffer->buf)) {
            return HDF_FAILURE;
        }
    } else {
        HDF_LOGE("%{public}s: buffer->type is  err!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, buffer->offset)) {
        HDF_LOGE("%{public}s: Write offset failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, buffer->length)) {
        HDF_LOGE("%{public}s: Write length failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, buffer->capacity)) {
        HDF_LOGE("%{public}s: Write size failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t CodecProxyParseBufferInfo(struct HdfSBuf *reply, CodecBufferInfo *buffer)
{
    uint32_t readLen = 0;
    if (reply == NULL || buffer == NULL) {
        HDF_LOGE("%{public}s: buffer null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(reply, (uint32_t *)&buffer->type)) {
        HDF_LOGE("%{public}s: read type failed!", __func__);
        return HDF_FAILURE;
    }
    if (buffer->type == BUFFER_TYPE_VIRTUAL) {
        void *buf = (void *)buffer->buf;
        if (!HdfSbufReadBuffer(reply, (const void **)&buf, &readLen)) {
            HDF_LOGE("%{public}s: read addr failed!", __func__);
            return HDF_FAILURE;
        }
    } else if (buffer->type == BUFFER_TYPE_FD) {
        buffer->buf = (intptr_t)HdfSbufReadFileDescriptor(reply);
        if (buffer->buf < 0) {
            HDF_LOGE("%{public}s: read fd failed!", __func__);
            return HDF_FAILURE;
        }
    } else if (buffer->type == BUFFER_TYPE_HANDLE) {
        if (!ParseBufferHandle(reply, (BufferHandle **)&buffer->buf)) {
            return HDF_FAILURE;
        }
    }
    if (!HdfSbufReadUint32(reply, &buffer->offset)) {
        HDF_LOGE("%{public}s: read offset failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &buffer->length)) {
        HDF_LOGE("%{public}s: read length failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &buffer->capacity)) {
        HDF_LOGE("%{public}s: read size failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CodecProxyParseCodecBuffer(struct HdfSBuf *reply, CodecBuffer *codecBuffer)
{
    if (reply == NULL || codecBuffer == NULL) {
        HDF_LOGE("%{public}s: params error!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadUint32(reply, &codecBuffer->bufferId)) {
        HDF_LOGE("%{public}s: read sequence failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt64(reply, &codecBuffer->timeStamp)) {
        HDF_LOGE("%{public}s: read timeStamp failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(reply, &codecBuffer->flag)) {
        HDF_LOGE("%{public}s: read flag failed!", __func__);
        return HDF_FAILURE;
    }
    for (uint32_t i = 0; i < codecBuffer->bufferCnt; i++) {
        if (CodecProxyParseBufferInfo(reply, &codecBuffer->buffer[i])) {
            HDF_LOGE("%{public}s: read buffers failed!", __func__);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecProxyPackCodecBuffer(struct HdfSBuf *data, const CodecBuffer *codecBuffer)
{
    if (data == NULL || codecBuffer == NULL) {
        HDF_LOGE("%{public}s: params error!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteUint32(data, codecBuffer->bufferCnt)) {
        HDF_LOGE("%{public}s: write bufferCnt failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, codecBuffer->bufferId)) {
        HDF_LOGE("%{public}s: write bufferId failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt64(data, codecBuffer->timeStamp)) {
        HDF_LOGE("%{public}s: write timeStamp failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(data, codecBuffer->flag)) {
        HDF_LOGE("%{public}s: write flag failed!", __func__);
        return HDF_FAILURE;
    }
    for (uint32_t i = 0; i < codecBuffer->bufferCnt; i++) {
        if (CodecProxyPackBufferInfo(data, &codecBuffer->buffer[i])) {
            HDF_LOGE("%{public}s: write buffers failed!", __func__);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecProxyParseFenceFd(struct HdfSBuf *reply, int32_t *fenceFd)
{
    uint8_t validFd = 0;
    if (!HdfSbufReadUint8(reply, &validFd)) {
        HDF_LOGE("%{public}s: read validFd failed!", __func__);
        return HDF_FAILURE;
    }
    if (validFd != 0) {
        *fenceFd = HdfSbufReadFileDescriptor(reply);
    } else {
        *fenceFd = -1;
    }
    return HDF_SUCCESS;
}

int32_t CodecProxyPackFenceFd(struct HdfSBuf *data, int fenceFd)
{
    uint8_t validFd = fenceFd >= 0;
    if (!HdfSbufWriteUint8(data, validFd)) {
        HDF_LOGE("%{public}s: write validFd flag failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (validFd != 0 && !HdfSbufWriteFileDescriptor(data, fenceFd)) {
        HDF_LOGE("%{public}s: write fenceFd failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
