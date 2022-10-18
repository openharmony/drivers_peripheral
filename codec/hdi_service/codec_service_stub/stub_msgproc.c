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
#include "stub_msgproc.h"
#include <hdf_log.h>
#include <osal_mem.h>
#include "common_msgproc.h"

#define HDF_LOG_TAG codec_hdi_stub

int32_t CodecSerPackAlignment(struct HdfSBuf *reply, Alignment *alignment)
{
    if (reply == NULL || alignment == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteInt32(reply, alignment->widthAlignment)) {
        HDF_LOGE("%{public}s: Write widthAlignment failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(reply, alignment->heightAlignment)) {
        HDF_LOGE("%{public}s: Write heightAlignment failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CodecSerPackRect(struct HdfSBuf *reply, Rect *rectangle)
{
    if (reply == NULL || rectangle == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufWriteInt32(reply, rectangle->width)) {
        HDF_LOGE("%{public}s: Write width failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(reply, rectangle->height)) {
        HDF_LOGE("%{public}s: Write height failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static bool CodecCapabilityBaseMarshalling(struct HdfSBuf *reply, CodecCapability *cap)
{
    if (!HdfSbufWriteUint32(reply, (uint32_t)cap->mime)) {
        HDF_LOGE("%{public}s: write cap->mime failed!", __func__);
        return false;
    }
    if (!HdfSbufWriteUint32(reply, (uint32_t)cap->type)) {
        HDF_LOGE("%{public}s: write cap->type failed!", __func__);
        return false;
    }
    for (uint32_t i = 0; i < NAME_LENGTH; i++) {
        if (!HdfSbufWriteUint8(reply, (uint8_t)(cap->name)[i])) {
            HDF_LOGE("%{public}s: write (cap->name)[i] failed!", __func__);
            return false;
        }
    }
    for (uint32_t i = 0; i < PROFILE_NUM; i++) {
        if (!HdfSbufWriteInt32(reply, (cap->supportProfiles)[i])) {
            HDF_LOGE("%{public}s: write (cap->supportProfiles)[i] failed!", __func__);
            return false;
        }
    }
    if (!HdfSbufWriteInt8(reply, cap->isSoftwareCodec ? 1 : 0)) {
        HDF_LOGE("%{public}s: write cap->isSoftwareCodec failed!", __func__);
        return false;
    }
    if (!HdfSbufWriteInt32(reply, cap->processModeMask)) {
        HDF_LOGE("%{public}s: write cap->processModeMask failed!", __func__);
        return false;
    }
    if (!HdfSbufWriteUint32(reply, cap->capsMask)) {
        HDF_LOGE("%{public}s: write cap->capsMask failed!", __func__);
        return false;
    }
    if (!HdfSbufWriteUint32(reply, cap->allocateMask)) {
        HDF_LOGE("%{public}s: write cap->allocateMask failed!", __func__);
        return false;
    }
    return true;
}

static bool CodecCapabilityRangeValueMarshalling(struct HdfSBuf *reply, const RangeValue *dataBlock)
{
    if (!HdfSbufWriteInt32(reply, dataBlock->min)) {
        HDF_LOGE("%{public}s: write dataBlock->min failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(reply, dataBlock->max)) {
        HDF_LOGE("%{public}s: write dataBlock->max failed!", __func__);
        return false;
    }

    return true;
}

static bool CodecCapabilityPortMarshalling(struct HdfSBuf *reply, CodecCapability *cap)
{
    if (cap->type < AUDIO_DECODER) {
        if (!HdfSbufWriteUnpadBuffer(reply, (const uint8_t *)&cap->port, sizeof(VideoPortCap))) {
            HDF_LOGE("%{public}s: write video failed!", __func__);
            return false;
        }
    } else if (cap->type < INVALID_TYPE) {
        if (!HdfSbufWriteUnpadBuffer(reply, (const uint8_t *)&cap->port, sizeof(AudioPortCap))) {
            HDF_LOGE("%{public}s: write audio failed!", __func__);
            return false;
        }
    } else {
        if (!HdfSbufWriteUnpadBuffer(reply, (const uint8_t *)&cap->port, sizeof(cap->port))) {
            HDF_LOGE("%{public}s: write port failed!", __func__);
            return false;
        }
    }
    return true;
}

int32_t CodecSerPackCapability(struct HdfSBuf *reply, CodecCapability *cap)
{
    if (reply == NULL || cap == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!CodecCapabilityBaseMarshalling(reply, cap)) {
        return HDF_FAILURE;
    }
    if (!CodecCapabilityRangeValueMarshalling(reply, &cap->inputBufferNum)) {
        HDF_LOGE("%{public}s: write cap->inputBufferNum failed!", __func__);
        return HDF_FAILURE;
    }
    if (!CodecCapabilityRangeValueMarshalling(reply, &cap->outputBufferNum)) {
        HDF_LOGE("%{public}s: write cap->outputBufferNum failed!", __func__);
        return HDF_FAILURE;
    }
    if (!CodecCapabilityRangeValueMarshalling(reply, &cap->bitRate)) {
        HDF_LOGE("%{public}s: write cap->bitRate failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt32(reply, cap->inputBufferSize)) {
        HDF_LOGE("%{public}s: write cap->inputBufferSize failed!", __func__);
        return false;
    }
    if (!HdfSbufWriteInt32(reply, cap->outputBufferSize)) {
        HDF_LOGE("%{public}s: write cap->outputBufferSize failed!", __func__);
        return false;
    }
    if (!CodecCapabilityPortMarshalling(reply, cap)) {
        HDF_LOGE("%{public}s: write cap->port failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CodecSerParseParam(struct HdfSBuf *data, Param *param)
{
    if (data == NULL || param == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (!HdfSbufReadInt32(data, (int32_t *)&param->key)) {
        HDF_LOGE("%{public}s: read param->key failed!", __func__);
        return HDF_FAILURE;
    }

    int8_t *valCp = NULL;
    int32_t valCpLen = 0;
    if (!HdfSbufReadInt32(data, &valCpLen)) {
        HDF_LOGE("%{public}s: read size failed!", __func__);
        return HDF_FAILURE;
    }
    if (valCpLen > 0) {
        valCp = (int8_t *)OsalMemCalloc(sizeof(int8_t) * valCpLen);
        if (valCp == NULL) {
            return HDF_FAILURE;
        }
        for (int32_t i = 0; i < valCpLen; i++) {
            if (!HdfSbufReadInt8(data, &valCp[i])) {
                HDF_LOGE("%{public}s: read valCp[i] failed!", __func__);
                OsalMemFree(valCp);
                return HDF_FAILURE;
            }
        }
    }
    param->val = (void *)valCp;
    param->size = valCpLen;

    return HDF_SUCCESS;
}

int32_t CodecSerPackParam(struct HdfSBuf *reply, Param *param)
{
    if (reply == NULL || param == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (!HdfSbufWriteInt32(reply, (int32_t)param->key)) {
        HDF_LOGE("%{public}s: write param->key failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(reply, param->size)) {
        HDF_LOGE("%{public}s: write param->size failed!", __func__);
        return false;
    }
    for (int32_t i = 0; i < param->size; i++) {
        if (!HdfSbufWriteInt8(reply, ((int8_t *)(param->val))[i])) {
            HDF_LOGE("%{public}s: write (param->val)[i] failed!", __func__);
            return false;
        }
    }

    return HDF_SUCCESS;
}

static int32_t CodecSerPackBufferInfo(struct HdfSBuf *reply, const CodecBufferInfo *buffer)
{
    if (reply == NULL || buffer == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(reply, (uint32_t)buffer->type)) {
        HDF_LOGE("%{public}s: Write tempType failed!", __func__);
        return HDF_FAILURE;
    }
    if (buffer->type == BUFFER_TYPE_VIRTUAL) {
        if (!HdfSbufWriteBuffer(reply, (void *)buffer->buf, buffer->length)) {
            HDF_LOGE("%{public}s: Write addr failed!", __func__);
            return HDF_FAILURE;
        }
    } else if (buffer->type == BUFFER_TYPE_FD) {
        if (!HdfSbufWriteFileDescriptor(reply, (int32_t)buffer->buf)) {
            HDF_LOGE("%{public}s: Write fd failed!", __func__);
            return HDF_FAILURE;
        }
    } else if (buffer->type == BUFFER_TYPE_HANDLE) {
        if (!PackBufferHandle(reply, (BufferHandle *)buffer->buf)) {
            return HDF_FAILURE;
        }
    }
    if (!HdfSbufWriteUint32(reply, buffer->offset)) {
        HDF_LOGE("%{public}s: Write offset failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(reply, buffer->length)) {
        HDF_LOGE("%{public}s: Write length failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(reply, buffer->capacity)) {
        HDF_LOGE("%{public}s: Write size failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t CodecSerParseBufferInfo(struct HdfSBuf *data, CodecBufferInfo *buffer)
{
    uint32_t readLen = 0;
    if (data == NULL || buffer == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, (uint32_t *)&buffer->type)) {
        HDF_LOGE("%{public}s: read type failed!", __func__);
        return HDF_FAILURE;
    }
    if (buffer->type == BUFFER_TYPE_VIRTUAL) {
        void *buf = (void *)buffer->buf;
        if (!HdfSbufReadBuffer(data, (const void **)&buf, &readLen)) {
            HDF_LOGE("%{public}s: read addr failed!", __func__);
            return HDF_FAILURE;
        }
    } else if (buffer->type == BUFFER_TYPE_FD) {
        buffer->buf = (intptr_t)HdfSbufReadFileDescriptor(data);
        if (buffer->buf < 0) {
            HDF_LOGE("%{public}s: read fd failed!", __func__);
            return HDF_FAILURE;
        }
    } else if (buffer->type == BUFFER_TYPE_HANDLE) {
        if (!ParseBufferHandle(data, (BufferHandle **)&buffer->buf)) {
            return HDF_FAILURE;
        }
    }
    if (!HdfSbufReadUint32(data, &buffer->offset)) {
        HDF_LOGE("%{public}s: read offset failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &buffer->length)) {
        HDF_LOGE("%{public}s: read length failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &buffer->capacity)) {
        HDF_LOGE("%{public}s: read size failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t CodecSerParseCodecBuffer(struct HdfSBuf *data, CodecBuffer *codecBuffer)
{
    if (data == NULL || codecBuffer == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &codecBuffer->bufferId)) {
        HDF_LOGE("%{public}s: read sequence failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadInt64(data, &codecBuffer->timeStamp)) {
        HDF_LOGE("%{public}s: read timeStamp failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufReadUint32(data, &codecBuffer->flag)) {
        HDF_LOGE("%{public}s: read flag failed!", __func__);
        return HDF_FAILURE;
    }
    for (uint32_t i = 0; i < codecBuffer->bufferCnt; i++) {
        if (CodecSerParseBufferInfo(data, &codecBuffer->buffer[i])) {
            HDF_LOGE("%{public}s: read buffers failed!", __func__);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecSerPackCodecBuffer(struct HdfSBuf *reply, const CodecBuffer *codecBuffer)
{
    if (reply == NULL || codecBuffer == NULL) {
        HDF_LOGE("%{public}s: params null!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(reply, codecBuffer->bufferId)) {
        HDF_LOGE("%{public}s: write sequence failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteInt64(reply, codecBuffer->timeStamp)) {
        HDF_LOGE("%{public}s: write timeStamp failed!", __func__);
        return HDF_FAILURE;
    }
    if (!HdfSbufWriteUint32(reply, codecBuffer->flag)) {
        HDF_LOGE("%{public}s: write flag failed!", __func__);
        return HDF_FAILURE;
    }
    for (uint32_t i = 0; i < codecBuffer->bufferCnt; i++) {
        if (CodecSerPackBufferInfo(reply, &codecBuffer->buffer[i])) {
            HDF_LOGE("%{public}s: write buffers failed!", __func__);
            return HDF_FAILURE;
        }
    }
    return HDF_SUCCESS;
}

int32_t CodecSerParseFenceFd(struct HdfSBuf *data, int32_t *fenceFd)
{
    uint8_t validFd = 0;
    if (!HdfSbufReadUint8(data, &validFd)) {
        HDF_LOGE("%{public}s: read validFd failed!", __func__);
        return HDF_FAILURE;
    }
    if (validFd != 0) {
        *fenceFd = HdfSbufReadFileDescriptor(data);
    } else {
        *fenceFd = -1;
    }
    return HDF_SUCCESS;
}

int32_t CodecSerPackFenceFd(struct HdfSBuf *reply, int32_t fenceFd)
{
    uint8_t validFd = fenceFd >= 0;
    if (!HdfSbufWriteUint8(reply, validFd)) {
        HDF_LOGE("%{public}s: write validFd flag failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (validFd != 0 && !HdfSbufWriteFileDescriptor(reply, fenceFd)) {
        HDF_LOGE("%{public}s: write fenceFd failed!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}
