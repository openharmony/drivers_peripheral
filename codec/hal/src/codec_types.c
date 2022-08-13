/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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
#include "codec_types.h"
#include <buffer_handle.h>
#include <buffer_handle_utils.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include <securec.h>
#include <unistd.h>
#include "codec_omx_ext.h"
static bool BufferHandleMarshalling(struct HdfSBuf *data, BufferHandle *handle)
{
    if (handle == NULL) {
        HDF_LOGE("%{public}s: handle is NULL!", __func__);
        return false;
    }

    uint8_t validFd = 0;
    if (!HdfSbufWriteUint32(data, handle->reserveFds) || !HdfSbufWriteUint32(data, handle->reserveInts) ||
        !HdfSbufWriteInt32(data, handle->width) || !HdfSbufWriteInt32(data, handle->stride) ||
        !HdfSbufWriteInt32(data, handle->height) || !HdfSbufWriteInt32(data, handle->size) ||
        !HdfSbufWriteInt32(data, handle->format) || !HdfSbufWriteInt64(data, handle->usage) ||
        !HdfSbufWriteUint64(data, handle->phyAddr) || !HdfSbufWriteInt32(data, handle->key)) {
        HDF_LOGE("%{public}s: write handle failed!", __func__);
        return false;
    }
    if (handle->fd >= 0) {
        validFd = 1;
    }
    if (!HdfSbufWriteUint8(data, validFd)) {
        HDF_LOGE("%{public}s: write uint8_t failed!", __func__);
        return false;
    }
    if ((validFd != 0) && !HdfSbufWriteFileDescriptor(data, handle->fd)) {
        HDF_LOGE("%{public}s: write fd failed!", __func__);
        return false;
    }

    for (uint32_t i = 0; i < handle->reserveFds; i++) {
        if (!HdfSbufWriteFileDescriptor(data, handle->reserve[i])) {
            HDF_LOGE("%{public}s: write handle->reserve[%{public}d] failed!", __func__, i);
            return false;
        }
    }

    for (uint32_t i = 0; i < handle->reserveInts; i++) {
        if (!HdfSbufWriteInt32(data, handle->reserve[i + handle->reserveFds])) {
            HDF_LOGE("%{public}s: write handle->reserve[%{public}d] failed!", __func__, i + handle->reserveFds);
            return false;
        }
    }

    return true;
}

static bool BufferHandleUnmarshalling(struct HdfSBuf *data, BufferHandle **handle)
{
    uint8_t validFd = 0;
    uint32_t reserveFds = 0;
    uint32_t reserveInts = 0;
    if (!HdfSbufReadUint32(data, &reserveFds) || !HdfSbufReadUint32(data, &reserveInts)) {
        HDF_LOGE("%{public}s: read reserveFds or reserveInts failed!", __func__);
        return false;
    }

    BufferHandle *tmpHandle = AllocateBufferHandle(reserveFds, reserveInts);
    if (tmpHandle == NULL) {
        HDF_LOGE("%{public}s: allocate buffer handle failed!", __func__);
        return false;
    }

    if (!HdfSbufReadInt32(data, &tmpHandle->width) || !HdfSbufReadInt32(data, &tmpHandle->stride) ||
        !HdfSbufReadInt32(data, &tmpHandle->height) || !HdfSbufReadInt32(data, &tmpHandle->size) ||
        !HdfSbufReadInt32(data, &tmpHandle->format) || !HdfSbufReadUint64(data, &tmpHandle->usage) ||
        !HdfSbufReadUint64(data, &tmpHandle->phyAddr) || !HdfSbufReadInt32(data, &tmpHandle->key)) {
        HDF_LOGE("%{public}s: read handle failed!", __func__);
        FreeBufferHandle(tmpHandle);
        return false;
    }

    if (!HdfSbufReadUint8(data, &validFd)) {
        HDF_LOGE("%{public}s: read handle bool value failed!", __func__);
        FreeBufferHandle(tmpHandle);
        return false;
    }

    if (validFd != 0) {
        tmpHandle->fd = HdfSbufReadFileDescriptor(data);
    }

    for (uint32_t i = 0; i < tmpHandle->reserveFds; i++) {
        tmpHandle->reserve[i] = HdfSbufReadFileDescriptor(data);
    }

    for (uint32_t i = 0; i < tmpHandle->reserveInts; i++) {
        if (!HdfSbufReadInt32(data, &tmpHandle->reserve[tmpHandle->reserveFds + i])) {
            HDF_LOGE("%{public}s: read reserve bool value failed!", __func__);
            FreeBufferHandle(tmpHandle);
            return false;
        }
    }
    *handle = tmpHandle;
    return true;
}

bool OMX_TUNNELSETUPTYPEBlockMarshalling(struct HdfSBuf *data, const struct OMX_TUNNELSETUPTYPE *dataBlock)
{
    if (!HdfSbufWriteUint32(data, dataBlock->nTunnelFlags)) {
        HDF_LOGE("%{public}s: write dataBlock->nTunnelFlags failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->eSupplier)) {
        HDF_LOGE("%{public}s: write dataBlock->eSupplier failed!", __func__);
        return false;
    }

    return true;
}

bool OMX_TUNNELSETUPTYPEBlockUnmarshalling(struct HdfSBuf *data, struct OMX_TUNNELSETUPTYPE *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }
    if (!HdfSbufReadUint32(data, &dataBlock->nTunnelFlags)) {
        HDF_LOGE("%{public}s: read dataBlock->nTunnelFlags failed!", __func__);
        return false;
    }

    if (!HdfSbufReadInt32(data, (int32_t *)&dataBlock->eSupplier)) {
        HDF_LOGE("%{public}s: read dataBlock->eSupplier failed!", __func__);
        return false;
    }

    return true;
}

void OMX_TUNNELSETUPTYPEFree(struct OMX_TUNNELSETUPTYPE *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

static bool CodecBufferMarshalling(struct HdfSBuf *data, const struct OmxCodecBuffer *dataBlock)
{
    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->bufferType)) {
        HDF_LOGE("%{public}s: write dataBlock->bufferType failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteUint32(data, dataBlock->bufferLen)) {
        HDF_LOGE("%{public}s: write dataBlock->bufferLen failed!", __func__);
        return false;
    }
    if (dataBlock->bufferLen <= 0) {
        return true;
    }

    if (dataBlock->buffer == NULL) {
        HDF_LOGE("%{public}s: dataBlock->buffer is null", __func__);
        return false;
    }

    if (dataBlock->bufferType == CODEC_BUFFER_TYPE_AVSHARE_MEM_FD) {
        int fd = (int)(uintptr_t)dataBlock->buffer;
        if (!HdfSbufWriteFileDescriptor(data, fd)) {
            HDF_LOGE("%{public}s: write fd failed!", __func__);
            return false;
        }
    } else if (dataBlock->bufferType == CODEC_BUFFER_TYPE_HANDLE ||
               dataBlock->bufferType == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE) {
        BufferHandle *handle = (BufferHandle *)dataBlock->buffer;
        if (!BufferHandleMarshalling(data, handle)) {
            HDF_LOGE("%{public}s: write handle failed!", __func__);
            return false;
        }
    } else {
        HDF_LOGE("%{public}s:unsupported bufferType %{public}d!", __func__, dataBlock->bufferType);
        return false;
    }
    return true;
}

bool OmxCodecBufferBlockMarshalling(struct HdfSBuf *data, const struct OmxCodecBuffer *dataBlock)
{
    uint8_t validFd = 0;
    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: dataBlock is NULL!", __func__);
        return false;
    }

    if (!HdfSbufWriteUint32(data, dataBlock->bufferId) || !HdfSbufWriteUint32(data, dataBlock->size)) {
        HDF_LOGE("%{public}s: write dataBlock:bufferId or size failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteUnpadBuffer(data, (const uint8_t *)&dataBlock->version, sizeof(union OMX_VERSIONTYPE))) {
        HDF_LOGE("%{public}s: write dataBlock->version failed!", __func__);
        return false;
    }

    if (!CodecBufferMarshalling(data, dataBlock)) {
        return false;
    }

    if (!HdfSbufWriteUint32(data, dataBlock->allocLen) || !HdfSbufWriteUint32(data, dataBlock->filledLen) ||
        !HdfSbufWriteUint32(data, dataBlock->offset)) {
        HDF_LOGE("%{public}s: write dataBlock:allocLen, filledLen or offset failed!", __func__);
        return false;
    }

    validFd = dataBlock->fenceFd >= 0;
    if (!HdfSbufWriteUint8(data, validFd)) {
        HDF_LOGE("%{public}s: write validFd failed!", __func__);
        return false;
    }
    if (validFd != 0 && !HdfSbufWriteFileDescriptor(data, dataBlock->fenceFd)) {
        HDF_LOGE("%{public}s: write dataBlock->fenceFd failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->type) || !HdfSbufWriteInt64(data, dataBlock->pts) ||
        !HdfSbufWriteUint32(data, dataBlock->flag)) {
        HDF_LOGE("%{public}s: write dataBlock:type, pts or flag failed!", __func__);
        return false;
    }
    return true;
}

static bool CodecBufferUnmarshalling(struct HdfSBuf *data, struct OmxCodecBuffer *dataBlock)
{
    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: dataBlock is NULL!", __func__);
        return false;
    }
    if (!HdfSbufReadInt32(data, (int32_t *)&dataBlock->bufferType)) {
        HDF_LOGE("%{public}s: read dataBlock->bufferType failed!", __func__);
        return false;
    }

    uint32_t bufferCpLen = 0;
    if (!HdfSbufReadUint32(data, &bufferCpLen)) {
        HDF_LOGE("%{public}s: read bufferCpLen failed!", __func__);
        return false;
    }
    dataBlock->bufferLen = bufferCpLen;
    if (dataBlock->bufferLen <= 0) {
        dataBlock->buffer = NULL;
        return true;
    }
    if (dataBlock->bufferType == CODEC_BUFFER_TYPE_AVSHARE_MEM_FD) {
        int fd = HdfSbufReadFileDescriptor(data);
        if (fd < 0) {
            HDF_LOGE("%{public}s: read fd failed!", __func__);
            return false;
        }
        dataBlock->buffer = (uint8_t *)(unsigned long)fd;
    } else if (dataBlock->bufferType == CODEC_BUFFER_TYPE_HANDLE ||
               dataBlock->bufferType == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE) {
        BufferHandle *handle = NULL;
        if (!BufferHandleUnmarshalling(data, &handle)) {
            HDF_LOGE("%{public}s: read bufferhandle failed!", __func__);
            return false;
        }
        dataBlock->buffer = (uint8_t *)handle;
    } else {
        HDF_LOGE("%{public}s: unsupported bufferType %{public}d", __func__, dataBlock->bufferType);
        return false;
    }
    return true;
}

void ReleaseOmxCodecBuffer(struct OmxCodecBuffer *codecBuffer)
{
    if (codecBuffer == NULL) {
        return;
    }

    if (codecBuffer->fenceFd >= 0) {
        close(codecBuffer->fenceFd);
        codecBuffer->fenceFd = -1;
    }
    if (codecBuffer->buffer == NULL || codecBuffer->bufferLen == 0) {
        return;
    }

    if (codecBuffer->bufferType == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE ||
        codecBuffer->bufferType == CODEC_BUFFER_TYPE_HANDLE) {
        FreeBufferHandle((BufferHandle *)codecBuffer->buffer);
    } else if (codecBuffer->bufferType != CODEC_BUFFER_TYPE_AVSHARE_MEM_FD) {
        OsalMemFree(codecBuffer->buffer);
    } else {
        int fd = (uintptr_t)codecBuffer->buffer;
        close(fd);
    }
    codecBuffer->buffer = NULL;
    codecBuffer->bufferLen = 0;
}

void InitOmxCodecBuffer(struct OmxCodecBuffer *codecBuffer)
{
    if (codecBuffer != NULL) {
        (void)memset_s(codecBuffer, sizeof(struct OmxCodecBuffer), 0, sizeof(struct OmxCodecBuffer));
        codecBuffer->fenceFd = -1;
    }
}
bool OmxCodecBufferBlockUnmarshalling(struct HdfSBuf *data, struct OmxCodecBuffer *dataBlock)
{
    uint8_t validFd = 0;
    if (dataBlock == NULL || data == NULL) {
        HDF_LOGE("%{public}s: dataBlock or data is NULL!", __func__);
        return false;
    }
    if (!HdfSbufReadUint32(data, &dataBlock->bufferId) || !HdfSbufReadUint32(data, &dataBlock->size)) {
        HDF_LOGE("%{public}s: read dataBlock:bufferId or size failed!", __func__);
        return false;
    }
    const union OMX_VERSIONTYPE *versionCp =
        (const union OMX_VERSIONTYPE *)HdfSbufReadUnpadBuffer(data, sizeof(union OMX_VERSIONTYPE));
    if (versionCp == NULL) {
        HDF_LOGE("%{public}s: read versionCp failed!", __func__);
        return false;
    }
    (void)memcpy_s(&dataBlock->version, sizeof(union OMX_VERSIONTYPE), versionCp, sizeof(union OMX_VERSIONTYPE));
    if (!CodecBufferUnmarshalling(data, dataBlock)) {
        return false;
    }
    if (!HdfSbufReadUint32(data, &dataBlock->allocLen) || !HdfSbufReadUint32(data, &dataBlock->filledLen) ||
        !HdfSbufReadUint32(data, &dataBlock->offset)) {
        HDF_LOGE("%{public}s: read dataBlock:allocLen, filledLen or offset failed!", __func__);
        return false;
    }

    if (!HdfSbufReadUint8(data, &validFd)) {
        HDF_LOGE("%{public}s: read validFd failed!", __func__);
        return false;
    }

    if (validFd != 0) {
        dataBlock->fenceFd = HdfSbufReadFileDescriptor(data);
    }

    if (!HdfSbufReadInt32(data, (int32_t *)&dataBlock->type) || !HdfSbufReadInt64(data, &dataBlock->pts) ||
        !HdfSbufReadUint32(data, &dataBlock->flag)) {
        HDF_LOGE("%{public}s: read dataBlock:type, pts or flag failed!", __func__);
        return false;
    }
    return true;
}

bool RangeValueBlockMarshalling(struct HdfSBuf *data, const RangeValue *dataBlock)
{
    if (!HdfSbufWriteInt32(data, dataBlock->min)) {
        HDF_LOGE("%{public}s: write dataBlock->min failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, dataBlock->max)) {
        HDF_LOGE("%{public}s: write dataBlock->max failed!", __func__);
        return false;
    }

    return true;
}

bool RangeValueBlockUnmarshalling(struct HdfSBuf *data, RangeValue *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }
    if (!HdfSbufReadInt32(data, &dataBlock->min)) {
        HDF_LOGE("%{public}s: read dataBlock->min failed!", __func__);
        return false;
    }

    if (!HdfSbufReadInt32(data, &dataBlock->max)) {
        HDF_LOGE("%{public}s: read dataBlock->max failed!", __func__);
        return false;
    }

    return true;
}

void RangeValueFree(RangeValue *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

bool RectBlockMarshalling(struct HdfSBuf *data, const Rect *dataBlock)
{
    if (!HdfSbufWriteInt32(data, dataBlock->width)) {
        HDF_LOGE("%{public}s: write dataBlock->width failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, dataBlock->height)) {
        HDF_LOGE("%{public}s: write dataBlock->height failed!", __func__);
        return false;
    }

    return true;
}

bool RectBlockUnmarshalling(struct HdfSBuf *data, Rect *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }
    if (!HdfSbufReadInt32(data, &dataBlock->width)) {
        HDF_LOGE("%{public}s: read dataBlock->width failed!", __func__);
        return false;
    }

    if (!HdfSbufReadInt32(data, &dataBlock->height)) {
        HDF_LOGE("%{public}s: read dataBlock->height failed!", __func__);
        return false;
    }

    return true;
}

bool AlignmentBlockMarshalling(struct HdfSBuf *data, const Alignment *dataBlock)
{
    if (!HdfSbufWriteInt32(data, dataBlock->widthAlignment)) {
        HDF_LOGE("%{public}s: write dataBlock->widthAlignment failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, dataBlock->heightAlignment)) {
        HDF_LOGE("%{public}s: write dataBlock->heightAlignment failed!", __func__);
        return false;
    }

    return true;
}

bool AlignmentBlockUnmarshalling(struct HdfSBuf *data, Alignment *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }
    if (!HdfSbufReadInt32(data, &dataBlock->widthAlignment)) {
        HDF_LOGE("%{public}s: read dataBlock->widthAlignment failed!", __func__);
        return false;
    }

    if (!HdfSbufReadInt32(data, &dataBlock->heightAlignment)) {
        HDF_LOGE("%{public}s: read dataBlock->heightAlignment failed!", __func__);
        return false;
    }

    return true;
}

bool VideoPortCapBlockMarshalling(struct HdfSBuf *data, const CodecVideoPortCap *dataBlock)
{
    if (!RectBlockMarshalling(data, &dataBlock->minSize)) {
        HDF_LOGE("%{public}s: write dataBlock->minSize failed!", __func__);
        return false;
    }

    if (!RectBlockMarshalling(data, &dataBlock->maxSize)) {
        HDF_LOGE("%{public}s: write dataBlock->maxSize failed!", __func__);
        return false;
    }

    if (!AlignmentBlockMarshalling(data, &dataBlock->whAlignment)) {
        HDF_LOGE("%{public}s: write dataBlock->whAlignment failed!", __func__);
        return false;
    }

    if (!RangeValueBlockMarshalling(data, &dataBlock->blockCount)) {
        HDF_LOGE("%{public}s: write dataBlock->blockCount failed!", __func__);
        return false;
    }

    if (!RangeValueBlockMarshalling(data, &dataBlock->blocksPerSecond)) {
        HDF_LOGE("%{public}s: write dataBlock->blocksPerSecond failed!", __func__);
        return false;
    }

    if (!RectBlockMarshalling(data, &dataBlock->blockSize)) {
        HDF_LOGE("%{public}s: write dataBlock->blockSize failed!", __func__);
        return false;
    }

    for (uint32_t i = 0; i < PIX_FORMAT_NUM; i++) {
        if (!HdfSbufWriteInt32(data, (dataBlock->supportPixFmts)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->supportPixFmts)[i] failed!", __func__);
            return false;
        }
    }

    return true;
}

bool VideoPortCapBlockUnmarshalling(struct HdfSBuf *data, CodecVideoPortCap *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }
    if (!RectBlockUnmarshalling(data, &dataBlock->minSize)) {
        HDF_LOGE("%{public}s: read &dataBlock->minSize failed!", __func__);
        return false;
    }

    if (!RectBlockUnmarshalling(data, &dataBlock->maxSize)) {
        HDF_LOGE("%{public}s: read &dataBlock->maxSize failed!", __func__);
        return false;
    }

    if (!AlignmentBlockUnmarshalling(data, &dataBlock->whAlignment)) {
        HDF_LOGE("%{public}s: read &dataBlock->whAlignment failed!", __func__);
        return false;
    }

    if (!RangeValueBlockUnmarshalling(data, &dataBlock->blockCount)) {
        HDF_LOGE("%{public}s: read &dataBlock->blockCount failed!", __func__);
        return false;
    }

    if (!RangeValueBlockUnmarshalling(data, &dataBlock->blocksPerSecond)) {
        HDF_LOGE("%{public}s: read &dataBlock->blocksPerSecond failed!", __func__);
        return false;
    }

    if (!RectBlockUnmarshalling(data, &dataBlock->blockSize)) {
        HDF_LOGE("%{public}s: read &dataBlock->blockSize failed!", __func__);
        return false;
    }

    for (uint32_t i = 0; i < PIX_FORMAT_NUM; i++) {
        if (!HdfSbufReadInt32(data, &(dataBlock->supportPixFmts)[i])) {
            HDF_LOGE("%{public}s: read supportPixFmts[i] failed!", __func__);
            return false;
        }
    }

    return true;
}

bool AudioPortCapBlockMarshalling(struct HdfSBuf *data, const CodecAudioPortCap *dataBlock)
{
    for (uint32_t i = 0; i < SAMPLE_FORMAT_NUM; i++) {
        if (!HdfSbufWriteInt32(data, (dataBlock->sampleFormats)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->sampleFormats)[i] failed!", __func__);
            return false;
        }
    }

    for (uint32_t i = 0; i < SAMPLE_RATE_NUM; i++) {
        if (!HdfSbufWriteInt32(data, (dataBlock->sampleRate)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->sampleRate)[i] failed!", __func__);
            return false;
        }
    }

    for (uint32_t i = 0; i < CHANNEL_NUM; i++) {
        if (!HdfSbufWriteInt32(data, (dataBlock->channelLayouts)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->channelLayouts)[i] failed!", __func__);
            return false;
        }
    }

    for (uint32_t i = 0; i < CHANNEL_NUM; i++) {
        if (!HdfSbufWriteInt32(data, (dataBlock->channelCount)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->channelCount)[i] failed!", __func__);
            return false;
        }
    }

    return true;
}

bool AudioPortCapBlockUnmarshalling(struct HdfSBuf *data, CodecAudioPortCap *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }

    for (uint32_t i = 0; i < SAMPLE_FORMAT_NUM; i++) {
        if (!HdfSbufReadInt32(data, &(dataBlock->sampleFormats)[i])) {
            HDF_LOGE("%{public}s: read sampleFormats[i] failed!", __func__);
            return false;
        }
    }

    for (uint32_t i = 0; i < SAMPLE_RATE_NUM; i++) {
        if (!HdfSbufReadInt32(data, &(dataBlock->sampleRate)[i])) {
            HDF_LOGE("%{public}s: read sampleRate[i] failed!", __func__);
            return false;
        }
    }

    for (uint32_t i = 0; i < CHANNEL_NUM; i++) {
        if (!HdfSbufReadInt32(data, &(dataBlock->channelLayouts)[i])) {
            HDF_LOGE("%{public}s: read channelLayouts[i] failed!", __func__);
            return false;
        }
    }

    for (uint32_t i = 0; i < CHANNEL_NUM; i++) {
        if (!HdfSbufReadInt32(data, &(dataBlock->channelCount)[i])) {
            HDF_LOGE("%{public}s: read channelCount[i] failed!", __func__);
            return false;
        }
    }

    return true;
}

void AudioPortCapFree(CodecAudioPortCap *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

bool CodecCompCapabilityBlockMarshalling(struct HdfSBuf *data, const CodecCompCapability *dataBlock)
{
    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->role)) {
        HDF_LOGE("%{public}s: write dataBlock->role failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->type)) {
        HDF_LOGE("%{public}s: write dataBlock->type failed!", __func__);
        return false;
    }

    for (uint32_t i = 0; i < NAME_LENGTH; i++) {
        if (!HdfSbufWriteUint8(data, (uint8_t)(dataBlock->compName)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->compName)[i] failed!", __func__);
            return false;
        }
    }

    for (uint32_t i = 0; i < PROFILE_NUM; i++) {
        if (!HdfSbufWriteInt32(data, (dataBlock->supportProfiles)[i])) {
            HDF_LOGE("%{public}s: write (dataBlock->supportProfiles)[i] failed!", __func__);
            return false;
        }
    }

    if (!HdfSbufWriteInt32(data, dataBlock->maxInst)) {
        HDF_LOGE("%{public}s: write dataBlock->maxInst failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt8(data, dataBlock->isSoftwareCodec ? 1 : 0)) {
        HDF_LOGE("%{public}s: write dataBlock->isSoftwareCodec failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteInt32(data, dataBlock->processModeMask)) {
        HDF_LOGE("%{public}s: write dataBlock->processModeMask failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteUint32(data, dataBlock->capsMask)) {
        HDF_LOGE("%{public}s: write dataBlock->capsMask failed!", __func__);
        return false;
    }

    if (!RangeValueBlockMarshalling(data, &dataBlock->bitRate)) {
        HDF_LOGE("%{public}s: write dataBlock->bitRate failed!", __func__);
        return false;
    }

    if (!HdfSbufWriteUnpadBuffer(data, (const uint8_t *)&dataBlock->port, sizeof(PortCap))) {
        HDF_LOGE("%{public}s: write dataBlock->port failed!", __func__);
        return false;
    }

    return true;
}

bool CodecCompCapabilityBlockUnmarshalling(struct HdfSBuf *data, CodecCompCapability *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }

    if (!HdfSbufReadInt32(data, (int32_t *)&dataBlock->role) ||
        !HdfSbufReadInt32(data, (int32_t *)&dataBlock->type)) {
        HDF_LOGE("%{public}s: read dataBlock->role or dataBlock->type failed!", __func__);
        return false;
    }

    for (uint32_t i = 0; i < NAME_LENGTH; i++) {
        if (!HdfSbufReadUint8(data, (uint8_t *)&(dataBlock->compName)[i])) {
            HDF_LOGE("%{public}s: read compName[i] failed!", __func__);
            return false;
        }
    }

    for (uint32_t j = 0; j < PROFILE_NUM; j++) {
        if (!HdfSbufReadInt32(data, &(dataBlock->supportProfiles)[j])) {
            HDF_LOGE("%{public}s: read supportProfiles[i] failed!", __func__);
            return false;
        }
    }

    if (!HdfSbufReadInt32(data, &dataBlock->maxInst)) {
        HDF_LOGE("%{public}s: read dataBlock->maxInst failed!", __func__);
        return false;
    }

    if (!HdfSbufReadInt8(data, (int8_t *)&dataBlock->isSoftwareCodec)) {
        HDF_LOGE("%{public}s: read dataBlock->isSoftwareCodec failed!", __func__);
        return false;
    }

    if (!HdfSbufReadInt32(data, &dataBlock->processModeMask)) {
        HDF_LOGE("%{public}s: read dataBlock->processModeMask failed!", __func__);
        return false;
    }

    if (!HdfSbufReadUint32(data, &dataBlock->capsMask)) {
        HDF_LOGE("%{public}s: read dataBlock->capsMask failed!", __func__);
        return false;
    }

    if (!RangeValueBlockUnmarshalling(data, &dataBlock->bitRate)) {
        HDF_LOGE("%{public}s: read &dataBlock->bitRate failed!", __func__);
        return false;
    }

    const PortCap *portCp = (const PortCap *)HdfSbufReadUnpadBuffer(data, sizeof(PortCap));
    if (portCp == NULL) {
        HDF_LOGE("%{public}s: read portCp failed!", __func__);
        return false;
    }
    (void)memcpy_s(&dataBlock->port, sizeof(PortCap), portCp, sizeof(PortCap));

    return true;
}
