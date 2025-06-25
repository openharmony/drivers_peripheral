/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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
#include <osal_mem.h>
#include <securec.h>
#include <unistd.h>
#include "codec_omx_ext.h"
#include "codec_log_wrapper.h"

#define IF_FALSE_PRINT_MSG_RETURN_FALSE(cond, msg) \
    if (!(cond)) { \
        CODEC_LOGE(msg); \
        return false; \
    }

static bool BufferHandleMarshalling(struct HdfSBuf *data, BufferHandle *handle)
{
    if (handle == NULL) {
        CODEC_LOGE("handle is NULL!");
        return false;
    }

    uint8_t validFd = 0;
    if (!HdfSbufWriteUint32(data, handle->reserveFds) || !HdfSbufWriteUint32(data, handle->reserveInts) ||
        !HdfSbufWriteInt32(data, handle->width) || !HdfSbufWriteInt32(data, handle->stride) ||
        !HdfSbufWriteInt32(data, handle->height) || !HdfSbufWriteInt32(data, handle->size) ||
        !HdfSbufWriteInt32(data, handle->format) || !HdfSbufWriteInt64(data, handle->usage) ||
        !HdfSbufWriteUint64(data, handle->phyAddr)) {
        CODEC_LOGE("write handle failed!");
        return false;
    }
    if (handle->fd >= 0) {
        validFd = 1;
    }
    if (!HdfSbufWriteUint8(data, validFd)) {
        CODEC_LOGE("write uint8_t failed!");
        return false;
    }
    if ((validFd != 0) && !HdfSbufWriteFileDescriptor(data, handle->fd)) {
        CODEC_LOGE("write fd failed!");
        return false;
    }

    for (uint32_t i = 0; i < handle->reserveFds; i++) {
        if (!HdfSbufWriteFileDescriptor(data, handle->reserve[i])) {
            CODEC_LOGE("write handle->reserve[%{public}d] failed!", i);
            return false;
        }
    }

    for (uint32_t i = 0; i < handle->reserveInts; i++) {
        if (!HdfSbufWriteInt32(data, handle->reserve[i + handle->reserveFds])) {
            CODEC_LOGE("write handle->reserve[%{public}d] failed!", i + handle->reserveFds);
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
        CODEC_LOGE("read reserveFds or reserveInts failed!");
        return false;
    }

    BufferHandle *tmpHandle = AllocateBufferHandle(reserveFds, reserveInts);
    if (tmpHandle == NULL) {
        CODEC_LOGE("allocate buffer handle failed!");
        return false;
    }

    if (!HdfSbufReadInt32(data, &tmpHandle->width) || !HdfSbufReadInt32(data, &tmpHandle->stride) ||
        !HdfSbufReadInt32(data, &tmpHandle->height) || !HdfSbufReadInt32(data, &tmpHandle->size) ||
        !HdfSbufReadInt32(data, &tmpHandle->format) || !HdfSbufReadUint64(data, &tmpHandle->usage) ||
        !HdfSbufReadUint64(data, &tmpHandle->phyAddr)) {
        CODEC_LOGE("read handle failed!");
        FreeBufferHandle(tmpHandle);
        return false;
    }

    if (!HdfSbufReadUint8(data, &validFd)) {
        CODEC_LOGE("read handle bool value failed!");
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
            CODEC_LOGE("read reserve bool value failed!");
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
        CODEC_LOGE("write dataBlock->nTunnelFlags failed!");
        return false;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->eSupplier)) {
        CODEC_LOGE("write dataBlock->eSupplier failed!");
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
        CODEC_LOGE("read dataBlock->nTunnelFlags failed!");
        return false;
    }

    if (!HdfSbufReadInt32(data, (int32_t *)&dataBlock->eSupplier)) {
        CODEC_LOGE("read dataBlock->eSupplier failed!");
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
        CODEC_LOGE("write dataBlock->bufferType failed!");
        return false;
    }

    if (!HdfSbufWriteUint32(data, dataBlock->bufferLen)) {
        CODEC_LOGE("write dataBlock->bufferLen failed!");
        return false;
    }
    if (dataBlock->bufferLen <= 0) {
        return true;
    }

    if (dataBlock->buffer == NULL) {
        CODEC_LOGE("dataBlock->buffer is null");
        return false;
    }

    if (dataBlock->bufferType == CODEC_BUFFER_TYPE_AVSHARE_MEM_FD) {
        int fd = (int)(uintptr_t)dataBlock->buffer;
        if (!HdfSbufWriteFileDescriptor(data, fd)) {
            CODEC_LOGE("write fd failed!");
            return false;
        }
    } else if (dataBlock->bufferType == CODEC_BUFFER_TYPE_HANDLE ||
               dataBlock->bufferType == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE) {
        BufferHandle *handle = (BufferHandle *)dataBlock->buffer;
        if (!BufferHandleMarshalling(data, handle)) {
            CODEC_LOGE("write handle failed!");
            return false;
        }
    } else {
        CODEC_LOGE("unsupported bufferType %{public}d!", dataBlock->bufferType);
        return false;
    }
    return true;
}

bool OmxCodecBufferBlockMarshalling(struct HdfSBuf *data, const struct OmxCodecBuffer *dataBlock)
{
    uint8_t validFd = 0;
    if (dataBlock == NULL) {
        CODEC_LOGE("dataBlock is NULL!");
        return false;
    }

    if (!HdfSbufWriteUint32(data, dataBlock->bufferId) || !HdfSbufWriteUint32(data, dataBlock->size)) {
        CODEC_LOGE("write dataBlock:bufferId or size failed!");
        return false;
    }

    if (!HdfSbufWriteUnpadBuffer(data, (const uint8_t *)&dataBlock->version, sizeof(union OMX_VERSIONTYPE))) {
        CODEC_LOGE("write dataBlock->version failed!");
        return false;
    }

    if (!CodecBufferMarshalling(data, dataBlock)) {
        return false;
    }

    if (!HdfSbufWriteUint32(data, dataBlock->allocLen) || !HdfSbufWriteUint32(data, dataBlock->filledLen) ||
        !HdfSbufWriteUint32(data, dataBlock->offset)) {
        CODEC_LOGE("write dataBlock:allocLen, filledLen or offset failed!");
        return false;
    }

    validFd = dataBlock->fenceFd >= 0;
    if (!HdfSbufWriteUint8(data, validFd)) {
        CODEC_LOGE("write validFd failed!");
        return false;
    }
    if (validFd != 0 && !HdfSbufWriteFileDescriptor(data, dataBlock->fenceFd)) {
        CODEC_LOGE("write dataBlock->fenceFd failed!");
        return false;
    }

    if (!HdfSbufWriteInt32(data, (int32_t)dataBlock->type) || !HdfSbufWriteInt64(data, dataBlock->pts) ||
        !HdfSbufWriteUint32(data, dataBlock->flag)) {
        CODEC_LOGE("write dataBlock:type, pts or flag failed!");
        return false;
    }
    return true;
}

static bool CodecBufferUnmarshalling(struct HdfSBuf *data, struct OmxCodecBuffer *dataBlock)
{
    if (dataBlock == NULL) {
        CODEC_LOGE("dataBlock is NULL!");
        return false;
    }
    if (!HdfSbufReadInt32(data, (int32_t *)&dataBlock->bufferType)) {
        CODEC_LOGE("read dataBlock->bufferType failed!");
        return false;
    }

    uint32_t bufferCpLen = 0;
    if (!HdfSbufReadUint32(data, &bufferCpLen)) {
        CODEC_LOGE("read bufferCpLen failed!");
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
            CODEC_LOGE("read fd failed!");
            return false;
        }
        dataBlock->buffer = (uint8_t *)(unsigned long)fd;
    } else if (dataBlock->bufferType == CODEC_BUFFER_TYPE_HANDLE ||
               dataBlock->bufferType == CODEC_BUFFER_TYPE_DYNAMIC_HANDLE) {
        BufferHandle *handle = NULL;
        if (!BufferHandleUnmarshalling(data, &handle)) {
            CODEC_LOGE("read bufferhandle failed!");
            return false;
        }
        dataBlock->buffer = (uint8_t *)handle;
    } else {
        CODEC_LOGE("unsupported bufferType %{public}d", dataBlock->bufferType);
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
        int32_t ret = memset_s(codecBuffer, sizeof(struct OmxCodecBuffer), 0, sizeof(struct OmxCodecBuffer));
        if (ret != EOK) {
            CODEC_LOGE("memset_s codecBuffer err [%{public}d].", ret);
            return;
        }
        codecBuffer->fenceFd = -1;
    }
}
bool OmxCodecBufferBlockUnmarshalling(struct HdfSBuf *data, struct OmxCodecBuffer *dataBlock)
{
    uint8_t validFd = 0;
    if (dataBlock == NULL || data == NULL) {
        CODEC_LOGE("dataBlock or data is NULL!");
        return false;
    }
    if (!HdfSbufReadUint32(data, &dataBlock->bufferId) || !HdfSbufReadUint32(data, &dataBlock->size)) {
        CODEC_LOGE("read dataBlock:bufferId or size failed!");
        return false;
    }
    const union OMX_VERSIONTYPE *versionCp =
        (const union OMX_VERSIONTYPE *)HdfSbufReadUnpadBuffer(data, sizeof(union OMX_VERSIONTYPE));
    if (versionCp == NULL) {
        CODEC_LOGE("read versionCp failed!");
        return false;
    }
    (void)memcpy_s(&dataBlock->version, sizeof(union OMX_VERSIONTYPE), versionCp, sizeof(union OMX_VERSIONTYPE));
    if (!CodecBufferUnmarshalling(data, dataBlock)) {
        return false;
    }
    if (!HdfSbufReadUint32(data, &dataBlock->allocLen) || !HdfSbufReadUint32(data, &dataBlock->filledLen) ||
        !HdfSbufReadUint32(data, &dataBlock->offset)) {
        CODEC_LOGE("read dataBlock:allocLen, filledLen or offset failed!");
        return false;
    }

    if (!HdfSbufReadUint8(data, &validFd)) {
        CODEC_LOGE("read validFd failed!");
        return false;
    }

    if (validFd != 0) {
        dataBlock->fenceFd = HdfSbufReadFileDescriptor(data);
    }

    if (!HdfSbufReadInt32(data, (int32_t *)&dataBlock->type) || !HdfSbufReadInt64(data, &dataBlock->pts) ||
        !HdfSbufReadUint32(data, &dataBlock->flag)) {
        CODEC_LOGE("read dataBlock:type, pts or flag failed!");
        return false;
    }
    return true;
}

bool RangeValueBlockMarshalling(struct HdfSBuf *data, const RangeValue *dataBlock)
{
    if (!HdfSbufWriteInt32(data, dataBlock->min)) {
        CODEC_LOGE("write dataBlock->min failed!");
        return false;
    }

    if (!HdfSbufWriteInt32(data, dataBlock->max)) {
        CODEC_LOGE("write dataBlock->max failed!");
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
        CODEC_LOGE("read dataBlock->min failed!");
        return false;
    }

    if (!HdfSbufReadInt32(data, &dataBlock->max)) {
        CODEC_LOGE("read dataBlock->max failed!");
        return false;
    }

    return true;
}

bool CodecCompCapabilityBlockMarshalling(struct HdfSBuf *data, const CodecCompCapability *dataBlock)
{
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteInt32(data, (int32_t)dataBlock->role),
        "write dataBlock->role failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteInt32(data, (int32_t)dataBlock->type),
        "write dataBlock->type failed!");
    for (uint32_t i = 0; i < NAME_LENGTH; i++) {
        IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteUint8(data, (uint8_t)(dataBlock->compName)[i]),
            "write (dataBlock->compName)[i] failed!");
    }
    for (uint32_t i = 0; i < PROFILE_NUM; i++) {
        IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteInt32(data, (dataBlock->supportProfiles)[i]),
            "write (dataBlock->supportProfiles)[i] failed!");
    }
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteInt32(data, dataBlock->maxInst),
        "write dataBlock->maxInst failed!");
    int8_t isSoftwareCodec = dataBlock->isSoftwareCodec ? 1 : 0;
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteInt8(data, isSoftwareCodec),
        "write dataBlock->isSoftwareCodec failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteInt32(data, dataBlock->processModeMask),
        "write dataBlock->processModeMask failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteUint32(data, dataBlock->capsMask),
        "write dataBlock->capsMask failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(RangeValueBlockMarshalling(data, &dataBlock->bitRate),
        "write dataBlock->bitRate failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteUnpadBuffer(data, (const uint8_t *)&dataBlock->port, sizeof(PortCap)),
        "write dataBlock->port failed!");
    int8_t canSwapWidthHeight = dataBlock->canSwapWidthHeight ? 1 : 0;
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufWriteInt8(data, canSwapWidthHeight),
        "write dataBlock->canSwapWidthHeight failed!");
 
    CODEC_LOGI("write HdfSBuf data success!");
    return true;
}

bool CodecCompCapabilityBlockUnmarshalling(struct HdfSBuf *data, CodecCompCapability *dataBlock)
{
    if (dataBlock == NULL) {
        return false;
    }

    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufReadInt32(data, (int32_t *)&dataBlock->role) &&
                                    HdfSbufReadInt32(data, (int32_t *)&dataBlock->type),
                                    "read dataBlock->role or dataBlock->type failed!");
    for (uint32_t i = 0; i < NAME_LENGTH; i++) {
        IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufReadUint8(data, (uint8_t *)&(dataBlock->compName)[i]),
            "read compName[i] failed!");
    }
    for (uint32_t j = 0; j < PROFILE_NUM; j++) {
        IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufReadInt32(data, &(dataBlock->supportProfiles)[j]),
            "read supportProfiles[i] failed!");
    }
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufReadInt32(data, &dataBlock->maxInst),
        "read dataBlock->maxInst failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufReadInt8(data, (int8_t *)&dataBlock->isSoftwareCodec),
        "read dataBlock->isSoftwareCodec failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufReadInt32(data, &dataBlock->processModeMask),
        "read dataBlock->processModeMask failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufReadUint32(data, &dataBlock->capsMask),
        "read dataBlock->capsMask failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(RangeValueBlockUnmarshalling(data, &dataBlock->bitRate),
        "read &dataBlock->bitRate failed!");
    const PortCap *portCp = (const PortCap *)HdfSbufReadUnpadBuffer(data, sizeof(PortCap));
    IF_FALSE_PRINT_MSG_RETURN_FALSE(portCp != NULL, "read portCp failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(memcpy_s(&dataBlock->port, sizeof(PortCap), portCp, sizeof(PortCap)) == EOK,
        "memcpy_s dataBlock->port failed!");
    IF_FALSE_PRINT_MSG_RETURN_FALSE(HdfSbufReadInt8(data, (int8_t *)&dataBlock->canSwapWidthHeight),
        "read dataBlock->canSwapWidthHeight failed!");

    CODEC_LOGI("read HdfSBuf data success!");
    return true;
}
