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
#include "common_msgproc.h"
#include <buffer_handle_utils.h>
#include <hdf_log.h>

#define HDF_LOG_TAG codec_hdi_bufferhandle

bool PackBufferHandle(struct HdfSBuf *data, BufferHandle *handle)
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

    validFd = (handle->fd >= 0);
    if (!HdfSbufWriteUint8(data, validFd)) {
        HDF_LOGE("%{public}s: write uint8_t failed!", __func__);
        return false;
    }
    if (validFd && !HdfSbufWriteFileDescriptor(data, handle->fd)) {
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

bool ParseBufferHandle(struct HdfSBuf *data, BufferHandle **handle)
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
