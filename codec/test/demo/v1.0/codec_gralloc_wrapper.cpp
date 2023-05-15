/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "codec_gralloc_wrapper.h"
#include <idisplay_gralloc.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/include/idisplay_buffer.h"

using namespace std;
using namespace OHOS;

#define HDF_LOG_TAG codec_hdi_gralloc

#ifdef __cplusplus
extern "C"
{
#endif
OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer *g_gralloc = nullptr;
int32_t GrAllocatorInit(void)
{
    g_gralloc = OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer::Get();
    if (g_gralloc == nullptr) {
        HDF_LOGE("%{public}s g_gralloc init failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t GrMemCreate(OHOS::HDI::Display::Buffer::V1_0::AllocInfo alloc, BufferHandle **bufferHandle)
{
    if (g_gralloc == nullptr) {
        HDF_LOGE("%{public}s g_gralloc null", __func__);
        return HDF_FAILURE;
    }
    int32_t err = g_gralloc->AllocMem(alloc, *bufferHandle);
    if (err != DISPLAY_SUCCESS) {
        HDF_LOGE("%{public}s AllocMem fail, ret:%{public}d", __func__, err);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t GrMemDestroy(BufferHandle *bufferHandle)
{
    if (g_gralloc == nullptr) {
        HDF_LOGE("%{public}s g_gralloc null", __func__);
        return HDF_FAILURE;
    }
    g_gralloc->FreeMem(*bufferHandle);
    return HDF_SUCCESS;
}

static int32_t GrMemMap(BufferHandle *bufferHandle)
{
    if (g_gralloc == nullptr) {
        HDF_LOGE("%{public}s g_gralloc null", __func__);
        return HDF_FAILURE;
    }
    g_gralloc->Mmap(*bufferHandle);
    return HDF_SUCCESS;
}

static int32_t GrMemUnmap(BufferHandle *bufferHandle)
{
    if (g_gralloc == nullptr) {
        HDF_LOGE("%{public}s g_gralloc null", __func__);
        return HDF_FAILURE;
    }
    g_gralloc->Unmap(*bufferHandle);
    return HDF_SUCCESS;
}

int32_t CreateGrShareMemory(BufferHandle **bufferHandle, CodecCmd cmd, ShareMemory *shareMemory)
{
    if (bufferHandle == NULL || shareMemory == NULL) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_FAILURE;
    }
    OHOS::HDI::Display::Buffer::V1_0::AllocInfo alloc = {
        .width = cmd.width,
        .height = cmd.height,
        .usage =  OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_READ
            | OHOS::HDI::Display::Composer::V1_0::HBM_USE_CPU_WRITE
            | OHOS::HDI::Display::Composer::V1_0::HBM_USE_MEM_DMA,
        .format = cmd.pixFmt};

    int32_t ret = GrMemCreate(alloc, bufferHandle);
    if (ret != HDF_SUCCESS || *bufferHandle == NULL) {
        HDF_LOGE("%{public}s: Failed to create buffer handle!", __func__);
        return HDF_FAILURE;
    }
    ret = GrMemMap(*bufferHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to map buffer handle!", __func__);
        return ret;
    }
    shareMemory->virAddr = static_cast<uint8_t *>((*bufferHandle)->virAddr);
    if (shareMemory->virAddr == NULL) {
        HDF_LOGE("%{public}s: Failed to map buffer handle!", __func__);
        return HDF_FAILURE;
    }
    shareMemory->size = (*bufferHandle)->size;
    shareMemory->fd = (*bufferHandle)->fd;
    return HDF_SUCCESS;
}

int32_t DestroyGrShareMemory(BufferHandle *bufferHandle)
{
    if (bufferHandle == NULL) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_FAILURE;
    }
    return GrMemDestroy(bufferHandle);
}

int32_t OpenGrShareMemory(BufferHandle *bufferHandle, ShareMemory *shareMemory)
{
    if (bufferHandle == NULL || shareMemory == NULL) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = GrMemMap(bufferHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to map buffer handle!", __func__);
        return ret;
    }
    shareMemory->virAddr = static_cast<uint8_t *>(bufferHandle->virAddr);
    if (shareMemory->virAddr == NULL) {
        HDF_LOGE("%{public}s: Failed to map buffer handle!", __func__);
        return HDF_FAILURE;
    }
    shareMemory->size = bufferHandle->size;
    shareMemory->fd = bufferHandle->fd;
    return HDF_SUCCESS;
}

int32_t ReleaseGrShareMemory(BufferHandle *bufferHandle, ShareMemory *shareMemory)
{
    if (bufferHandle == NULL || shareMemory == NULL) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_FAILURE;
    }

    int32_t ret = GrMemUnmap(bufferHandle);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: Failed to Unmap bufferHandle!", __func__);
        return ret;
    }
    shareMemory->virAddr = NULL;
    return HDF_SUCCESS;
}
#ifdef __cplusplus
}
#endif