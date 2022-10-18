/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
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

#include "share_mem.h"
#include <sys/mman.h>
#include "ashmem_wrapper.h"
#include "hdf_log.h"

#define HDF_LOG_TAG codec_hdi_share_mem

int32_t CreateFdShareMemory(ShareMemory *shareMemory)
{
    if (shareMemory == NULL || shareMemory->size <= 0) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_FAILURE;
    }
    int32_t fd = AshmemCreateFd("", shareMemory->size);
    if (fd < 0) {
        HDF_LOGE("%{public}s invalid fd", __func__);
        return HDF_FAILURE;
    }
    shareMemory->fd = fd;
    shareMemory->virAddr = MapAshmemFd(fd, shareMemory->size);
    if ((void*)shareMemory->virAddr == MAP_FAILED) {
        HDF_LOGE("%{public}s: Failed to map fd!", __func__);
        shareMemory->virAddr = NULL;
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t OpenFdShareMemory(ShareMemory *shareMemory)
{
    if (shareMemory == NULL || shareMemory->fd < 0) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_FAILURE;
    }
    shareMemory->virAddr = MapAshmemFd(shareMemory->fd, shareMemory->size);
    if ((void*)shareMemory->virAddr == MAP_FAILED) {
        HDF_LOGE("%{public}s: Failed to map fd!", __func__);
        shareMemory->virAddr = NULL;
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t ReleaseFdShareMemory(ShareMemory *shareMemory)
{
    if (shareMemory == NULL || shareMemory->virAddr == NULL) {
        HDF_LOGE("%{public}s invalid param", __func__);
        return HDF_FAILURE;
    }
    UnmapAshmemFd(shareMemory->virAddr, shareMemory->size);
    CloseAshmemFd(shareMemory->fd);
    return HDF_SUCCESS;
}

