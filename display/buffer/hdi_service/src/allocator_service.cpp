/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "allocator_service.h"

#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/dma-buf.h>
#include <securec.h>
#include <dlfcn.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include "display_log.h"
#include "hdf_trace.h"
#include "hdf_remote_service.h"
#include "display_buffer_dfx.h"

#undef LOG_TAG
#define LOG_TAG "ALLOC_SRV"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002515
#define BUFF_SIZE 16

namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_0 {
extern "C" IAllocator* AllocatorImplGetInstance(void)
{
    return new (std::nothrow) AllocatorService();
}

AllocatorService::AllocatorService()
    : libHandle_(nullptr),
    vdiImpl_(nullptr),
    createVdi_(nullptr),
    destroyVdi_(nullptr)
{
    int32_t ret = LoadVdi();
    if (ret == HDF_SUCCESS) {
        vdiImpl_ = createVdi_();
        CHECK_NULLPOINTER_RETURN(vdiImpl_);
    } else {
        HDF_LOGE("%{public}s: Load buffer VDI failed", __func__);
    }
}

AllocatorService::~AllocatorService()
{
    std::lock_guard<std::mutex> lck(mutex_);
    if (destroyVdi_ != nullptr && vdiImpl_ != nullptr) {
        destroyVdi_(vdiImpl_);
        vdiImpl_ = nullptr;
        destroyVdi_ = nullptr;
    }
    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
        libHandle_ = nullptr;
    }
}

int32_t AllocatorService::LoadVdi()
{
    const char* errStr = dlerror();
    if (errStr != nullptr) {
        HDF_LOGD("%{public}s: allocator load vdi, clear earlier dlerror: %{public}s", __func__, errStr);
    }
#ifdef BUFFER_VDI_DEFAULT_LIBRARY_ENABLE
    libHandle_ = dlopen(DISPLAY_BUFFER_VDI_DEFAULT_LIBRARY, RTLD_LAZY);
    if (libHandle_ == nullptr) {
        DISPLAY_LOGE("display buffer load vendor vdi default library failed: %{public}s", DISPLAY_BUFFER_VDI_LIBRARY);
#endif // BUFFER_VDI_DEFAULT_LIBRARY_ENABLE
        libHandle_ = dlopen(DISPLAY_BUFFER_VDI_LIBRARY, RTLD_LAZY);
        DISPLAY_LOGD("display buffer load vendor vdi library: %{public}s", DISPLAY_BUFFER_VDI_LIBRARY);
#ifdef BUFFER_VDI_DEFAULT_LIBRARY_ENABLE
    } else {
        DISPLAY_LOGD("display buffer load vendor vdi default library: %{public}s", DISPLAY_BUFFER_VDI_LIBRARY);
    }
#endif // BUFFER_VDI_DEFAULT_LIBRARY_ENABLE
    CHECK_NULLPOINTER_RETURN_VALUE(libHandle_, HDF_FAILURE);

    createVdi_ = reinterpret_cast<CreateDisplayBufferVdiFunc>(dlsym(libHandle_, "CreateDisplayBufferVdi"));
    if (createVdi_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            HDF_LOGE("%{public}s: allocator CreateDisplayBufferVdi dlsym error: %{public}s", __func__, errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }

    destroyVdi_ = reinterpret_cast<DestroyDisplayBufferVdiFunc>(dlsym(libHandle_, "DestroyDisplayBufferVdi"));
    if (destroyVdi_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            HDF_LOGE("%{public}s: allocator DestroyDisplayBufferVdi dlsym error: %{public}s", __func__, errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

void AllocatorService::WriteAllocPidToDma(int32_t fd)
{
    pid_t remotePid = HdfRemoteGetCallingPid();
    char pidStr[BUFF_SIZE] = { 0 };
    if (sprintf_s(pidStr, BUFF_SIZE, "%d", remotePid) >= 0) {
        ioctl(fd, DMA_BUF_SET_NAME_A, pidStr);
    }
}

void AllocatorService::FreeMemVdi(BufferHandle* handle)
{
    DisplayBufferDfx dfxIns("HDI:Display:FreeMemVdi:FreeMem");
    dfxIns.SetTimer();
    dfxIns.StartTimeStamp();
    {
        HdfTrace traceTwo("FreeMem", "HDI:VDI:");
        vdiImpl_->FreeMem(*handle);
    }
}

int32_t AllocatorService::AllocMem(const AllocInfo& info, sptr<NativeBuffer>& handle)
{
    HdfTrace trace(__func__, "HDI:DISP:");

    BufferHandle* buffer = nullptr;
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);
    {
        DisplayBufferDfx dfxIns("HDI:Display:AllocatorService:AllocMem");
        dfxIns.SetTimer();
        dfxIns.StartTimeStamp();
        HdfTrace traceOne("AllocMem-VDI", "HDI:VDI:");
        int32_t ec = vdiImpl_->AllocMem(info, buffer);
        if (ec != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: AllocMem failed, ec = %{public}d", __func__, ec);
            return ec;
        }
    }

    CHECK_NULLPOINTER_RETURN_VALUE(buffer, HDF_DEV_ERR_NO_MEMORY);
    WriteAllocPidToDma(buffer->fd);

    handle = new NativeBuffer();
    if (handle == nullptr) {
        HDF_LOGE("%{public}s: new NativeBuffer failed", __func__);
        FreeMemVdi(buffer);
        return HDF_FAILURE;
    }

    handle->SetBufferHandle(buffer, true, [this](BufferHandle* freeBuffer) {
        FreeMemVdi(freeBuffer);
    });
    return HDF_SUCCESS;
}
} // namespace V1_0
} // namespace Buffer
} // namespace Display
} // namespace HDI
} // namespace OHOS
