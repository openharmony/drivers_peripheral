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

#include "metadata_service.h"
#include <dlfcn.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include "hilog/log.h"
#include "display_log.h"
#include "hdf_trace.h"

#undef LOG_TAG
#define LOG_TAG "METADATA_SRV"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002515
#undef DISPLAY_TRACE
#define DISPLAY_TRACE HdfTrace trace(__func__, "HDI:DISP:")

namespace OHOS {
namespace HDI {
namespace Display {
namespace Buffer {
namespace V1_1 {
using namespace OHOS::HDI::Base;
extern "C" IMetadata *MetadataImplGetInstance(void)
{
    return new (std::nothrow) MetadataService();
}

MetadataService::MetadataService()
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

MetadataService::~MetadataService()
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

int32_t MetadataService::LoadVdi()
{
    const char* errStr = dlerror();
    if (errStr != nullptr) {
        HDF_LOGD("%{public}s: metadata load vdi, clear earlier dlerror: %{public}s", __func__, errStr);
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
            HDF_LOGE("%{public}s: metadata CreateDisplayBufferVdi dlsym error: %{public}s", __func__, errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }

    destroyVdi_ = reinterpret_cast<DestroyDisplayBufferVdiFunc>(dlsym(libHandle_, "DestroyDisplayBufferVdi"));
    if (destroyVdi_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            HDF_LOGE("%{public}s: metadata DestroyDisplayBufferVdi dlsym error: %{public}s", __func__, errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t MetadataService::RegisterBuffer(const sptr<NativeBuffer>& handle)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(handle, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);

    BufferHandle* buffer = handle->GetBufferHandle();
    CHECK_NULLPOINTER_RETURN_VALUE(buffer, HDF_FAILURE);
    int32_t ret = vdiImpl_->RegisterBuffer(*buffer);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, ret, DISPLAY_LOGE(" fail"));
    return HDF_SUCCESS;
}

int32_t MetadataService::SetMetadata(const sptr<NativeBuffer>& handle, uint32_t key, const std::vector<uint8_t>& value)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(handle, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);

    BufferHandle* buffer = handle->GetBufferHandle();
    CHECK_NULLPOINTER_RETURN_VALUE(buffer, HDF_FAILURE);
    int32_t ret = vdiImpl_->SetMetadata(*buffer, key, value);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, ret, DISPLAY_LOGE(" fail"));
    return HDF_SUCCESS;
}

int32_t MetadataService::GetMetadata(const sptr<NativeBuffer>& handle, uint32_t key, std::vector<uint8_t>& value)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(handle, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);

    BufferHandle* buffer = handle->GetBufferHandle();
    CHECK_NULLPOINTER_RETURN_VALUE(buffer, HDF_FAILURE);
    int32_t ret = vdiImpl_->GetMetadata(*buffer, key, value);
    return ret;
}

int32_t MetadataService::ListMetadataKeys(const sptr<NativeBuffer>& handle, std::vector<uint32_t>& keys)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(handle, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);

    BufferHandle* buffer = handle->GetBufferHandle();
    CHECK_NULLPOINTER_RETURN_VALUE(buffer, HDF_FAILURE);
    int32_t ret = vdiImpl_->ListMetadataKeys(*buffer, keys);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, ret, DISPLAY_LOGE(" fail"));
    return HDF_SUCCESS;
}

int32_t MetadataService::EraseMetadataKey(const sptr<NativeBuffer>& handle, uint32_t key)
{
    DISPLAY_TRACE;
    CHECK_NULLPOINTER_RETURN_VALUE(handle, HDF_FAILURE);
    CHECK_NULLPOINTER_RETURN_VALUE(vdiImpl_, HDF_FAILURE);

    BufferHandle* buffer = handle->GetBufferHandle();
    CHECK_NULLPOINTER_RETURN_VALUE(buffer, HDF_FAILURE);
    int32_t ret = vdiImpl_->EraseMetadataKey(*buffer, key);
    DISPLAY_CHK_RETURN(ret != HDF_SUCCESS, ret, DISPLAY_LOGE(" fail"));
    return HDF_SUCCESS;
}

} // V1_1
} // Buffer
} // Display
} // HDI
} // OHOS
