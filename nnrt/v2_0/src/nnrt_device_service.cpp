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

#include "nnrt_device_service.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <message_parcel.h>
#include <securec.h>
#include <mutex>
#include <dlfcn.h>
#include <hdf_trace.h>

#undef LOG_TAG
#define LOG_TAG "NNRT_DEVICE"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002600

#undef NNRT_TRACE
#define NNRT_TRACE HdfTrace trace(__func__, "HDI:NNRT:")

namespace OHOS {
namespace HDI {
namespace Nnrt {
namespace V2_0 {

extern "C" INnrtDevice *NnrtDeviceImplGetInstance(void)
{
    return new (std::nothrow) NnrtDeviceService();
}

NnrtDeviceService::NnrtDeviceService()
    : libHandle_(nullptr),
    createVdiFunc_(nullptr),
    destroyVdiFunc_(nullptr),
    vdiImpl_(nullptr)
{
    int32_t ret = LoadVdi();
    if (ret == HDF_SUCCESS) {
        vdiImpl_ = createVdiFunc_();
        if (vdiImpl_ == nullptr) {
            HDF_LOGE("vdiImpl_ is null and return\n");
            return;
        }
    } else {
        HDF_LOGE("Load nnrt device VDI failed, lib: %s", NNRT_DEVICE_VDI_LIBRARY);
    }
}

NnrtDeviceService::~NnrtDeviceService()
{
    if ((destroyVdiFunc_ != nullptr) && (vdiImpl_ != nullptr)) {
        destroyVdiFunc_(vdiImpl_);
    }
    if (libHandle_ != nullptr) {
        dlclose(libHandle_);
    }
}

int32_t NnrtDeviceService::LoadVdi()
{
    const char* errStr = dlerror();
    if (errStr != nullptr) {
        HDF_LOGE("nnrt loadvdi, clear earlier dlerror: %s", errStr);
    }
    libHandle_ = dlopen(NNRT_DEVICE_VDI_LIBRARY, RTLD_LAZY);
    if (libHandle_ == nullptr) {
        errStr = dlerror();
        printf("opendl failed, error:%s\n", errStr);
    }
    if (!checkNullpointer(libHandle_)) {
        return HDF_FAILURE;
    }

    createVdiFunc_ = reinterpret_cast<CreateNnrtDeviceVdiFunc>(dlsym(libHandle_, "CreateNnrtDeviceVdi"));
    if (createVdiFunc_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            HDF_LOGE("nnrt CreateNnrtDeviceVdi dlsym error: %s", errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }

    destroyVdiFunc_ = reinterpret_cast<DestroyNnrtDeviceVdiFunc>(dlsym(libHandle_, "DestroyNnrtDeviceVdi"));
    if (destroyVdiFunc_ == nullptr) {
        errStr = dlerror();
        if (errStr != nullptr) {
            HDF_LOGE("composer DestroyNnrtDeviceVdi dlsym error: %s", errStr);
        }
        dlclose(libHandle_);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::GetDeviceName(std::string& name)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->GetDeviceName(name);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::GetVendorName(std::string& name)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->GetVendorName(name);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::GetDeviceType(DeviceType& deviceType)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->GetDeviceType(deviceType);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::GetDeviceStatus(DeviceStatus& status)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->GetDeviceStatus(status);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::GetSupportedOperation(const Model& model, std::vector<bool>& ops)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->GetSupportedOperation(model, ops);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::IsFloat16PrecisionSupported(bool& isSupported)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->IsFloat16PrecisionSupported(isSupported);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::IsPerformanceModeSupported(bool& isSupported)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->IsPerformanceModeSupported(isSupported);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::IsPrioritySupported(bool& isSupported)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->IsPrioritySupported(isSupported);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::IsDynamicInputSupported(bool& isSupported)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->IsDynamicInputSupported(isSupported);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::PrepareModel(const Model& model, const ModelConfig& config,
    sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->PrepareModel(model, config, preparedModel);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::IsModelCacheSupported(bool& isSupported)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->IsModelCacheSupported(isSupported);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::PrepareModelFromModelCache(const std::vector<SharedBuffer>& modelCache,
    const ModelConfig& config, sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->PrepareModelFromModelCache(modelCache, config, preparedModel);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_ERR_NOT_SUPPORT;
}

int32_t NnrtDeviceService::PrepareOfflineModel(const std::vector<SharedBuffer>& offlineModels,
    const ModelConfig& config, sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->PrepareOfflineModel(offlineModels, config, preparedModel);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::AllocateBuffer(uint32_t length, SharedBuffer& buffer)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->AllocateBuffer(length, buffer);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

int32_t NnrtDeviceService::ReleaseBuffer(const SharedBuffer& buffer)
{
    NNRT_TRACE;

    if (!checkNullpointer(vdiImpl_)) {
        return HDF_FAILURE;
    }
    int32_t ret =  vdiImpl_->ReleaseBuffer(buffer);
    NNRT_CHK_RETURN(ret != HDF_SUCCESS, HDF_FAILURE, HDF_LOGE(" fail"));

    return HDF_SUCCESS;
}

} // V2_0
} // Nnrt
} // HDI
} // OHOS
