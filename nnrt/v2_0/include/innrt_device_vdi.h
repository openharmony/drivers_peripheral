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

#ifndef OHOS_HDI_NNRT_V2_0_INNRT_DEVICES_VDI_H
#define OHOS_HDI_NNRT_V2_0_INNRT_DEVICES_VDI_H

#include "nnrt/v2_0/innrt_device.h"
#include "nnrt/v2_0/iprepared_model.h"
#include "nnrt/v2_0/model_types.h"
#include "nnrt/v2_0/nnrt_types.h"
#include "nnrt/v2_0/nnrt_device_stub.h"

#include <hdf_base.h>

namespace OHOS {
namespace HDI {
namespace Nnrt {
namespace V2_0 {
using namespace OHOS::HDI::Nnrt::V2_0;

#define NNRT_DEVICE_VDI_LIBRARY "libnpu_vdi_impl.z.so"

class INnrtDeviceVdi {
public:
    virtual ~INnrtDeviceVdi() = default;

    virtual int32_t GetDeviceName(std::string& name) = 0;
    virtual int32_t GetVendorName(std::string& name) = 0;
    virtual int32_t GetDeviceType(DeviceType& deviceType) = 0;
    virtual int32_t GetDeviceStatus(DeviceStatus& status) = 0;
    virtual int32_t GetSupportedOperation(const Model& model, std::vector<bool>& ops) = 0;
    virtual int32_t IsFloat16PrecisionSupported(bool& isSupported) = 0;
    virtual int32_t IsPerformanceModeSupported(bool& isSupported) = 0;
    virtual int32_t IsPrioritySupported(bool& isSupported) = 0;
    virtual int32_t IsDynamicInputSupported(bool& isSupported) = 0;
    virtual int32_t PrepareModel(const Model& model, const ModelConfig& config,
                      sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel) = 0;
    virtual int32_t IsModelCacheSupported(bool& isSupported) = 0;
    virtual int32_t PrepareModelFromModelCache(const std::vector<SharedBuffer>& modelCache, const ModelConfig& config,
                      sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel) = 0;
    virtual int32_t PrepareOfflineModel(const std::vector<SharedBuffer>& offlineModels, const ModelConfig& config,
                      sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel) = 0;
    virtual int32_t AllocateBuffer(uint32_t length, SharedBuffer& buffer) = 0;
    virtual int32_t ReleaseBuffer(const SharedBuffer& buffer) = 0;
};

using CreateNnrtDeviceVdiFunc = INnrtDeviceVdi* (*)();
using DestroyNnrtDeviceVdiFunc = void (*)(INnrtDeviceVdi* vdi);
extern "C" INnrtDeviceVdi* CreateNnrtDeviceVdi();
extern "C" void DestroyNnrtDeviceVdi(INnrtDeviceVdi* vdi);

} // V2_0
} // Nnrt
} // HDI
} // OHOS

#endif // OHOS_HDI_NNRT_V2_0_INNRT_DEVICES_VDI_H