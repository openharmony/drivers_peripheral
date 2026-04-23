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

#ifndef OHOS_HDI_NNRT_V2_0_NNRT_DEVICE_SERVICE_H
#define OHOS_HDI_NNRT_V2_0_NNRT_DEVICE_SERVICE_H

#include "innrt_device_vdi.h"
#include "ashmem.h"
#include "nnrt_common.h"

namespace OHOS {
namespace HDI {
namespace Nnrt {
namespace V2_0 {
using namespace OHOS::HDI::Nnrt::V2_0;

class NnrtDeviceService : public INnrtDevice {
public:
    NnrtDeviceService();
    ~NnrtDeviceService();

    int32_t GetDeviceName(std::string& name) override;
    int32_t GetVendorName(std::string& name) override;
    int32_t GetDeviceType(DeviceType& deviceType) override;
    int32_t GetDeviceStatus(DeviceStatus& status) override;
    int32_t GetSupportedOperation(const Model& model, std::vector<bool>& ops) override;
    int32_t IsFloat16PrecisionSupported(bool& isSupported) override;
    int32_t IsPerformanceModeSupported(bool& isSupported) override;
    int32_t IsPrioritySupported(bool& isSupported) override;
    int32_t IsDynamicInputSupported(bool& isSupported) override;
    int32_t PrepareModel(const Model& model, const ModelConfig& config,
                      sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel) override;
    int32_t IsModelCacheSupported(bool& isSupported) override;
    int32_t PrepareModelFromModelCache(const std::vector<SharedBuffer>& modelCache, const ModelConfig& config,
                      sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel) override;
    int32_t PrepareOfflineModel(const std::vector<SharedBuffer>& offlineModels, const ModelConfig& config,
                      sptr<OHOS::HDI::Nnrt::V2_0::IPreparedModel>& preparedModel) override;
    int32_t AllocateBuffer(uint32_t length, SharedBuffer& buffer) override;
    int32_t ReleaseBuffer(const SharedBuffer& buffer) override;
private:
    int32_t LoadVdi();

private:
    void* libHandle_;
    CreateNnrtDeviceVdiFunc createVdiFunc_;
    DestroyNnrtDeviceVdiFunc destroyVdiFunc_;
    INnrtDeviceVdi* vdiImpl_;
};

} // V2_0
} // Nnrt
} // HDI
} // OHOS

#endif // OHOS_HDI_NNRT_V2_0_NNRT_DEVICE_SERVICE_H