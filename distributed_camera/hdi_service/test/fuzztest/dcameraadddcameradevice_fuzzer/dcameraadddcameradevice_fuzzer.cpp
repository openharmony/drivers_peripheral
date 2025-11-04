/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "dcameraadddcameradevice_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "dcamera_host.h"
#include "v1_1/id_camera_provider_callback.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {

void DcameraAddDCameraDeviceFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    size_t deviceIdLen = fdp.ConsumeIntegralInRange<size_t>(0, 64);
    std::string deviceId = fdp.ConsumeBytesAsString(deviceIdLen);

    size_t dhIdLen = fdp.ConsumeIntegralInRange<size_t>(0, 64);
    std::string dhId = fdp.ConsumeBytesAsString(dhIdLen);

    std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString(2048);
    std::string srcAbilityInfo = fdp.ConsumeRemainingBytesAsString();

    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    sptr<IDCameraProviderCallback> callback = nullptr;
    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    auto temp = DCameraHost::GetInstance();
    temp->dCameraDeviceMap_.clear();

    // Call target APIs with fully fuzzed data
    temp->AddDCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo, callback);
    temp->AddDeviceParamCheck(dhBase, sinkAbilityInfo, srcAbilityInfo, callback);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraAddDCameraDeviceFuzzTest(data, size);
    return 0;
}