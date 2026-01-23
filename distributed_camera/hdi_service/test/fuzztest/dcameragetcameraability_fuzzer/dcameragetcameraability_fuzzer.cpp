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

#include "dcameragetcameraability_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "dcamera_host.h"
#include "fuzzer/FuzzedDataProvider.h"
#include <string>
#include <vector>

namespace OHOS {
namespace DistributedHardware {
void DcameraGetCameraAbilityFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto temp = DCameraHost::GetInstance();
    temp->dCameraDeviceMap_.clear();

    std::string cameraId = fdp.ConsumeRandomLengthString(64);
    if (fdp.ConsumeBool()) {
        std::string deviceId = fdp.ConsumeRandomLengthString(64);
        std::string dhId = fdp.ConsumeRandomLengthString(64);
        DHBase dhBase;
        dhBase.deviceId_ = deviceId;
        dhBase.dhId_ = dhId;

        std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString(1024);
        std::string sourceAbilityInfo = fdp.ConsumeRandomLengthString(1024);

        OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase,
            sinkAbilityInfo, sourceAbilityInfo));
        
        if (dcameraDevice != nullptr) {
            temp->dCameraDeviceMap_[cameraId] = dcameraDevice;
        }
    }
    std::vector<uint8_t> cameraAbility;
    temp->GetCameraAbility(cameraId, cameraAbility);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraGetCameraAbilityFuzzTest(data, size);
    return 0;
}