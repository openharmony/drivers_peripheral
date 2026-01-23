/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "dcameraenableresult_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "fuzzer/FuzzedDataProvider.h"
#include "dcamera_device.h"
#include "dcamera_host.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
void DcameraEnableResultFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    std::string deviceId = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 256));
    std::string dhId = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 256));

    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::vector<int32_t> results;
    size_t numResults = fdp.ConsumeIntegralInRange<size_t>(0, 100);
    for (size_t i = 0; i < numResults; ++i) {
        results.push_back(fdp.ConsumeIntegral<int32_t>());
    }

    std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, 512));
    std::string srcAbilityInfo = fdp.ConsumeRemainingBytesAsString();

    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    dcameraDevice->EnableResult(results);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraEnableResultFuzzTest(data, size);
    return 0;
}