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

#include "dcameradevicegetsettings_fuzzer.h"

#include "dcamera_device.h"
#include "v1_1/dcamera_types.h"
#include "fuzzer/FuzzedDataProvider.h"
#include <string>
#include <vector>

namespace OHOS {
namespace DistributedHardware {

namespace {
    constexpr size_t MAX_ID_LENGTH = 64;
    constexpr size_t MAX_ABILITY_LENGTH = 1024;
}

void DcameraDeviceGetSettingsFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString(MAX_ID_LENGTH);
    std::string dhId = fdp.ConsumeRandomLengthString(MAX_ID_LENGTH);

    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString(MAX_ABILITY_LENGTH);
    std::string srcAbilityInfo = fdp.ConsumeRandomLengthString(MAX_ABILITY_LENGTH);

    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo, srcAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    std::vector<uint8_t> results;
    dcameraDevice->GetSettings(results);
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraDeviceGetSettingsFuzzTest(data, size);
    return 0;
}