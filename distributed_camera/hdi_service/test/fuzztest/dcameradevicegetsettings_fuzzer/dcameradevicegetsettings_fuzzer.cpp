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

#include "dcameradevicegetsettings_fuzzer.h"

#include "dcamera_device.h"
#include "dcamera_host.h"
#include "v1_0/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
void DcameraDeviceGetSettingsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::vector<uint8_t> results;
    results.push_back(*(reinterpret_cast<const uint8_t*>(data)));

    const std::string abilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new DCameraDevice(dhBase, abilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    dcameraDevice->GetSettings(results);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraDeviceGetSettingsFuzzTest(data, size);
    return 0;
}

