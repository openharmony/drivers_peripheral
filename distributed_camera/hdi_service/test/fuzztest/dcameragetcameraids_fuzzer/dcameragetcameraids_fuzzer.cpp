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

#include "dcameragetcameraids_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "dcamera_host.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {

namespace {
    constexpr size_t MAX_ID_LEN = 64;
    constexpr size_t MAX_DEVICES_COUNT = 10;
    constexpr size_t MAX_URL_LEN = 1024;
    constexpr const char* CAM_ID_SEPARATOR = "__";
    constexpr size_t MIN_JUNK_ENTRIES = 1;
    constexpr size_t MAX_JUNK_ENTRIES = 5;
    constexpr size_t MAX_JUNK_ID_LEN = 32;
} // namespace

void DCameraGetCameraIdsFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto host = DCameraHost::GetInstance();
    host->dCameraDeviceMap_.clear();
    size_t deviceCount = fdp.ConsumeIntegralInRange<size_t>(0, MAX_DEVICES_COUNT);
    for (size_t i = 0; i < deviceCount; ++i) {
        DHBase dhBase;
        dhBase.deviceId_ = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
        dhBase.dhId_ = fdp.ConsumeRandomLengthString(MAX_ID_LEN);

        std::string sink = fdp.ConsumeRandomLengthString(MAX_URL_LEN);
        std::string source = fdp.ConsumeRandomLengthString(MAX_URL_LEN);
        std::string camId = dhBase.deviceId_ + CAM_ID_SEPARATOR + dhBase.dhId_;

        OHOS::sptr<DCameraDevice> dev(new (std::nothrow) DCameraDevice(dhBase, sink, source));
        if (dev == nullptr) {
            continue;
        }
        host->dCameraDeviceMap_.emplace(camId + std::to_string(i), dev);
    }

    std::vector<std::string> cameraIds;

    if (fdp.ConsumeBool()) {
        size_t junkCount = fdp.ConsumeIntegralInRange<size_t>(MIN_JUNK_ENTRIES, MAX_JUNK_ENTRIES);
        for (size_t i = 0; i < junkCount; ++i) {
            cameraIds.push_back(fdp.ConsumeRandomLengthString(MAX_JUNK_ID_LEN));
        }
    }
    host->GetCameraIds(cameraIds);
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DCameraGetCameraIdsFuzzTest(data, size);
    return 0;
}