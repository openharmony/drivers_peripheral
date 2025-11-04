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

#include "dcamerareleasestreams_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include "dcamera_provider.h"
#include "v1_1/dcamera_types.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
void DcameraReleaseStreamsFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string dhId = fdp.ConsumeRandomLengthString();

    std::vector<int> streamIds;
    size_t numStreams = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    for (size_t i = 0; i < numStreams; ++i) {
        streamIds.push_back(fdp.ConsumeIntegral<int>());
    }

    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    DCameraProvider::GetInstance()->ReleaseStreams(dhBase, streamIds);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraReleaseStreamsFuzzTest(data, size);
    return 0;
}