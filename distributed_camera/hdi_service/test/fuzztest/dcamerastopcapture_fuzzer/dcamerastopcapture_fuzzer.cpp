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

#include "dcamerastopcapture_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dcamera_provider.h"
#include "v1_1/dcamera_types.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
void DcameraStopCaptureFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t streamId = fdp.ConsumeIntegral<int32_t>();
    
    // Consume data for deviceId string, limiting its length to avoid exhausting the buffer too quickly
    std::string deviceId = fdp.ConsumeRandomLengthString(fdp.remaining_bytes() / 2);
    
    // Consume data for dhId string, using all remaining bytes
    std::string dhId = fdp.ConsumeRemainingBytesAsString();
    
    std::vector<int> streamIds;
    streamIds.push_back(streamId);
    
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    DCameraProvider::GetInstance()->StopCapture(dhBase, streamIds);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraStopCaptureFuzzTest(data, size);
    return 0;
}