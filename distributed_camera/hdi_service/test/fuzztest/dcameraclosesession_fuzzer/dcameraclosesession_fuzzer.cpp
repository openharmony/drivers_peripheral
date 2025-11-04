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

#include "dcameraclosesession_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include "dcamera_provider.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
void DcameraCloseSessionFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    size_t deviceIdLength = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    std::string deviceId = fdp.ConsumeBytesAsString(deviceIdLength);

    std::string dhId = fdp.ConsumeRemainingBytesAsString();
    
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    DCameraProvider::GetInstance()->CloseSession(dhBase);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraCloseSessionFuzzTest(data, size);
    return 0;
}