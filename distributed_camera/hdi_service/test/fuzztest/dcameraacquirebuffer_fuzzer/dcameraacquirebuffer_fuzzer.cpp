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

#include "dcameraacquirebuffer_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "dcamera_provider.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
void DcameraAcquireBufferFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string deviceId = "1";
    std::string dhId = "2";
    int32_t streamId = 1;
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;
    FuzzedDataProvider fdp(data, size);
    DCameraBuffer buffer;
    buffer.index_ = fdp.ConsumeIntegral<int32_t>();
    buffer.size_ = fdp.ConsumeIntegral<uint32_t>();
    buffer.bufferHandle_ = sptr<NativeBuffer>(new NativeBuffer());

    DCameraProvider::GetInstance()->AcquireBuffer(dhBase, streamId, buffer);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraAcquireBufferFuzzTest(data, size);
    return 0;
}

