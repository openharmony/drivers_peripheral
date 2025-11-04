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

#include "dcameradisabledcameradevice_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include "dcamera_provider.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {

void DcameraDisableDCameraDeviceFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string dhId = fdp.ConsumeRandomLengthString();
    
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    DCameraProvider::GetInstance()->DisableDCameraDevice(dhBase);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraDisableDCameraDeviceFuzzTest(data, size);
    return 0;
}