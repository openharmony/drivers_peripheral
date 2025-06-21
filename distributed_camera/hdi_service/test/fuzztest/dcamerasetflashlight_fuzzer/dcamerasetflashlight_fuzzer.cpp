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

#include "dcamerasetflashlight_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "dcamera_host.h"

namespace OHOS {
namespace DistributedHardware {

void DcameraSetFlashlightFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::string cameraId(reinterpret_cast<const char*>(data), size);
    bool isEnable = *(reinterpret_cast<const int32_t*>(data)) % 2; // 2: bool value
    DCameraHost::GetInstance()->SetFlashlight(cameraId, isEnable);
    float level = 0.0;
    DCameraHost::GetInstance()->SetFlashlight_V1_2(level);
    DCameraHost::GetInstance()->PreCameraSwitch(cameraId);
    PrelaunchConfig config;
    int32_t operationMode = 0;
    DCameraHost::GetInstance()->PrelaunchWithOpMode(config, operationMode);
    DCameraHost::GetInstance()->Prelaunch(config);
}

void DCameraSetFlashlightV1_2FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(float))) {
        return;
    }
    FuzzedDataProvider fuzzProvider(data, size);
    float level = fuzzProvider.ConsumeFloatingPoint<float>();
    DCameraHost::GetInstance()->SetFlashlight_V1_2(level);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraSetFlashlightFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraSetFlashlightV1_2FuzzTest(data, size);
    return 0;
}