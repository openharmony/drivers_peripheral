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

#include "dcameraenabledcameradevice_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dcamera_provider.h"
#include "v1_1/id_camera_provider_callback.h"

namespace OHOS {
namespace DistributedHardware {
constexpr const char* TEST_ABILITY = R"({"SinkAbility": "SinkAbilityTest",
    "SourceCodec": "SourceCodecTest"
    })";

void DcameraEnableDCameraDeviceFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId = "1";
    std::string dhId = "2";
    std::string abilityInfo(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    sptr<IDCameraProviderCallback> callback;

    DCameraProvider::GetInstance()->EnableDCameraDevice(dhBase, abilityInfo, callback);
    dhBase.deviceId_ = "";
    std::string emptyAbilityInfo = "";
    DCameraProvider::GetInstance()->EnableDCameraDevice(dhBase, emptyAbilityInfo, callback);
    std::string sinkAbilityInfo = "";
    std::string sourceCodecInfo = "";
    DCameraProvider::GetInstance()->GetAbilityInfo(abilityInfo, sinkAbilityInfo, sourceCodecInfo);
    DCameraProvider::GetInstance()->GetAbilityInfo(TEST_ABILITY, sinkAbilityInfo, sourceCodecInfo);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraEnableDCameraDeviceFuzzTest(data, size);
    return 0;
}

