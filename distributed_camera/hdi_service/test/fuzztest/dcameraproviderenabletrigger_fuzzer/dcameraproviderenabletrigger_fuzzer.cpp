/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "dcameraproviderenabletrigger_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "dcamera_provider.h"
#include "v1_1/id_camera_provider_callback.h"

namespace OHOS {
namespace DistributedHardware {
constexpr const char *TEST_ABILITY_JSON =
    R"({"SinkAbility": "SinkAbilityTest", "SourceCodec": "SourceCodecTest"})";
constexpr size_t MAX_ID_LEN = 128;

void DcameraProviderEnableTriggerFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    DHBase dhBase;
    dhBase.deviceId_ = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    dhBase.dhId_ = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    std::string abilityInfo = fdp.ConsumeRemainingBytesAsString();
    sptr<IDCameraProviderCallback> callbackObj = nullptr;
    DCameraProvider::GetInstance()->EnableDCameraDevice(dhBase, abilityInfo, callbackObj);
    DCameraProvider::GetInstance()->EnableDCameraDevice(
        dhBase, TEST_ABILITY_JSON, callbackObj);
    DHBase emptyBase;
    DCameraProvider::GetInstance()->EnableDCameraDevice(
        emptyBase, abilityInfo, callbackObj);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DistributedHardware::DcameraProviderEnableTriggerFuzzTest(data, size);
    return 0;
}
