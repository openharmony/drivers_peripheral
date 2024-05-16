/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dcameraonsettingsresult_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dcamera_provider.h"
#include "v1_1/dcamera_types.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
const uint32_t DC_TYPE_SIZE = 7;
const DCSettingsType dcTypeFuzz[DC_TYPE_SIZE] = {
    DCSettingsType::UPDATE_METADATA, DCSettingsType::ENABLE_METADATA, DCSettingsType::DISABLE_METADATA,
    DCSettingsType::METADATA_RESULT, DCSettingsType::SET_FLASH_LIGHT, DCSettingsType::FPS_RANGE,
    DCSettingsType::UPDATE_FRAME_METADATA
};
}
void DcameraOnSettingsResultFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string deviceId = "1";
    std::string dhId = "2";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;
    DCameraSettings result;
    result.type_ = dcTypeFuzz[data[0] % DC_TYPE_SIZE];
    result.value_ = std::string(reinterpret_cast<const char*>(data), size);

    DCameraProvider::GetInstance()->OnSettingsResult(dhBase, result);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraOnSettingsResultFuzzTest(data, size);
    return 0;
}

