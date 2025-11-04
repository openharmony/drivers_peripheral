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

#include "dcameraupdatesettings_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dcamera_provider.h"
#include "dcamera_host.h"
#include "dcamera_device.h"
#include "v1_1/dcamera_types.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
const DCSettingsType DC_VALID_TYPES[] = {
    DCSettingsType::UPDATE_METADATA, DCSettingsType::ENABLE_METADATA, DCSettingsType::DISABLE_METADATA,
    DCSettingsType::METADATA_RESULT, DCSettingsType::SET_FLASH_LIGHT, DCSettingsType::FPS_RANGE,
    DCSettingsType::UPDATE_FRAME_METADATA
};

constexpr size_t MAX_ID_LEN = 64;
constexpr size_t MAX_URL_LEN = 1024;
constexpr size_t MAX_SETTING_VALUE_LEN = 256;
constexpr size_t MAX_SETTINGS_COUNT = 10;
constexpr const char* CAM_ID_SEPARATOR = "__";

} // namespace

void DcameraUpdateSettingsFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    auto host = DCameraHost::GetInstance();
    auto provider = DCameraProvider::GetInstance();
    if (host == nullptr || provider == nullptr) {
        return;
    }
    host->dCameraDeviceMap_.clear();

    DHBase dhBaseToUpdate;
    dhBaseToUpdate.deviceId_ = fdp.ConsumeRandomLengthString(MAX_ID_LEN);
    dhBaseToUpdate.dhId_ = fdp.ConsumeRandomLengthString(MAX_ID_LEN);

    if (fdp.ConsumeBool()) {
        std::string sink = fdp.ConsumeRandomLengthString(MAX_URL_LEN);
        std::string source = fdp.ConsumeRandomLengthString(MAX_URL_LEN);
        std::string camId = dhBaseToUpdate.deviceId_ + CAM_ID_SEPARATOR + dhBaseToUpdate.dhId_;

        OHOS::sptr<DCameraDevice> dev(new (std::nothrow) DCameraDevice(dhBaseToUpdate, sink, source));
        if (dev != nullptr) {
            host->dCameraDeviceMap_.emplace(camId, dev);
        }
    }
    std::vector<DCameraSettings> settings;
    size_t settingsCount = fdp.ConsumeIntegralInRange<size_t>(0, MAX_SETTINGS_COUNT);
    
    for (size_t i = 0; i < settingsCount; ++i) {
        DCameraSettings setting;
        setting.type_ = fdp.PickValueInArray(DC_VALID_TYPES);
        setting.value_ = fdp.ConsumeRandomLengthString(MAX_SETTING_VALUE_LEN);
        settings.push_back(setting);
    }
    provider->UpdateSettings(dhBaseToUpdate, settings);
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraUpdateSettingsFuzzTest(data, size);
    return 0;
}