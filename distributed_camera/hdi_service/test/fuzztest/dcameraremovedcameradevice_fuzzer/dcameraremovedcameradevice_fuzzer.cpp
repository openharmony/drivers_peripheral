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

#include "dcameraremovedcameradevice_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dcamera_host.h"

namespace OHOS {
namespace DistributedHardware {

void DcameraRemoveDCameraDeviceFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId = "1";
    std::string dhId = "2";
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;
    std::string cameraId = "1__2";
    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string sourceAbilityInfo(reinterpret_cast<const char*>(data), size);
    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo,
        sourceAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    DCameraHost::GetInstance()->dCameraDeviceMap_.emplace(cameraId, dcameraDevice);

    DCameraHost::GetInstance()->RemoveDCameraDevice(dhBase);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraRemoveDCameraDeviceFuzzTest(data, size);
    return 0;
}