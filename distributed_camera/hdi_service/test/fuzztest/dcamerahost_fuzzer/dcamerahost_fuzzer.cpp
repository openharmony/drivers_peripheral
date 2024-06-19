/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "dcamerahost_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dcamera_host.h"

namespace OHOS {
namespace DistributedHardware {
void DCameraGetCameraAbilityFromDevFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string cameraId = "1__2";
    DHBase dhBase;
    dhBase.deviceId_ = "1";
    dhBase.dhId_ = "2";
    std::string sinkAbilityInfo = "sink";
    std::string sourceAbilityInfo = "source";
    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo,
        sourceAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    DCameraHost::GetInstance()->dCameraDeviceMap_.emplace(cameraId, dcameraDevice);
    std::shared_ptr<CameraAbility> cameraAbility = make_shared<CameraAbility>(1, 1);
    DCameraHost::GetInstance()->GetCameraAbilityFromDev(cameraId, cameraAbility);
}

void DCameraAddDeviceParamCheckFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string deviceId = "1";
    std::string dhId = "2";
    std::string sinkAbilityInfo(reinterpret_cast<const char*>(data), size);
    std::string srcAbilityInfo(reinterpret_cast<const char*>(data), size);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;
    sptr<IDCameraProviderCallback> callback;
    DCameraHost::GetInstance()->AddDeviceParamCheck(dhBase, sinkAbilityInfo, srcAbilityInfo, callback);
}

void DCameraGetCamDevNumFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DCameraHost::GetInstance()->GetCamDevNum();
}

void DCameraIsCameraIdInvalidFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string cameraId = "1__2";
    DHBase dhBase;
    dhBase.deviceId_ = "1";
    dhBase.dhId_ = "2";
    std::string sinkAbilityInfo = "sink";
    std::string sourceAbilityInfo = "source";
    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo,
        sourceAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    DCameraHost::GetInstance()->dCameraDeviceMap_.emplace(cameraId, dcameraDevice);
    DCameraHost::GetInstance()->IsCameraIdInvalid(cameraId);
}

void DCameraGetCameraIdByDHBaseFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DHBase dhBase;
    dhBase.deviceId_ = "1";
    dhBase.dhId_ = "2";
    DCameraHost::GetInstance()->GetCameraIdByDHBase(dhBase);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DCameraGetCameraAbilityFromDevFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraAddDeviceParamCheckFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraGetCamDevNumFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraIsCameraIdInvalidFuzzTest(data, size);
    OHOS::DistributedHardware::DCameraGetCameraIdByDHBaseFuzzTest(data, size);
    return 0;
}
