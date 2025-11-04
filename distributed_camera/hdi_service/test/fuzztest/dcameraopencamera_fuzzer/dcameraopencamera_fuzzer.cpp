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

#include "dcameraopencamera_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dcamera_host.h"
#include "v1_0/icamera_device_callback.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {

class DemoCameraDeviceCallback : public ICameraDeviceCallback {
public:
    DemoCameraDeviceCallback() = default;
    virtual ~DemoCameraDeviceCallback() = default;
    int32_t OnError(ErrorType type, int32_t errorCode) override
    {
        return 0;
    }
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override
    {
        return 0;
    }
};

void DcameraOpenCameraFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string dhId = fdp.ConsumeRandomLengthString();
    std::string cameraId = deviceId + "__" + dhId;
    
    sptr<ICameraDeviceCallback> callbackObj(new DemoCameraDeviceCallback());
    sptr<HDI::Camera::V1_0::ICameraDevice> demoCameraDevice = nullptr;
    
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString();
    std::string sourceAbilityInfo = fdp.ConsumeRemainingBytesAsString();

    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo,
        sourceAbilityInfo));
    if (dcameraDevice != nullptr) {
        DCameraHost::GetInstance()->dCameraDeviceMap_[cameraId] = dcameraDevice;
    }
    DCameraHost::GetInstance()->OpenCamera(cameraId, callbackObj, demoCameraDevice);
    sptr<HDI::Camera::V1_1::ICameraDevice> demoCameraDevice_V1_1 = nullptr;
    DCameraHost::GetInstance()->OpenCamera_V1_1(cameraId, callbackObj, demoCameraDevice_V1_1);
    sptr<HDI::Camera::V1_2::ICameraDevice> demoCameraDevice_V1_2 = nullptr;
    DCameraHost::GetInstance()->OpenCamera_V1_2(cameraId, callbackObj, demoCameraDevice_V1_2);
    sptr<HDI::Camera::V1_3::ICameraDevice> demoCameraDevice_V1_3 = nullptr;
    DCameraHost::GetInstance()->OpenCamera_V1_3(cameraId, callbackObj, demoCameraDevice_V1_3);
    DCameraHost::GetInstance()->OpenSecureCamera(cameraId, callbackObj, demoCameraDevice_V1_3);
    OHOS::HDI::Camera::V1_3::CameraDeviceResourceCost resourceCost;
    DCameraHost::GetInstance()->GetResourceCost(cameraId, resourceCost);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedHardware::DcameraOpenCameraFuzzTest(data, size);
    return 0;
}