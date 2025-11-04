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
#include "dcameragetdevicebydhbase_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "dcamera_host.h"
#include "dcamera_provider.h"

namespace OHOS {
namespace DistributedHardware {

constexpr size_t MAX_STRING_LEN = 4096;

void DcameraGetDeviceByDHBaseFuzzTest(FuzzedDataProvider& fdp)
{
    std::string deviceId = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);
    std::string dhId = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);
    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;
    
    std::string cameraId = deviceId + "__" + dhId;
    std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);
    std::string sourceAbilityInfo = fdp.ConsumeRandomLengthString(MAX_STRING_LEN); // 修复
    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo,
        sourceAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }
    DCameraHost::GetInstance()->dCameraDeviceMap_.emplace(cameraId, dcameraDevice);
    DCameraHost::GetInstance()->GetDCameraDeviceByDHBase(dhBase);
}

void DCameraProviderGetCallbackBydhBaseFuzzTest(FuzzedDataProvider& fdp)
{
    std::string deviceId = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);
    std::string dhId = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);

    DHBase dhBase;
    dhBase.deviceId_ = deviceId;
    dhBase.dhId_ = dhId;

    std::string sinkAbilityInfo = fdp.ConsumeRandomLengthString(MAX_STRING_LEN);
    std::string sourceAbilityInfo = fdp.ConsumeRandomLengthString(MAX_STRING_LEN); // 修复
    OHOS::sptr<DCameraDevice> dcameraDevice(new (std::nothrow) DCameraDevice(dhBase, sinkAbilityInfo,
        sourceAbilityInfo));
    if (dcameraDevice == nullptr) {
        return;
    }

    std::string cameraId = deviceId + "__" + dhId;
    DCameraHost::GetInstance()->dCameraDeviceMap_.emplace(cameraId, dcameraDevice);

    OHOS::sptr<DCameraProvider> provider = DCameraProvider::GetInstance();
    if (provider == nullptr) {
        return;
    }

    sptr<IDCameraProviderCallback> callback = provider->GetCallbackBydhBase(dhBase);
    if (callback != nullptr) {
        callback->OpenSession(dhBase);
    }
}

void ClearGlobalState()
{
    DCameraHost::GetInstance()->dCameraDeviceMap_.clear();
}

}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    
    bool runFirstTest = fdp.ConsumeBool();
    if (runFirstTest) {
        OHOS::DistributedHardware::DcameraGetDeviceByDHBaseFuzzTest(fdp);
    } else {
        OHOS::DistributedHardware::DCameraProviderGetCallbackBydhBaseFuzzTest(fdp);
    }
    OHOS::DistributedHardware::ClearGlobalState();
    return 0;
}