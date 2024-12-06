/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dcamerahostsetcallback_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dcamera_host.h"

namespace OHOS {
namespace DistributedHardware {
class DemoCameraHostCallback : public ICameraHostCallback {
public:
    DemoCameraHostCallback() = default;
    virtual ~DemoCameraHostCallback() = default;

    int32_t OnCameraStatus(const std::string& cameraId, CameraStatus status)
    {
        return 0;
    }

    int32_t OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status)
    {
        return 0;
    }

    int32_t OnCameraEvent(const std::string& cameraId, CameraEvent event)
    {
        return 0;
    }
};

void DcameraHostSetCallbackFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string foo(reinterpret_cast<const char*>(data), size);
    foo = "source";
    sptr<ICameraHostCallback> callbackObj(new DemoCameraHostCallback());
    DCameraHost::GetInstance()->SetCallback(callbackObj);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DcameraHostSetCallbackFuzzTest(data, size);
    return 0;
}

