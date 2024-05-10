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

#include "dcameraenabledcameradevice_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dcamera_provider.h"
#include "v1_0/id_camera_provider_callback.h"

namespace OHOS {
namespace DistributedHardware {

class MockDCameraProviderCallbackImpl : public IDCameraProviderCallback {
public:
    MockDCameraProviderCallbackImpl(const std::string& devId, const std::string& dhId) : devId_(devId), dhId_(dhId)
    {
    }
    ~MockDCameraProviderCallbackImpl() = default;

    int32_t OpenSession(const DHBase& dhBase)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t CloseSession(const DHBase& dhBase)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t ConfigureStreams(const DHBase& dhBase, const std::vector<DCStreamInfo>& streamInfos)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t ReleaseStreams(const DHBase& dhBase, const std::vector<int>& streamIds)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t StartCapture(const DHBase& dhBase, const std::vector<DCCaptureInfo>& captureInfos)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t StopCapture(const DHBase& dhBase, const std::vector<int>& streamIds)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t UpdateSettings(const DHBase& dhBase, const std::vector<DCameraSettings>& settings)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t NotifyEvent(const DHBase& dhBase, const DCameraHDFEvent& event)
    {
        return DCamRetCode::SUCCESS;
    }

private:
    std::string devId_;
    std::string dhId_;
};

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

    sptr<IDCameraProviderCallback> callback = new MockDCameraProviderCallbackImpl(deviceId, dhId);

    DCameraProvider::GetInstance()->EnableDCameraDevice(dhBase, abilityInfo, callback);
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

