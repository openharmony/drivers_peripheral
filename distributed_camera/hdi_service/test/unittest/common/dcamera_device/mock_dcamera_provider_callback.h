/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_DCAMERA_PROVIDER_CALLBACK_H
#define MOCK_DCAMERA_PROVIDER_CALLBACK_H

#include "v1_1/id_camera_provider_callback.h"

namespace OHOS {
namespace DistributedHardware {

using namespace OHOS::HDI::DistributedCamera::V1_1;

class MockDCameraProviderCallback : public IDCameraProviderCallback {
public:
    MockDCameraProviderCallback() = default;
    virtual ~MockDCameraProviderCallback() = default;

    int32_t OpenSession(const DHBase& dhBase) { return DCamRetCode::SUCCESS; }
    int32_t CloseSession(const DHBase& dhBase) { return DCamRetCode::SUCCESS; }
    int32_t ConfigureStreams(const DHBase& dhBase, const std::vector<DCStreamInfo>& streamInfos)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t ReleaseStreams(const DHBase& dhBase, const std::vector<int>& streamIds) { return DCamRetCode::SUCCESS; }
    int32_t StartCapture(const DHBase& dhBase, const std::vector<DCCaptureInfo>& captureInfos)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t StopCapture(const DHBase& dhBase, const std::vector<int>& streamIds) { return DCamRetCode::SUCCESS; }
    int32_t UpdateSettings(const DHBase& dhBase, const std::vector<DCameraSettings>& settings)
    {
        return DCamRetCode::SUCCESS;
    }
    int32_t NotifyEvent(const DHBase& dhBase, const DCameraHDFEvent& event) { return DCamRetCode::SUCCESS; }
};

} // namespace DistributedHardware
} // namespace OHOS
#endif // MOCK_DCAMERA_PROVIDER_CALLBACK_H