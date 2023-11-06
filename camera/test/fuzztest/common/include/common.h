/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <stdlib.h>
#include <thread>
#include <iostream>
#include <unistd.h>
#include <map>
#include <vector>
#include <fcntl.h>
#include "camera.h"
#include "v1_2/types.h"
#include "metadata_utils.h"
#include "v1_2/icamera_host.h"
#include "v1_1/icamera_device.h"
#include "v1_1/istream_operator.h"
#include "v1_2/camera_host_proxy.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
class CameraManager {
public:
    void Init();
    void InitV1_2();
    void Open();
    void OpenV1_2();
    void Close();
    void GetCameraMetadata();
    OHOS::sptr<OHOS::Camera::ICameraHost> service = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_1::ICameraHost> serviceV1_1 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::ICameraHost> serviceV1_2 = nullptr;
    OHOS::sptr<ICameraHostCallback> hostCallback = nullptr;
    OHOS::sptr<ICameraDevice> cameraDevice = nullptr;
    OHOS::sptr<ICameraDeviceCallback> deviceCallback = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_1::ICameraDevice> cameraDeviceV1_1 = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoCapture = nullptr;

    OHOS::sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperator_V1_1 = nullptr;
    OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoV1_1 = nullptr;
    std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfosV1_1;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::PrelaunchConfig> prelaunchConfig = nullptr;

    int32_t rc;
    std::vector<std::string> cameraIds;
    std::vector<uint8_t> abilityVec = {};
    std::shared_ptr<CameraMetadata> ability = nullptr;

    using ResultCallback = std::function<void (uint64_t, const std::shared_ptr<CameraMetadata>)>;
    static ResultCallback resultCallback_;

    class TestStreamOperatorCallback : public IStreamOperatorCallback {
    public:
        TestStreamOperatorCallback() = default;
        virtual ~TestStreamOperatorCallback() = default;
        int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamId) override;
        int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo> &infos) override;
        int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo> &infos) override;
        int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t> &streamIds, uint64_t timestamp) override;
    };

    class DemoCameraDeviceCallback : public ICameraDeviceCallback {
    public:
        DemoCameraDeviceCallback() = default;
        virtual ~DemoCameraDeviceCallback() = default;

        int32_t OnError(ErrorType type, int32_t errorMsg) override;
        int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t> &result) override;
    };

    class TestCameraHostCallback : public ICameraHostCallback {
    public:
        TestCameraHostCallback() = default;
        virtual ~TestCameraHostCallback() = default;

        int32_t OnCameraStatus(const std::string& cameraId, CameraStatus status) override;
        int32_t OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status) override;
        int32_t OnCameraEvent(const std::string& cameraId, CameraEvent event) override;
    };
};
}
