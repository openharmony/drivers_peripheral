/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expected in compliance with the License.
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

#ifndef UT_COMMON_H
#define UT_COMMON_H

#include "v1_3/types.h"
#include "v1_3/icamera_host.h"
#include "v1_3/icamera_device.h"
#include "v1_3/istream_operator.h"
#include "v1_3/camera_host_proxy.h"
#include "hdi_common_v1_2.h"

namespace OHOS::Camera {

using namespace OHOS::HDI::Camera::V1_3;
class HdiCommonV1_3 : public OHOS::Camera::HdiCommonV1_2 {
public:
    void Init();
    void Open(int cameraId);
    void OpenSecureCamera(int cameraId);
    void Close();
    void GetCameraMetadata(int cameraId);
    void DefaultMeta(std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosProfessionalCapture(std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosMeta(std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void StartProfessionalStream(std::vector<StreamIntent> intents, uint8_t professionalMode);
    void StartStream(std::vector<StreamIntent> intents,
        OHOS::HDI::Camera::V1_3::OperationMode mode = OHOS::HDI::Camera::V1_3::NORMAL);
    void StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming);
    void StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds);
    OHOS::sptr<OHOS::HDI::Camera::V1_3::ICameraHost> serviceV1_3 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_3::ICameraDevice> cameraDeviceV1_3 = nullptr;
    class TestStreamOperatorCallbackV1_3;
    OHOS::sptr<TestStreamOperatorCallbackV1_3> streamOperatorCallbackV1_3 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_3::IStreamOperator> streamOperator_V1_3 = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoMeta = nullptr;
    int streamIdMeta = 106;
    int metaWidth = 1920;
    int metaHeight = 1080;
    int captureIdMeta = 2060;
    uint32_t itemCapacity = 100;
    uint32_t dataCapacity = 2000;
    uint32_t dataCount = 1;

    class TestStreamOperatorCallbackV1_3 : public OHOS::HDI::Camera::V1_3::IStreamOperatorCallback {
    public:
        std::shared_ptr<CameraMetadata> streamResultMeta = nullptr;
        TestStreamOperatorCallbackV1_3() = default;
        virtual ~TestStreamOperatorCallbackV1_3() = default;
        int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamId) override;
        int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo> &infos) override;
        int32_t OnCaptureEndedExt(int32_t captureId,
            const std::vector<HDI::Camera::V1_3::CaptureEndedInfoExt> &infos) override;
        int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo> &infos) override;
        int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t> &streamIds, uint64_t timestamp) override;
        int32_t OnCaptureStarted_V1_2(int32_t captureId,
            const std::vector<HDI::Camera::V1_2::CaptureStartedInfo> &infos) override;
        int32_t OnCaptureReady(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
        int32_t OnFrameShutterEnd(int32_t captureId, const std::vector<int32_t>& streamIds,
            uint64_t timestamp) override;
        int32_t OnResult(int32_t streamId, const std::vector<uint8_t>& result) override;
    };

    using StreamResultCallback = std::function<void (int32_t, const std::shared_ptr<CameraMetadata>)>;
    static StreamResultCallback streamResultCallback_;
};
}
#endif