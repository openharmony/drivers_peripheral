/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HDI_COMMON_V1_2_H
#define HDI_COMMON_V1_2_H

#include "v1_2/types.h"
#include "v1_2/icamera_host.h"
#include "v1_2/icamera_device.h"
#include "v1_2/istream_operator.h"
#include "v1_2/camera_host_proxy.h"
#include "v1_2/image_process_service_proxy.h"
#include "v1_2/iimage_process_session.h"
#include "v1_2/iimage_process_callback.h"
#include "hdi_common_v1_1.h"

namespace OHOS::Camera {

enum Numbers {
    ZERO,
    ONE,
    TWO,
    THREE,
    FOUR,
    FIVE,
    SIX,
    SEVEN,
    EIGHT,
    NINE,
    TEN,
    SIXTEEN = 16,
};

using namespace OHOS::HDI::Camera::V1_2;
class HdiCommonV1_2 : public OHOS::Camera::HdiCommonV1_1 {
public:
    void Init();
    int32_t DefferredImageTestInit();
    void Open(int cameraId);
    void OpenCameraV1_2(int cameraId);
    void GetCameraMetadata(int cameraId);
    void DefaultSketch(std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosPreviewV1_2(std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosSketch(std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming);
    void StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds);
    OHOS::sptr<OHOS::HDI::Camera::V1_2::ICameraHost> serviceV1_2 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> cameraDeviceV1_2 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::IStreamOperatorCallback> streamOperatorCallbackV1_2 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::ICameraHostCallback> hostCallbackV1_2 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperator_V1_2 = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoSketch = nullptr;
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessSession> imageProcessSession_ = nullptr;
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessService> imageProcessService_ = nullptr;
    class TestImageProcessCallback;
    sptr<TestImageProcessCallback> imageProcessCallback_ = nullptr;
    std::vector<std::string> pendingImageIds_;
    int analyzeFormat = PIXEL_FMT_YCRCB_420_SP;
    int streamIdSketch = 105;
    int sketchWidth = 640;
    int sketchHeight = 480;
    int captureIdSketch = 2050;
    uint32_t itemCapacity = 100;
    uint32_t dataCapacity = 2000;
    uint32_t dataCount = 1;

    float statusV1_2;
    static FlashlightStatus statusCallback;

    class TestStreamOperatorCallbackV1_2 : public OHOS::HDI::Camera::V1_2::IStreamOperatorCallback {
    public:
        TestStreamOperatorCallbackV1_2() = default;
        virtual ~TestStreamOperatorCallbackV1_2() = default;
        int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamId) override;
        int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo> &infos) override;
        int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo> &infos) override;
        int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t> &streamIds, uint64_t timestamp) override;
        int32_t OnCaptureStarted_V1_2(int32_t captureId,
            const std::vector<HDI::Camera::V1_2::CaptureStartedInfo> &infos) override;
    };

    class TestCameraHostCallbackV1_2 : public OHOS::HDI::Camera::V1_2::ICameraHostCallback {
    public:
        TestCameraHostCallbackV1_2() = default;
        virtual ~TestCameraHostCallbackV1_2() = default;

        int32_t OnCameraStatus(const std::string& cameraId, CameraStatus status) override;
        int32_t OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status) override;
        int32_t OnFlashlightStatus_V1_2(FlashlightStatus status) override;
        int32_t OnCameraEvent(const std::string& cameraId, CameraEvent event) override;
    };

    class TestImageProcessCallback : public OHOS::HDI::Camera::V1_2::IImageProcessCallback {
    public:
        int32_t coutProcessDone_ = 0;
        int32_t coutStatusChanged_ = 0;
        int32_t countError_ = 0;
        std::string curImageId_;
        int32_t curErrorCode_ = 0;
        bool isDone_ = false;
        OHOS::HDI::Camera::V1_2::ImageBufferInfo curImageBufferInfo_;
        OHOS::HDI::Camera::V1_2::SessionStatus curStatus_;
        TestImageProcessCallback() = default;
        virtual ~TestImageProcessCallback() = default;
        int32_t OnProcessDone(const std::string& imageId,
            const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer) override;
        int32_t OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status) override;
        int32_t OnError(const std::string& imageId, OHOS::HDI::Camera::V1_2::ErrorCode errorCode) override;
    };
};
}
#endif