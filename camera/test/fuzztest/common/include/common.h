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

#ifndef COMMON_H
#define COMMON_H

#include <stdlib.h>
#include <thread>
#include <iostream>
#include <unistd.h>
#include <sys/time.h>
#include <map>
#include <vector>
#include <fcntl.h>
#include "camera.h"
#include "v1_2/types.h"
#include "v1_3/types.h"
#include "metadata_utils.h"
#include "v1_2/icamera_host.h"
#include "v1_2/icamera_device.h"
#include "v1_2/istream_operator.h"
#include "v1_2/camera_host_proxy.h"
#include "v1_2/image_process_service_proxy.h"
#include "v1_3/icamera_host.h"
#include "v1_3/icamera_device.h"
#include "v1_0/ioffline_stream_operator.h"
#include "display_format.h"
#include "video_key_info.h"
#include "iconsumer_surface.h"

namespace OHOS::Camera {
enum CameraUtConstants {
    UT_SLEEP_TIME = 2,
    UT_SECOND_TIMES = 3,
    UT_SECOND_TIMES_MAX = 100,
    UT_TUNNEL_MODE = 5,
    UT_DATA_SIZE = 8,
    UT_PREVIEW_SIZE = 3112960,
};

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
};

enum ImageDataSaveSwitch {
    SWITCH_OFF,
    SWITCH_ON,
};

enum CameraIds {
    DEVICE_0, // rear camera
    DEVICE_1, // front camera
    DEVICE_2,
    DEVICE_3,
    DEVICE_4,
    DEVICE_5,
    DEVICE_6,
};

using namespace OHOS::HDI::Camera::V1_0;
class CameraManager {
public:
    void Init();
    void InitV1_2();
    void InitV1_3();
    void Open();
    void OpenV1_2();
    void OpenV1_3();
    void OpenCameraV1_2();
    void Close();
    void GetCameraMetadata();
    void DefaultPreview(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultCapture(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultSketch(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosPreview(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosPreviewV1_2(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosCapture(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosAnalyze(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosVideo(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void DefaultInfosSketch(
        std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> &infos);
    void StartStream(std::vector<StreamIntent> intents);
    uint64_t GetCurrentLocalTimeStamp();
    int32_t DumpImageFile(int streamId, std::string suffix, const void* buffer, int32_t size);
    void StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming);
    void StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds);
    OHOS::sptr<OHOS::Camera::ICameraHost> service = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_1::ICameraHost> serviceV1_1 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::ICameraHost> serviceV1_2 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_3::ICameraHost> serviceV1_3 = nullptr;
    OHOS::sptr<ICameraDevice> cameraDevice = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_1::ICameraDevice> cameraDeviceV1_1 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::ICameraDevice> cameraDeviceV1_2 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_3::ICameraDevice> cameraDeviceV1_3 = nullptr;
    OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::IStreamOperatorCallback> streamOperatorCallbackV1_2 = nullptr;
    OHOS::sptr<ICameraHostCallback> hostCallback = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::ICameraHostCallback> hostCallbackV1_2 = nullptr;
    OHOS::sptr<IStreamOperator> streamOperator = nullptr;
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperator_V1_1 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_2::IStreamOperator> streamOperator_V1_2 = nullptr;
    class DemoCameraDeviceCallback;
    OHOS::sptr<DemoCameraDeviceCallback> deviceCallback = nullptr;
    std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfos;
    std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfosV1_1;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::PrelaunchConfig> prelaunchConfig = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoV1_1 = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfo = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoSnapshot = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoCapture = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoAnalyze = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoPre = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoVideo = nullptr;
    std::shared_ptr<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1> streamInfoSketch = nullptr;
    std::shared_ptr<CaptureInfo> captureInfo = nullptr;
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessSession> imageProcessSession_ = nullptr;
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessService> imageProcessService_ = nullptr;
    class TestImageProcessCallback;
    sptr<TestImageProcessCallback> imageProcessCallback_ = nullptr;
    std::vector<std::string> pendingImageIds_;
    int previewFormat = PIXEL_FMT_YCRCB_420_SP;
    int videoFormat = PIXEL_FMT_YCRCB_420_SP;
    int snapshotFormat = PIXEL_FMT_YCRCB_420_SP;
    int analyzeFormat = PIXEL_FMT_YCRCB_420_SP;
    int streamIdPreview = 100;
    int streamIdCapture = 101;
    int streamIdSketch = 105;
    int captureWidth = 1280;
    int captureHeight = 960;
    int sketchWidth = 640;
    int sketchHeight = 480;
    int captureIdPreview = 2000;
    int captureIdSketch = 2050;
    int previewWidth = 1920;
    int previewHeight = 1080;
    int captureIdCapture = 2010;
    int captureIdVideo = 2020;
    int streamIdVideo = 102;
    int videoHeight = 1080;
    int videoWidth = 1920;
    int analyzeWidth = 1920;
    int analyzeHeight = 1080;
    int snapshotWidth = 4160;
    int snapshotHeight = 3120;
    int streamIdAnalyze = 103;
    std::vector<int> captureIds;
    std::vector<int> streamIds;
    int32_t imageDataSaveSwitch = SWITCH_OFF;
    uint32_t itemCapacity = 100;
    uint32_t dataCapacity = 2000;
    uint32_t dataCount = 1;

    int32_t rc;
    bool status;
    float statusV1_2;
    static FlashlightStatus statusCallback;
    std::vector<std::string> cameraIds;
    std::vector<uint8_t> abilityVec = {};
    std::shared_ptr<CameraMetadata> ability = nullptr;
    std::vector<StreamIntent> intents;
    class StreamConsumer;
    std::map<OHOS::Camera::StreamIntent, std::shared_ptr<StreamConsumer>> consumerMap_ = {};
    class TestBufferConsumerListener : public OHOS::IBufferConsumerListener {
    public:
        TestBufferConsumerListener() {}
        ~TestBufferConsumerListener() {}
        void OnBufferAvailable()
        {
            hasAvailablebuffer = true;
        }
        bool checkBufferAvailable()
        {
            if (hasAvailablebuffer) {
                hasAvailablebuffer = false;
                return true;
            }
            return false;
        }
    private:
        bool hasAvailablebuffer = false;
    };

    class StreamConsumer {
    public:
        void CalculateFps(int64_t timestamp, int32_t streamId);
        void CreateProducerForBuffer(OHOS::sptr<OHOS::SurfaceBuffer> buffer, int64_t timestamp);
        OHOS::sptr<OHOS::IBufferProducer> CreateProducer(std::function<void(void*, uint32_t)> callback);
        OHOS::sptr<BufferProducerSequenceable> CreateProducerSeq(std::function<void(void*, uint32_t)> callback);
        void TakeSnapshoe()
        {
            shotCount_++;
        }
        void WaitSnapshotEnd()
        {
            std::cout << "ready to wait" << std::endl;
            std::unique_lock<std::mutex> l(l_);
            cv_.wait(l, [this]() {return shotCount_ == 0; });
        }
        ~StreamConsumer()
        {
            running_ = false;
            if (consumerThread_ != nullptr) {
                consumerThread_->join();
                delete consumerThread_;
            }
        }
    public:
        std::atomic<uint64_t> shotCount_ = 0;
        std::mutex l_;
        std::condition_variable cv_;
        bool running_ = true;
        OHOS::sptr<OHOS::IConsumerSurface> consumer_ = nullptr;
        std::thread* consumerThread_ = nullptr;
        std::function<void(void*, uint32_t)> callback_ = nullptr;
        bool isFirstCalculateFps_ = false;
        int timestampCount_ = 0;
        static int64_t g_timestamp[2];
        int64_t intervalTimestamp_ = 0;
        const int64_t ONESECOND_OF_MICROSECOND_UNIT = 1000000000;
        int64_t interval_ = ONESECOND_OF_MICROSECOND_UNIT;
    };

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