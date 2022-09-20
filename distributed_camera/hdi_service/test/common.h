/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef DISTRIBUTED_CAMERA_TEST_COMMON_H
#define DISTRIBUTED_CAMERA_TEST_COMMON_H

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "camera_metadata_info.h"
#include "distributed_hardware_log.h"
#include "idistributed_hardware_source.h"
#include "iservice_registry.h"
#include "securec.h"
#include "surface.h"

#include "constants.h"
#include "dcamera.h"
#include "dcamera_host.h"
#include "v1_0/dcamera_types.h"
#include "v1_0/icamera_device.h"
#include "v1_0/icamera_host.h"
#include "v1_0/ioffline_stream_operator.h"
#include "v1_0/istream_operator.h"
#include "v1_0/types.h"

namespace OHOS {
namespace DistributedHardware {
using namespace OHOS::HDI::DistributedCamera::V1_0;
using namespace OHOS::HDI::Camera::V1_0;
class Test {
public:
    void Init();
    void Open();
    void Close();
    std::shared_ptr<CameraAbility> GetCameraAbility();
    uint64_t GetCurrentLocalTimeStamp();
    int32_t SaveYUV(const char* type, const void* buffer, int32_t size);
    int32_t SaveVideoFile(const char* type, const void* buffer, int32_t size, int32_t operationMode);
    void StartStream(std::vector<StreamIntent> intents);
    void StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming);
    void StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds);
    void StopOfflineStream(int captureId);
    void GetCameraMetadata();

    void SetPreviewStreamInfo();
    void SetVideoStreamInfo();
    void SetPhotoStreamInfo();

    OHOS::sptr<DStreamOperatorCallback> streamOperatorCallback = nullptr;
    OHOS::sptr<DCameraHostCallback> hostCallback = nullptr;
    OHOS::sptr<DCameraDeviceCallback> deviceCallback = nullptr;
    OHOS::sptr<IStreamOperator> streamOperator = nullptr;
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
    OHOS::sptr<IStreamOperatorCallback> offlineStreamOperatorCallback = nullptr;
    CaptureInfo captureInfo;
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo_pre;
    StreamInfo streamInfo_video;
    StreamInfo streamInfo_capture;
    std::vector<std::string> cameraIds;
    int streamId_preview = 1000;
    int streamId_preview_double = 1001;
    int streamId_capture = 1010;
    int streamId_video = 1020;
    int captureId_preview = 2000;
    int captureId_preview_double = 2001;
    int captureId_capture = 2010;
    int captureId_video = 2020;
    int preview_format = PIXEL_FMT_YCRCB_420_SP;
    int video_format = PIXEL_FMT_YCRCB_420_SP;
    int snapshot_format = PIXEL_FMT_YCRCB_420_SP;
    int preview_width = 1920;
    int preview_height = 1080;
    int snapshot_width = 4160;
    int snapshot_height = 3120;
    int video_width = 1920;
    int video_height = 1080;
    std::vector<int> captureIds;
    std::vector<int> streamIds;
    std::vector<StreamIntent> intents;
    OHOS::HDI::Camera::V1_0::CamRetCode rc;
    OHOS::sptr<OHOS::HDI::Camera::V1_0::ICameraHost> service = nullptr;
    std::vector<uint8_t> ability;
    OHOS::sptr<ICameraDevice> cameraDevice = nullptr;
    bool status;
    int previewBufCnt = 0;
    int32_t videoFd = -1;
    class StreamConsumer;
    std::map<OHOS::HDI::Camera::V1_0::StreamIntent, std::shared_ptr<StreamConsumer>> consumerMap_ = {};

    class TestBufferConsumerListener : public IBufferConsumerListener {
    public:
        TestBufferConsumerListener() {}
        ~TestBufferConsumerListener() {}
        void OnBufferAvailable() {}
    };

    class StreamConsumer {
    public:
        OHOS::sptr<OHOS::IBufferProducer> CreateProducer(std::function<void(void*, uint32_t)> callback);
        void TakeSnapshot()
        {
            shotCount_++;
        }
        void WaitSnapshotEnd()
        {
            std::cout << "ready to wait" << std::endl;
            std::unique_lock<std::mutex> l(l_);
            cv_.wait(l, [this]() { return shotCount_ == 0; });
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
        OHOS::sptr<OHOS::Surface> consumer_ = nullptr;
        std::thread* consumerThread_ = nullptr;
        std::function<void(void*, uint32_t)> callback_ = nullptr;
    };
};

class DCameraMockRegisterCallback : public RegisterCallback {
public:
    virtual ~DCameraMockRegisterCallback() = default;
    int32_t OnRegisterResult(const std::string &devId, const std::string &dhId, int32_t status,
        const std::string &data)
    {
        cout << "Register devId: " << devId << " dhId: " << dhId << " status:" << status << endl;
        return 0;
    }
};

class DCameraMockUnRegisterCallback : public UnregisterCallback {
public:
    virtual ~DCameraMockUnRegisterCallback() = default;
    int32_t OnUnregisterResult(const std::string &devId, const std::string &dhId, int32_t status,
        const std::string &data)
    {
        cout << "UnRegister devId: " << devId << " dhId: " << dhId << " status:" << status << endl;
        return 0;
    }
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // DISTRIBUTED_CAMERA_TEST_COMMON_H
