/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TEST_DISPLAY_H
#define TEST_DISPLAY_H
#include <gtest/gtest.h>
#include "camera.h"
#include <thread>
#include <map>
#include <cstdio>
#include <climits>
#include "v1_0/types.h"
#include "v1_0/icamera_host.h"
#include "v1_0/icamera_device.h"
#include "v1_0/istream_operator.h"
#include "v1_0/stream_operator_proxy.h"
#include "idevice_manager.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "display_format.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include "buffer_manager.h"
#include "stream_customer.h"
#include "camera_host_callback.h"
#include "camera_device_callback.h"
#include "stream_operator_callback.h"
#include "v1_0/istream_operator_callback.h"
#include "v1_0/icamera_host.h"
#include "v1_0/camera_host_proxy.h"
#include "ibuffer.h"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <getopt.h>
#include <linux/fb.h>
#include <linux/videodev2.h>
#include <mutex>
#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <vector>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <securec.h>
#include <surface_buffer.h>
#include <ibuffer_producer.h>
#include <fstream>
#define PATH_MAX 128
#define BUFFERSCOUNT 8
#define CAMERA_BUFFER_QUEUE_IPC 654320
#define RANGE_LIMIT(x) ((x) > 255 ? 255 : ((x) < 0 ? 0 : (x)))
#define PREVIEW_WIDTH 640
#define PREVIEW_HEIGHT 480
#define CAPTURE_WIDTH 1280
#define CAPTURE_HEIGHT 960
#define VIDEO_WIDTH 1280
#define VIDEO_HEIGHT 960
#define ANALYZE_WIDTH 640
#define ANALYZE_HEIGHT 480

constexpr int DEFAULT_STREAM_ID = 1001;
constexpr int INVALID_VALUE_TEST = 2147483647;

using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::Camera;
class TestCameraBase {
public:
    // This should get the size setting according to the bottom layer
    unsigned int bufSize_ = 614400; // 614400:bufSize
    unsigned char* displayBuf_ = nullptr;
    unsigned int camframeV4l2Exit_ = 1;
    unsigned int numOfReadyFrames_ = 0;
    unsigned int bufCont_ = BUFFERSCOUNT;
    pthread_cond_t subThreadReadyCond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t subThreadReadyMutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t previewThreadId_;
    std::mutex readyFrameLock_;

    int fbFd_ = 0;
    int readIndex_ = 0;
    struct fb_var_screeninfo vinfo_;
    struct fb_fix_screeninfo finfo_;
    
    std::shared_ptr<StreamCustomer> streamCustomerPreview_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerCapture_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerVideo_ = nullptr;
    std::shared_ptr<StreamCustomer> streamCustomerAnalyze_ = nullptr;
    OHOS::sptr<IStreamOperator> streamOperator = nullptr;
    std::shared_ptr<IStreamOperatorCallback> streamOperatorCallback = nullptr;
    CaptureInfo captureInfo = {};
    std::vector<StreamInfo> streamInfos = {};
    StreamInfo streamInfo = {};
    StreamInfo streamInfoPre = {};
    StreamInfo streamInfoVideo = {};
    StreamInfo streamInfoCapture = {};
    StreamInfo streamInfoAnalyze = {};
    OHOS::sptr<ICameraHost> cameraHost = nullptr;
    OHOS::sptr<ICameraDevice> cameraDevice = nullptr;
    std::shared_ptr<CameraAbility> ability = nullptr;
    std::vector<uint8_t> ability_ = {};
    std::vector<int> captureIds;
    std::vector<std::string> cameraIds;
    std::vector<int> streamIds;
    std::vector<StreamIntent> intents;
    enum {
        STREAM_ID_PREVIEW = 1000, // 1000:preview streamID
        STREAM_ID_CAPTURE,
        STREAM_ID_VIDEO,
        STREAM_ID_ANALYZE,
        CAPTURE_ID_PREVIEW = 2000, // 2000:preview captureId
        CAPTURE_ID_CAPTURE,
        CAPTURE_ID_VIDEO,
        CAPTURE_ID_ANALYZE
    };
    enum {
        PREVIEW_MODE = 0,
        CAPTURE_MODE,
        VIDEO_MODE,
        ANALYZE_MODE,
    };
    CamRetCode rc;
    int initFlag = 0;
    bool status = false;

public:
    TestCameraBase();
    uint64_t GetCurrentLocalTimeStamp();
    int32_t SaveYUV(char* type, unsigned char* buffer, int32_t size);
    int DoFbMunmap(unsigned char* addr);
    unsigned char* DoFbMmap(int* pmemfd);
    void FBLog();
    OHOS::Camera::RetCode FBInit();
    void ProcessImage(unsigned char* p, unsigned char* fbp);
    void LcdDrawScreen(unsigned char* displayBuf, unsigned char* addr);
    void BufferCallback(unsigned char* addr, int choice);
    void Init();
    void UsbInit();
    std::shared_ptr<CameraAbility> GetCameraAbility();
    std::shared_ptr<CameraAbility> GetCameraAbilityById(std::string cameraId);
    void OpenUsbCamera();
    CamRetCode SelectOpenCamera(std::string cameraId);
    void Close();
    void OpenCamera();
    void DefaultInfosPreview();
    void DefaultInfosCapture();
    void AchieveStreamOperator();
    void StartStream(std::vector<StreamIntent> intents);
    void StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds);
    void StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming);
    float CalTime(struct timeval start, struct timeval end);
    void StoreImage(const unsigned char *bufStart, const uint32_t size) const;
    void StoreVideo(const unsigned char *bufStart, const uint32_t size) const;
    void OpenVideoFile();
    void PrintFaceDetectInfo(const unsigned char *bufStart, const uint32_t size) const;
    void CloseFd();
    int videoFd_ = -1;
};

#ifndef CAMERA_BUILT_ON_OHOS_LITE
class DemoCameraDeviceCallback : public ICameraDeviceCallback {
public:
    DemoCameraDeviceCallback() = default;
    virtual ~DemoCameraDeviceCallback() = default;
    int32_t OnError(ErrorType type, int32_t errorCode) override;
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;

    void PrintStabiliInfo(const std::vector<uint8_t>& result);
    void PrintFpsInfo(const std::vector<uint8_t>& result);
    void DealCameraMetadata(const std::vector<uint8_t> &settings);
};

class DemoCameraHostCallback : public ICameraHostCallback {
public:
    DemoCameraHostCallback() = default;
    virtual ~DemoCameraHostCallback() = default;

public:
    int32_t OnCameraStatus(const std::string& cameraId, CameraStatus status) override;

    int32_t OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status) override;

    int32_t OnCameraEvent(const std::string& cameraId, CameraEvent event) override;
};

class DemoStreamOperatorCallback : public IStreamOperatorCallback {
public:
    DemoStreamOperatorCallback() = default;
    virtual ~DemoStreamOperatorCallback() = default;

public:
    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override;
    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos) override;
    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override;
    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override;
};

#endif
#endif
