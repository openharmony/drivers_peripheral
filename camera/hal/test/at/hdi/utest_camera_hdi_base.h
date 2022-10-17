/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UTEST_CAMERA_HDI_BASE_H
#define UTEST_CAMERA_HDI_BASE_H

#include <thread>
#include <unistd.h>
#include <vector>
#include <map>
#include <gtest/gtest.h>
#include <hdf_log.h>
#include <osal_mem.h>
#include "securec.h"

#include "camera.h"
#include "camera_metadata_info.h"
#include "metadata_utils.h"
#include "ibuffer.h"
#include "v1_0/ioffline_stream_operator.h"
#include <surface.h>
#include <display_type.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include "v1_0/icamera_host.h"
#include "v1_0/istream_operator.h"
#include "camera_host_callback.h"
#include "camera_device_callback.h"
#include "v1_0/icamera_device.h"
#include "stream_operator_callback.h"
#include "v1_0/istream_operator_callback.h"

#ifdef CAMERA_BUILT_ON_OHOS_LITE
#include "camera_device.h"
#include "camera_host.h"
#include "stream_operator.h"
#else
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "v1_0/camera_host_proxy.h"
#endif

using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::Camera;

class CameraHdiBaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    void SetUp(void);
    void TearDown(void);

protected:
    virtual bool InitCameraHost();
    virtual bool GetCameraDevice();
    virtual bool GetStreamOperator();
    virtual bool GetCameraIds();
    int32_t SaveToFile(const std::string& path, const void* buffer, int32_t size) const;
    uint64_t GetCurrentLocalTimeStamp() const;
    int32_t SaveYUV(const char* type, const void* buffer, int32_t size);

protected:
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    std::shared_ptr<CameraHost> cameraHost_ = nullptr;
    std::shared_ptr<ICameraDevice> cameraDevice_ = nullptr;
    std::shared_ptr<IStreamOperator> streamOperator_ = nullptr;
#else
    sptr<ICameraHost> cameraHost_ = nullptr;
    sptr<ICameraDevice> cameraDevice_ = nullptr;
    sptr<IStreamOperator> streamOperator_ = nullptr;
#endif

    std::vector<std::string> cameraIds_;
    int previewBufCnt = 0;
    int32_t videoFd = -1;
};

class DemoCameraDeviceCallback : public ICameraDeviceCallback {
public:
    DemoCameraDeviceCallback() = default;
    virtual ~DemoCameraDeviceCallback() = default;
    int32_t OnError(ErrorType type, int32_t errorCode) override;
    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result) override;
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

#endif // UTEST_CAMERA_HDI_BASE_H
