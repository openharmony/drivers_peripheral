/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "utest_offline_stream_operator.h"
#include "camera.h"
#include "camera_metadata_info.h"
#include "ibuffer.h"
#include "idevice_manager.h"
#include "if_system_ability_manager.h"
#include "v1_0/ioffline_stream_operator.h"
#include "iservice_registry.h"
#include <surface.h>
#include <display_type.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define SURFACE_ID (12345 + 666 + 2333)

using namespace OHOS;
using namespace std;
using namespace testing::ext;

const int CAMERA_BUFFER_QUEUE_IPC = 654320;
uint64_t GetCurrentLocalTimeStampOFL()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return tmp.count();
}

int32_t SaveToFile(const char* type, const void* buffer, int32_t size)
{
    int ret;
    char path[PATH_MAX] = {0};
    ret = sprintf_s(path, PATH_MAX, "/mnt/%s_%lld.yuv", type, GetCurrentLocalTimeStampOFL());
    if (ret < 0) {
        std::cout << "sprintf_s failed, errno = " << strerror(errno) << std::endl;
        return -1;
    }
    int imgFd = open(path, O_RDWR | O_CREAT, 00766);
    if (imgFd == -1) {
        std::cout << "open file failed, errno = " << strerror(errno) << std::endl;
        return -1;
    }

    ret = write(imgFd, buffer, size);
    if (ret == -1) {
        std::cout << "write file failed, errno = " << strerror(errno) << std::endl;
        close(imgFd);
        return -1;
    }

    close(imgFd);
    return 0;
}

void OffileStreamOperatorImplTest::SetUpTestCase(void)
{
    std::cout << "Camera::StreamOperatorImp SetUpTestCase" << std::endl;
}

void OffileStreamOperatorImplTest::TearDownTestCase(void)
{
    std::cout << "Camera::StreamOperatorImp TearDownTestCase" << std::endl;
}

void OffileStreamOperatorImplTest::SetUp(void)
{
    bool ret = InitCameraHost();
    if (!ret) {
        std::cout << "OffileStreamOperatorImplTest init camerahost failed" << std::endl;
        return;
    }

    ret = GetCameraIds();
    if (!ret) {
        std::cout << "OffileStreamOperatorImplTest init GetCameraIds failed" << std::endl;
        return;
    }

    ret = GetCameraDevice();
    if (!ret) {
        std::cout << "OffileStreamOperatorImplTest init GetCameraDevice failed" << std::endl;
        return;
    }

    ret = GetStreamOperator();
    if (!ret) {
        std::cout << "OffileStreamOperatorImplTest init GetStreamOperator failed" << std::endl;
        return;
    }
}

void OffileStreamOperatorImplTest::TearDown(void)
{
    std::cout << "Camera::StreamOperatorImp TearDown.." << std::endl;
}

HWTEST_F(OffileStreamOperatorImplTest, UTestPreviewAndSnapshotCombineCapture, TestSize.Level0)
{
    sptr<OHOS::IBufferProducer> producer;
    sptr<OHOS::IBufferProducer> producer_;
    std::vector<StreamInfo> streamInfos;
    StreamInfo streamInfo = {};
    streamInfo.streamId_ = 1201;
    streamInfo.width_ = 720;
    streamInfo.height_ = 480;
    streamInfo.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfo.dataspace_ = 8;
    streamInfo.intent_ = PREVIEW;
    streamInfo.tunneledMode_ = 5;
    std::shared_ptr<StreamConsumer> previewConsumer = std::make_shared<StreamConsumer>();
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    producer = previewConsumer->CreateProducer([this](OHOS::SurfaceBuffer* buffer) {
        SaveYUV("preview", buffer->GetVirAddr(), buffer->GetSize());
    });
#else
    producer = previewConsumer->CreateProducer([this](void* addr, uint32_t size) {
        SaveYUV("preview", addr, size);
    });
#endif
    streamInfo.bufferQueue_ = new BufferProducerSequenceable(producer);
    streamInfo.bufferQueue_->producer_->SetQueueSize(8);
    streamInfos.push_back(streamInfo);

    StreamInfo streamInfoSnapshot = {};
    streamInfoSnapshot.streamId_ = 1202;
    streamInfoSnapshot.width_ = 720;
    streamInfoSnapshot.height_ = 480;
    streamInfoSnapshot.format_ = PIXEL_FMT_YCRCB_420_SP;
    streamInfoSnapshot.dataspace_ = 8;
    streamInfoSnapshot.intent_ = STILL_CAPTURE;
    streamInfoSnapshot.tunneledMode_ = 5;
    std::shared_ptr<StreamConsumer> snapshotConsumer = std::make_shared<StreamConsumer>();;
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    producer = snapshotConsumer->CreateProducer([this](OHOS::SurfaceBuffer* buffer) {
        SaveYUV("preview", buffer->GetVirAddr(), buffer->GetSize());
    });
#else
    producer = snapshotConsumer->CreateProducer([this](void* addr, uint32_t size) {
        SaveYUV("preview", addr, size);
    });
#endif
    streamInfoSnapshot.bufferQueue_ = new BufferProducerSequenceable(producer_);
    streamInfo.bufferQueue_->producer_->SetQueueSize(8);
    streamInfos.push_back(streamInfoSnapshot);

    CamRetCode rc = (CamRetCode)streamOperator_->CreateStreams(streamInfos);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);
    std::shared_ptr<CameraMetadata> modeSetting = std::make_shared<CameraMetadata>(2, 128);
    int64_t expoTime = 0;
    modeSetting->addEntry(OHOS_SENSOR_EXPOSURE_TIME, &expoTime, 1);
    int64_t colorGains[4] = {0};
    modeSetting->addEntry(OHOS_SENSOR_COLOR_CORRECTION_GAINS, &colorGains, 4);

    std::vector<uint8_t> setting;
    OHOS::Camera::MetadataUtils::ConvertMetadataToVec(modeSetting, setting);
    rc = (CamRetCode)streamOperator_->CommitStreams(NORMAL, setting);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    std::vector<std::string> cameraIds;
    rc = (CamRetCode)cameraHost_->GetCameraIds(cameraIds);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    std::vector<uint8_t> ability;
    std::string cameraId = cameraIds.front();
    rc = (CamRetCode)cameraHost_->GetCameraAbility(cameraId, ability);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    int captureId = 2020;
    CaptureInfo captureInfo = {};
    captureInfo.streamIds_ = {streamInfo.streamId_, streamInfoSnapshot.streamId_};
    captureInfo.captureSetting_ = ability;
    captureInfo.enableShutterCallback_ = false;
    rc = (CamRetCode)streamOperator_->Capture(captureId, captureInfo, true);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);
    sleep(5);
#ifdef CAMERA_BUILT_ON_OHOS_LITE
    std::shared_ptr<IStreamOperatorCallback> streamOperatorCallback = std::make_shared<DemoStreamOperatorCallback>();
    std::shared_ptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
#else
    OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback = new DemoStreamOperatorCallback();
    OHOS::sptr<IOfflineStreamOperator> offlineStreamOperator = nullptr;
#endif
    rc = (CamRetCode)streamOperator_->ChangeToOfflineStream({ streamInfoSnapshot.streamId_ }, streamOperatorCallback,
        offlineStreamOperator);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    cameraDevice_->Close();
    sleep(5);

    std::cout << "begin to release offlne stream" << std::endl;
    rc = (CamRetCode)offlineStreamOperator->CancelCapture(2020);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    std::vector<int> streamIds = {1202};
    rc = (CamRetCode)offlineStreamOperator->ReleaseStreams(streamIds);
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    rc = (CamRetCode)offlineStreamOperator->Release();
    ASSERT_EQ(HDI::Camera::V1_0::NO_ERROR, rc);

    sleep(5);
}
