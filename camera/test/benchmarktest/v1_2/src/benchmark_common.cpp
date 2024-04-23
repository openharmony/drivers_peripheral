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

#include "hdi_common_v1_2.h"
#include "camera.h"
#include "video_key_info.h"

namespace OHOS::Camera {
Test::ResultCallback Test::resultCallback_ = 0;

uint64_t Test::GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return static_cast<uint64_t>(tmp.count());
}

int32_t Test::DumpImageFile(int streamId, std::string suffix, const void* buffer, int32_t size)
{
    if (imageDataSaveSwitch == SWITCH_OFF) {
        return 0;
    }
    if (streamId < 0) {
        CAMERA_LOGE("ivalid stream id: %{public}d", streamId);
        return -1;
    }
    char mkdirCmd[PATH_MAX] = {0};
    char path[PATH_MAX] = {0};
    int ret = sprintf_s(mkdirCmd, sizeof(mkdirCmd) / sizeof(mkdirCmd[0]),
        "mkdir -p /data/stream-%d", streamId);
    if (ret < 0) {
        return -1;
    }
    system(mkdirCmd);
    ret = sprintf_s(path, sizeof(path) / sizeof(path[0]), "data/stream-%d/%lld.%s",
        streamId, GetCurrentLocalTimeStamp(), suffix.c_str());
    if (ret < 0) {
        return -1;
    }

    int imgFd = open(path, O_RDWR | O_CREAT, 00766);
    if (imgFd == -1) {
        CAMERA_LOGE("open file failed, errno: %{public}s", strerror(errno));
        return -1;
    }

    ret = write(imgFd, buffer, size);
    if (ret == -1) {
        CAMERA_LOGE("write file failed, error: %{public}s", strerror(errno));
        close(imgFd);
        return -1;
    }
    close(imgFd);
    return 0;
}

void Test::Init()
{
    uint32_t mainVer;
    uint32_t minVer;
    int32_t ret;
    if (serviceV1_2 == nullptr) {
        serviceV1_2 = OHOS::HDI::Camera::V1_2::ICameraHost::Get("camera_service", false);
        if (serviceV1_2 == nullptr) {
            CAMERA_LOGE("V1_2::ICameraHost get failed");
            return;
        } else {
            CAMERA_LOGI("ICameraHost get success");
            ret = serviceV1_2->GetVersion(mainVer, minVer);
            if (ret != 0) {
                CAMERA_LOGE("V1_1::ICameraHost get version failed, ret = %{public}d", ret);
            } else {
                CAMERA_LOGE("V1_1::ICameraHost get version success, %{public}d, %{public}d", mainVer, minVer);
            }
        }
        ASSERT_TRUE(serviceV1_2 != nullptr);
        service = static_cast<OHOS::HDI::Camera::V1_0::ICameraHost *>(serviceV1_2.GetRefPtr());
    }
    hostCallback = new TestCameraHostCallback();
    service->SetCallback(hostCallback);
}

void Test::GetCameraMetadata(int cameraId)
{
    if (cameraId == DEVICE_1) {
        rc = service->GetCameraAbility(cameraIds[1], abilityVec);
    } else {
        rc = service->GetCameraAbility(cameraIds[0], abilityVec);
    }
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("GetCameraAbility failed, rc = %{public}d", rc);
    }
    MetadataUtils::ConvertVecToMetadata(abilityVec, ability);

    common_metadata_header_t* data = ability->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_AVAILABLE_MODES, &entry);
    if (ret == 0) {
        CAMERA_LOGI("get OHOS_CONTROL_AE_AVAILABLE_MODES success");
    }
}

void Test::Open(int cameraId)
{
    if (cameraDevice == nullptr) {
        service->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            CAMERA_LOGE("camera device list empty");
        }
        ASSERT_TRUE(cameraIds.size() != 0);
        GetCameraMetadata(cameraId);
        deviceCallback = new OHOS::Camera::Test::DemoCameraDeviceCallback();

        ASSERT_TRUE(serviceV1_2 != nullptr);
        if (cameraId == DEVICE_1) {
            rc = serviceV1_2->OpenCamera_V1_1(cameraIds[1], deviceCallback, cameraDeviceV1_1);
        } else {
            rc = serviceV1_2->OpenCamera_V1_1(cameraIds[0], deviceCallback, cameraDeviceV1_1);
        }
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_1 == nullptr) {
            CAMERA_LOGE("openCamera V1_1 failed, rc = %{public}d", rc);
            return;
        }
        ASSERT_TRUE(cameraDeviceV1_1 != nullptr);
        cameraDevice = static_cast<OHOS::HDI::Camera::V1_0::ICameraDevice *>(cameraDeviceV1_1.GetRefPtr());
        CAMERA_LOGI("OpenCamera V1_1 success");
    }
}

void Test::OpenCameraV1_2(int cameraId)
{
    if (cameraDevice == nullptr) {
        EXPECT_NE(service, nullptr);
        service->GetCameraIds(cameraIds);
        EXPECT_NE(cameraIds.size(), 0);
        GetCameraMetadata(cameraId);
        deviceCallback = new OHOS::Camera::Test::DemoCameraDeviceCallback();

        EXPECT_NE(serviceV1_2, nullptr);
        if (cameraId == DEVICE_1) {
            rc = serviceV1_2->OpenCamera_V1_2(cameraIds[1], deviceCallback, cameraDeviceV1_2);
        } else {
            rc = serviceV1_2->OpenCamera_V1_2(cameraIds[0], deviceCallback, cameraDeviceV1_2);
        }
        EXPECT_EQ(rc, HDI::Camera::V1_0::NO_ERROR);
        EXPECT_NE(cameraDeviceV1_2, nullptr);
        cameraDevice = static_cast<OHOS::HDI::Camera::V1_0::ICameraDevice *>(cameraDeviceV1_2.GetRefPtr());
        CAMERA_LOGI("OpenCamera V1_2 success");
    }
}

void Test::Close()
{
    if (cameraDevice != nullptr) {
        cameraDevice->Close();
        cameraDevice = nullptr;
    }
}

void Test::StartStream(std::vector<StreamIntent> intents)
{
    streamOperatorCallback = new TestStreamOperatorCallback();
    uint32_t mainVersion = 1;
    uint32_t minVersion = 0;
    rc = cameraDeviceV1_1->GetStreamOperator_V1_1(streamOperatorCallback, streamOperator_V1_1);
    if (rc == HDI::Camera::V1_0::NO_ERROR) {
        rc = streamOperator_V1_1->GetVersion(mainVersion, minVersion);
        streamOperator = static_cast<OHOS::HDI::Camera::V1_0::IStreamOperator *>(streamOperator_V1_1.GetRefPtr());
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGE("StreamOperator V1_1 get version failed, rc = %{public}d", rc);
        } else {
            CAMERA_LOGI("StreamOperator V1_1 get version success, %{public}u, %{public}u",
                mainVersion, minVersion);
        }
        CAMERA_LOGI("GetStreamOperator success");
    } else {
        CAMERA_LOGE("GetStreamOperator fail, rc = %{public}d", rc);
    }
    streamInfoPre = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoVideo = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoCapture = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    streamInfoAnalyze = std::make_shared<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>();
    for (auto& intent : intents) {
        if (intent == StreamIntent::PREVIEW) {
            streamInfoPre->v1_0.streamId_ = streamIdPreview;
            streamInfoPre->v1_0.width_ = previewWidth;
            streamInfoPre->v1_0.height_ = previewHeight;
            streamInfoPre->v1_0.format_ = previewFormat;
            streamInfoPre->v1_0.dataspace_ = UT_DATA_SIZE;
            streamInfoPre->v1_0.intent_ = intent;
            streamInfoPre->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
            std::shared_ptr<StreamConsumer> consumer_pre = std::make_shared<StreamConsumer>();
            streamInfoPre->v1_0.bufferQueue_ = consumer_pre->CreateProducerSeq([this](void* addr, uint32_t size) {
                DumpImageFile(streamIdPreview, "yuv", addr, size);
            });
            streamInfoPre->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
            consumerMap_[intent] = consumer_pre;
            streamInfos.push_back(*streamInfoPre);
        } else if (intent == StreamIntent::VIDEO) {
            streamInfoVideo->v1_0.streamId_ = streamIdVideo;
            streamInfoVideo->v1_0.width_ = videoWidth;
            streamInfoVideo->v1_0.height_ = videoHeight;
            streamInfoVideo->v1_0.format_ = videoFormat;
            streamInfoVideo->v1_0.dataspace_ = UT_DATA_SIZE;
            streamInfoVideo->v1_0.intent_ = intent;
            streamInfoVideo->v1_0.encodeType_ = ENCODE_TYPE_H265;
            streamInfoVideo->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
            std::shared_ptr<StreamConsumer> consumer_video = std::make_shared<StreamConsumer>();
            streamInfoVideo->v1_0.bufferQueue_ = consumer_video->CreateProducerSeq([this](void* addr, uint32_t size) {
                DumpImageFile(streamIdPreview, "yuv", addr, size);
            });
            streamInfoVideo->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
            consumerMap_[intent] = consumer_video;
            streamInfos.push_back(*streamInfoVideo);
        } else if (intent == StreamIntent::ANALYZE) {
            streamInfoAnalyze->v1_0.streamId_ = streamIdAnalyze;
            streamInfoAnalyze->v1_0.width_ = analyzeWidth;
            streamInfoAnalyze->v1_0.height_ = analyzeHeight;
            streamInfoAnalyze->v1_0.format_ = analyzeFormat;
            streamInfoAnalyze->v1_0.dataspace_ = UT_DATA_SIZE;
            streamInfoAnalyze->v1_0.intent_ = intent;
            streamInfoAnalyze->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
            
            std::shared_ptr<StreamConsumer> consumer_analyze = std::make_shared<StreamConsumer>();
            streamInfoAnalyze->v1_0.bufferQueue_ =
                consumer_analyze->CreateProducerSeq([this](void* addr, uint32_t size) {
                common_metadata_header_t *data = static_cast<common_metadata_header_t *>(addr);
                camera_metadata_item_t entry = {};

                int ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_IDS, &entry);
                if (ret == 0) {
                    for (size_t i = 0; i < entry.count; i++) {
                        int id = entry.data.i32[i];
                        CAMERA_LOGI("Face ids : %{public}d", id);
                    }
                }

                ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_RECTANGLES, &entry);
                if (ret == 0) {
                    for (size_t i = 0; i < entry.count; i++) {
                        int id = entry.data.i32[i];
                        CAMERA_LOGI("Face rectangles : %{public}d", id);
                    }
                }
            });
            streamInfoAnalyze->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
            consumerMap_[intent] = consumer_analyze;
            streamInfos.push_back(*streamInfoAnalyze);
        } else {
            streamInfoCapture->v1_0.streamId_ = streamIdAnalyze;
            streamInfoCapture->v1_0.width_ = analyzeWidth;
            streamInfoCapture->v1_0.height_ = analyzeHeight;
            streamInfoCapture->v1_0.format_ = analyzeFormat;
            streamInfoCapture->v1_0.dataspace_ = UT_DATA_SIZE;
            streamInfoCapture->v1_0.intent_ = intent;
            streamInfoCapture->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
            std::shared_ptr<StreamConsumer> consumer_capture = std::make_shared<StreamConsumer>();
            streamInfoCapture->v1_0.bufferQueue_ =
                consumer_capture->CreateProducerSeq([this](void* addr, uint32_t size) {
                DumpImageFile(streamIdPreview, "yuv", addr, size);
            });
            streamInfoCapture->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
            consumerMap_[intent] = consumer_capture;
            streamInfos.push_back(*streamInfoCapture);
        }
    }

    rc = streamOperator_V1_1->CreateStreams_V1_1(streamInfos);
    EXPECT_EQ(false, rc != HDI::Camera::V1_0::NO_ERROR);
    rc = streamOperator_V1_1->CommitStreams(OperationMode::NORMAL, abilityVec);
    EXPECT_EQ(false, rc != HDI::Camera::V1_0::NO_ERROR);
    sleep(1);
    std::vector<OHOS::HDI::Camera::V1_1::StreamInfo_V1_1>().swap(streamInfos);
}

void Test::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {streamId};
    captureInfo->captureSetting_ = abilityVec;
    captureInfo->enableShutterCallback_ = shutterCallback;
    if (streamOperator_V1_2 != nullptr) {
        rc = (CamRetCode)streamOperator_V1_2->Capture(captureId, *captureInfo, isStreaming);
    } else if (streamOperator_V1_1 != nullptr) {
        rc = (CamRetCode)streamOperator_V1_1->Capture(captureId, *captureInfo, isStreaming);
    } else {
        rc = (CamRetCode)streamOperator->Capture(captureId, *captureInfo, isStreaming);
    }
    EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
    if (rc == HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGI("check Capture: Capture success, %{public}d", captureId);
    } else {
        std::cout << "rc = " << rc << std::endl;
        CAMERA_LOGE("check Capture: Capture fail, rc = %{public}d", rc);
    }
    sleep(UT_SLEEP_TIME);
}

void Test::StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds)
{
    if (captureIds.size() > 0) {
        for (auto &captureId : captureIds) {
            if (streamOperator_V1_2 != nullptr) {
                rc = streamOperator_V1_2->CancelCapture(captureId);
            } else if (streamOperator_V1_1 != nullptr) {
                rc = streamOperator_V1_1->CancelCapture(captureId);
            } else {
                rc = streamOperator->CancelCapture(captureId);
            }
            EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
            if (rc == HDI::Camera::V1_0::NO_ERROR) {
                CAMERA_LOGI("check Capture: CancelCapture success, %{public}d", captureId);
            } else {
                CAMERA_LOGE("check Capture: CancelCapture fail, rc = %{public}d, captureId = %{public}d",
                    rc, captureId);
            }
        }
    }
    if (streamIds.size() > 0) {
        if (streamOperator_V1_2 != nullptr) {
            rc = streamOperator_V1_2->ReleaseStreams(streamIds);
        } else if (streamOperator_V1_1 != nullptr) {
            rc = streamOperator_V1_1->ReleaseStreams(streamIds);
        } else {
            rc = streamOperator->ReleaseStreams(streamIds);
        }
        EXPECT_EQ(true, rc == HDI::Camera::V1_0::NO_ERROR);
        if (rc == HDI::Camera::V1_0::NO_ERROR) {
            CAMERA_LOGI("check Capture: ReleaseStream success");
        } else {
            CAMERA_LOGE("check Capture: ReleaseStreams fail, rc = %{public}d", rc);
        }
    }
}

void Test::StreamConsumer::CalculateFps(int64_t timestamp, int32_t streamId)
{
    if (isFirstCalculateFps_) {
        if ((timestamp - intervalTimestamp_) >= interval_) {
            int64_t timeInterval = timestamp - intervalTimestamp_;
            if (timeInterval != 0) {
                float fps = (int64_t)(100000000000 * timestampCount_ / timeInterval) / 100.0;
                CAMERA_LOGI("Calculate FPS success, streamId: %{public}d, Fps:%{public}f", streamId, fps);
                interval_ = ONESECOND_OF_MICROSECOND_UNIT;
            } else {
                CAMERA_LOGE("Calculate FPS error timeInerval is 0");
            }
        }
    } else {
        intervalTimestamp_ = timestamp;
        isFirstCalculateFps_ = true;
    }
    if ((timestamp - intervalTimestamp_) >= ONESECOND_OF_MICROSECOND_UNIT * UT_SECOND_TIMES) {
        intervalTimestamp_ = timestamp;
        timestampCount_ = 0;
        interval_ = ONESECOND_OF_MICROSECOND_UNIT;
    }
    timestampCount_++;
}

OHOS::sptr<OHOS::IBufferProducer> Test::StreamConsumer::CreateProducer(std::function<void(void*, uint32_t)> callback)
{
    consumer_ = OHOS::IConsumerSurface::Create();
    if (consumer_ == nullptr) {
        return nullptr;
    }
    sptr<IBufferConsumerListener> listener = new TestBufferConsumerListener();
    consumer_->RegisterConsumerListener(listener);
    auto producer = consumer_->GetProducer();
    if (producer == nullptr) {
        return nullptr;
    }

    callback_ = callback;
    consumerThread_ = new std::thread([this, listener] {
        int32_t flushFence = 0;
        int64_t timestamp = 0;
        OHOS::Rect damage;
        TestBufferConsumerListener* checker = static_cast<TestBufferConsumerListener*>(listener.GetRefPtr());
        while (running_ == true) {
            OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
            if (checker->checkBufferAvailable()) {
                consumer_->AcquireBuffer(buffer, flushFence, timestamp, damage);
                if (buffer != nullptr) {
                    void* addr = buffer->GetVirAddr();
                    uint32_t size = buffer->GetSize();

                    int32_t gotSize = 0;
                    int32_t isKey = 0;
                    int32_t streamId = 0;
                    int32_t captureId = 0;
                    buffer->GetExtraData()->ExtraGet(OHOS::Camera::dataSize, gotSize);
                    buffer->GetExtraData()->ExtraGet(OHOS::Camera::isKeyFrame, isKey);
                    buffer->GetExtraData()->ExtraGet(OHOS::Camera::timeStamp, timestamp);
                    buffer->GetExtraData()->ExtraGet(OHOS::Camera::streamId, streamId);
                    buffer->GetExtraData()->ExtraGet(OHOS::Camera::captureId, captureId);
                    if (gotSize) {
                        CalculateFps(timestamp, streamId);
                        callback_(addr, gotSize);
                    } else {
                        callback_(addr, size);
                    }

                    consumer_->ReleaseBuffer(buffer, -1);
                    shotCount_--;
                    if (shotCount_ == 0) {
                        std::unique_lock<std::mutex> l(l_);
                        cv_.notify_one();
                    }
                }
            }
            if (running_ == false) {
                break;
            }
            usleep(1);
        }
    });

    return producer;
}

OHOS::sptr<BufferProducerSequenceable> Test::StreamConsumer::CreateProducerSeq(
    std::function<void(void*, uint32_t)> callback)
{
    OHOS::sptr<OHOS::IBufferProducer> producer = CreateProducer(callback);
    if (producer == nullptr) {
        return nullptr;
    }

    return new BufferProducerSequenceable(producer);
}

int32_t Test::TestStreamOperatorCallback::OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamId)
{
    for (auto it : streamId) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallback::OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, count: %{public}d", captureId, it.streamId_,
            it.frameCount_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallback::OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, error: %{public}d", captureId, it.streamId_,
            it.error_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallback::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    (void)timestamp;
    for (auto it : streamIds) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamId)
{
    for (auto it : streamId) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnCaptureEnded(int32_t captureId,
    const std::vector<CaptureEndedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, count: %{public}d", captureId, it.streamId_,
            it.frameCount_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnCaptureError(int32_t captureId,
    const std::vector<CaptureErrorInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d, error: %{public}d", captureId, it.streamId_,
            it.error_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    (void)timestamp;
    for (auto it : streamIds) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestStreamOperatorCallbackV1_2::OnCaptureStarted_V1_2(int32_t captureId,
    const std::vector<HDI::Camera::V1_2::CaptureStartedInfo> &infos)
{
    for (auto it : infos) {
        CAMERA_LOGE("captureId: %{public}d, streamId: %{public}d", captureId, it.streamId_);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::DemoCameraDeviceCallback::OnError(ErrorType type, int32_t errorMsg)
{
    CAMERA_LOGE("type: %{public}d, errorMsg: %{public}d", type, errorMsg);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::DemoCameraDeviceCallback::OnResult(uint64_t timestamp, const std::vector<uint8_t> &result)
{
    if (Test::resultCallback_) {
        std::shared_ptr<CameraMetadata> resultMeta;
        MetadataUtils::ConvertVecToMetadata(result, resultMeta);
        Test::resultCallback_(timestamp, resultMeta);
    }
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestCameraHostCallback::OnCameraStatus(const std::string& cameraId, CameraStatus status)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestCameraHostCallback::OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), status);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::TestCameraHostCallback::OnCameraEvent(const std::string& cameraId, CameraEvent event)
{
    CAMERA_LOGE("cameraId: %{public}s, status: %{public}d", cameraId.c_str(), event);
    return HDI::Camera::V1_0::NO_ERROR;
}

int32_t Test::DefferredImageTestInit()
{
    constexpr const char* serviceName = "camera_image_process_service";
    constexpr const int userId = 100;
    // get ImageProcessService
    imageProcessService_ = OHOS::HDI::Camera::V1_2::ImageProcessServiceProxy::Get(serviceName, false);
    if (imageProcessService_ == nullptr) {
        std::cout << "DefferredImageTestInit fail, imageProcessService_ == nullptr" << std::endl;
        return -1;
    }
    imageProcessCallback_ = new OHOS::Camera::Test::TestImageProcessCallback();
    if (imageProcessCallback_ == nullptr) {
        std::cout << "DefferredImageTestInit fail, imageProcessCallback_ == nullptr" << std::endl;
        return -1;
    }
    imageProcessService_->CreateImageProcessSession(userId, imageProcessCallback_, imageProcessSession_);
    if (imageProcessSession_ == nullptr) {
        std::cout << "DefferredImageTestInit fail, imageProcessSession_ == nullptr" << std::endl;
        return -1;
    }
    return 0;
}
int32_t Test::TestImageProcessCallback::OnProcessDone(const std::string& imageId,
    const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer)
{
    CAMERA_LOGI("imageId: %{public}s", imageId.c_str());
    coutProcessDone_++;
    curImageId_ = imageId;
    curImageBufferInfo_ = buffer;
    return 0;
}

int32_t Test::TestImageProcessCallback::OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status)
{
    CAMERA_LOGI("status: %{public}d", status);
    curStatus_ = status;
    coutStatusChanged_++;
    return 0;
}

int32_t Test::TestImageProcessCallback::OnError(const std::string& imageId, \
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    CAMERA_LOGI("imageId: %{public}s, errorCode: %{public}d", imageId.c_str(), errorCode);
    curImageId_ = imageId;
    curErrorCode_ = errorCode;
    countError_++;
    return 0;
}
}
