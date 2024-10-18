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

#include "hdi_common_v1_1.h"
#include "camera.h"
#include "video_key_info.h"

namespace OHOS::Camera {
int64_t OHOS::Camera::HdiCommonV1_1::StreamConsumer::g_timestamp[2] = {0};

void HdiCommonV1_1::Init()
{
    uint32_t mainVer;
    uint32_t minVer;
    int32_t ret;
    if (serviceV1_1 == nullptr) {
        serviceV1_1 = OHOS::HDI::Camera::V1_1::ICameraHost::Get("camera_service", false);
        if (serviceV1_1 == nullptr) {
            printf("Init ICameraHost get failed serviceV1_1 nullptr\n");
            CAMERA_LOGE("Init ICameraHost get failed serviceV1_1 nullptr");
            return;
        }
        CAMERA_LOGI("V1_1::ICameraHost get success");
        ret = serviceV1_1->GetVersion(mainVer, minVer);
        if (ret != 0) {
            printf("Init GetVersion failed, ret = %d\n", ret);
            CAMERA_LOGE("Init GetVersion failed, ret = %{public}d", ret);
            return;
        }
        CAMERA_LOGI("V1_1::ICameraHost get version success, %{public}d, %{public}d", mainVer, minVer);
        service = static_cast<OHOS::HDI::Camera::V1_0::ICameraHost *>(serviceV1_1.GetRefPtr());
    }

    hostCallback = new TestCameraHostCallback();
    ret = service->SetCallback(hostCallback);
    if (ret != 0) {
        printf("Init SetCallback failed, ret = %d\n", ret);
        CAMERA_LOGE("Init SetCallback failed, ret = %{public}d", ret);
    }
}

void HdiCommonV1_1::Open(int cameraId)
{
    if (cameraDevice == nullptr) {
        if (serviceV1_1 == nullptr) {
            printf("Open ICameraHost failed\n");
            CAMERA_LOGE("Open ICameraHost failed");
            return;
        }
        service->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            printf("Open GetCameraIds failed\n");
            CAMERA_LOGE("Open GetCameraIds failed");
            return;
        }
        GetCameraMetadata(cameraId);
        deviceCallback = new OHOS::Camera::HdiCommon::DemoCameraDeviceCallback();
        if (DEVICE_1 == cameraId) {
            rc = serviceV1_1->OpenCamera_V1_1(cameraIds[1], deviceCallback, cameraDeviceV1_1); // front camera
        } else {
            rc = serviceV1_1->OpenCamera_V1_1(cameraIds[0], deviceCallback, cameraDeviceV1_1); // rear camera
        }
        if (rc != HDI::Camera::V1_0::NO_ERROR || cameraDeviceV1_1 == nullptr) {
            printf("Open OpenCamera_V1_1 failed, rc = %d\n", rc);
            CAMERA_LOGE("Open OpenCamera_V1_1 failed, rc = %{public}d", rc);
            return;
        }
        cameraDevice = static_cast<OHOS::HDI::Camera::V1_0::ICameraDevice *>(cameraDeviceV1_1.GetRefPtr());
        CAMERA_LOGI("OpenCamera V1_1 success");
    }
}

void HdiCommonV1_1::GetCameraMetadata(int cameraId)
{
    if (DEVICE_1 == cameraId) {
        rc = service->GetCameraAbility(cameraIds[1], abilityVec); // front camera
    } else {
        rc = service->GetCameraAbility(cameraIds[0], abilityVec); // rear camera
    }
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("GetCameraAbility failed, rc = %d\n", rc);
        CAMERA_LOGE("GetCameraAbility failed, rc = %{public}d", rc);
        return;
    }
    MetadataUtils::ConvertVecToMetadata(abilityVec, ability);
}

void HdiCommonV1_1::DefaultPreview(std::shared_ptr<StreamInfo_V1_1> &infos)
{
    infos->v1_0.streamId_ = streamIdPreview;
    infos->v1_0.width_ = previewWidth;
    infos->v1_0.height_ = previewHeight;
    infos->v1_0.format_ = previewFormat;
    infos->v1_0.dataspace_ = UT_DATA_SIZE;
    infos->v1_0.intent_ = StreamIntent::PREVIEW;
    infos->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
}

void HdiCommonV1_1::DefaultCapture(std::shared_ptr<StreamInfo_V1_1> &infos)
{
    infos->v1_0.streamId_ = streamIdCapture;
    infos->v1_0.width_ = captureWidth;
    infos->v1_0.height_ = captureHeight;
    infos->v1_0.format_ = snapshotFormat;
    infos->v1_0.dataspace_ = UT_DATA_SIZE;
    infos->v1_0.intent_ = StreamIntent::STILL_CAPTURE;
    infos->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
}

void HdiCommonV1_1::DefaultInfosPreview(std::shared_ptr<StreamInfo_V1_1> &infos)
{
    DefaultPreview(infos);
    std::shared_ptr<StreamConsumer> consumer_pre = std::make_shared<StreamConsumer>();
    infos->v1_0.bufferQueue_ = consumer_pre->CreateProducerSeq([this](void* addr, uint32_t size) {
        DumpImageFile(streamIdPreview, "yuv", addr, size);
    });
    infos->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    consumerMap_[StreamIntent::PREVIEW] = consumer_pre;
}

void HdiCommonV1_1::DefaultInfosCapture(std::shared_ptr<StreamInfo_V1_1> &infos)
{
    DefaultCapture(infos);
    std::shared_ptr<StreamConsumer> consumer_capture = std::make_shared<StreamConsumer>();
    infos->v1_0.bufferQueue_ = consumer_capture->CreateProducerSeq([this](void* addr, uint32_t size) {
        DumpImageFile(streamIdCapture, "jpeg", addr, size);
    });
    infos->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    consumerMap_[StreamIntent::STILL_CAPTURE] = consumer_capture;
}

void HdiCommonV1_1::DefaultInfosVideo(std::shared_ptr<StreamInfo_V1_1> &infos)
{
    infos->v1_0.streamId_ = streamIdVideo;
    infos->v1_0.width_ = videoWidth;
    infos->v1_0.height_ = videoHeight;
    infos->v1_0.format_ = videoFormat;
    infos->v1_0.dataspace_ = UT_DATA_SIZE;
    infos->v1_0.intent_ = StreamIntent::VIDEO;
    infos->v1_0.encodeType_ = ENCODE_TYPE_H265;
    infos->v1_0.tunneledMode_ = UT_TUNNEL_MODE;
    std::shared_ptr<StreamConsumer> consumer_video = std::make_shared<StreamConsumer>();
    infos->v1_0.bufferQueue_ = consumer_video->CreateProducerSeq([this](void* addr, uint32_t size) {
        DumpImageFile(streamIdVideo, "yuv", addr, size);
    });
    infos->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    consumerMap_[StreamIntent::VIDEO] = consumer_video;
}

void HdiCommonV1_1::DefaultInfosAnalyze(std::shared_ptr<StreamInfo_V1_1> &infos)
{
    infos->v1_0.streamId_ = streamIdAnalyze;
    infos->v1_0.width_ = analyzeWidth;
    infos->v1_0.height_ = analyzeHeight;
    infos->v1_0.format_ = analyzeFormat;
    infos->v1_0.dataspace_ = UT_DATA_SIZE;
    infos->v1_0.intent_ = StreamIntent::ANALYZE;
    infos->v1_0.tunneledMode_ = UT_TUNNEL_MODE;

    std::shared_ptr<StreamConsumer> consumer_analyze = std::make_shared<StreamConsumer>();
    infos->v1_0.bufferQueue_ = consumer_analyze->CreateProducerSeq([this](void* addr, uint32_t size) {
        common_metadata_header_t *data = static_cast<common_metadata_header_t *>(addr);
        camera_metadata_item_t entry = {};

        int ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_IDS, &entry);
        if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
            for (size_t i = 0; i < entry.count; i++) {
                int id = entry.data.i32[i];
                CAMERA_LOGI("Face ids : %{public}d", id);
            }
        }

        ret = FindCameraMetadataItem(data, OHOS_STATISTICS_FACE_RECTANGLES, &entry);
        if (ret == HDI::Camera::V1_0::NO_ERROR && entry.data.i32 != nullptr && entry.count > 0) {
            for (size_t i = 0; i < entry.count; i++) {
                int id = entry.data.i32[i];
                CAMERA_LOGI("Face rectangles : %{public}d", id);
            }
        }
    });
    infos->v1_0.bufferQueue_->producer_->SetQueueSize(UT_DATA_SIZE);
    consumerMap_[StreamIntent::ANALYZE] = consumer_analyze;
}

void HdiCommonV1_1::StartStream(std::vector<StreamIntent> intents)
{
    StartStream(intents, OHOS::HDI::Camera::V1_1::NORMAL);
}

void HdiCommonV1_1::StartStream(std::vector<StreamIntent> intents, OperationMode_V1_1 mode)
{
    streamOperatorCallback = new TestStreamOperatorCallback();
    uint32_t mainVersion = 1;
    uint32_t minVersion = 0;
    rc = cameraDeviceV1_1->GetStreamOperator_V1_1(streamOperatorCallback, streamOperator_V1_1);
    if (rc == HDI::Camera::V1_0::NO_ERROR) {
        rc = streamOperator_V1_1->GetVersion(mainVersion, minVersion);
        streamOperator = static_cast<OHOS::HDI::Camera::V1_0::IStreamOperator *>(streamOperator_V1_1.GetRefPtr());
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            printf("StreamOperator V1_1 get version failed, rc = %d\n", rc);
            CAMERA_LOGE("StreamOperator V1_1 get version failed, rc = %{public}d", rc);
        }
        CAMERA_LOGI("GetStreamOperator success");
    } else {
        printf("GetStreamOperator fail, rc = %d\n", rc);
        CAMERA_LOGE("GetStreamOperator fail, rc = %{public}d", rc);
    }
    streamInfoPre = std::make_shared<StreamInfo_V1_1>();
    streamInfoVideo = std::make_shared<StreamInfo_V1_1>();
    streamInfoCapture = std::make_shared<StreamInfo_V1_1>();
    streamInfoAnalyze = std::make_shared<StreamInfo_V1_1>();
    for (auto& intent : intents) {
        if (intent == StreamIntent::PREVIEW) {
            DefaultInfosPreview(streamInfoPre);
            streamInfos.push_back(*streamInfoPre);
        } else if (intent == StreamIntent::VIDEO) {
            DefaultInfosVideo(streamInfoVideo);
            streamInfos.push_back(*streamInfoVideo);
        } else if (intent == StreamIntent::ANALYZE) {
            DefaultInfosAnalyze(streamInfoAnalyze);
            streamInfos.push_back(*streamInfoAnalyze);
        } else {
            DefaultInfosCapture(streamInfoCapture);
            streamInfos.push_back(*streamInfoCapture);
        }
    }
    rc = streamOperator_V1_1->CreateStreams_V1_1(streamInfos);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("check StartStream: CreateStreams_V1_1 fail, rc = %d\n", rc);
        CAMERA_LOGE("check StartStream: CreateStreams_V1_1 fail, rc = %{public}d", rc);
    }
    rc = streamOperator_V1_1->CommitStreams_V1_1(mode, abilityVec);
    if (rc != HDI::Camera::V1_0::NO_ERROR) {
        printf("check StartStream: CommitStreams_V1_1 fail, rc = %d\n", rc);
        CAMERA_LOGE("check StartStream: CommitStreams_V1_1 fail, rc = %{public}d", rc);
    }
    sleep(1);
    std::vector<StreamInfo_V1_1>().swap(streamInfos);
}

void HdiCommonV1_1::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    captureInfo = std::make_shared<CaptureInfo>();
    captureInfo->streamIds_ = {streamId};
    captureInfo->captureSetting_ = abilityVec;
    captureInfo->enableShutterCallback_ = shutterCallback;
    if (streamOperator_V1_1 != nullptr) {
        rc = (CamRetCode)streamOperator_V1_1->Capture(captureId, *captureInfo, isStreaming);
    } else {
        rc = (CamRetCode)streamOperator->Capture(captureId, *captureInfo, isStreaming);
    }

    if (rc != HDI::Camera::V1_0::NO_ERROR)  {
        printf("check Capture: Capture fail, rc = %d\n", rc);
        CAMERA_LOGE("check Capture: Capture fail, rc = %{public}d", rc);
    }
    sleep(UT_SLEEP_TIME);
}

void HdiCommonV1_1::StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds)
{
    if (captureIds.size() > 0) {
        for (auto &captureId : captureIds) {
            if (streamOperator_V1_1 != nullptr) {
                rc = streamOperator_V1_1->CancelCapture(captureId);
            } else {
                rc = streamOperator->CancelCapture(captureId);
            }
            if (rc != HDI::Camera::V1_0::NO_ERROR) {
                printf("CancelCapture fail, rc = %d, captureId = %d\n", rc, captureId);
                CAMERA_LOGE("CancelCapture fail, rc = %{public}d, captureId = %{public}d", rc, captureId);
            }
        }
    }
    if (streamIds.size() > 0) {
        if (streamOperator_V1_1 != nullptr) {
            rc = streamOperator_V1_1->ReleaseStreams(streamIds);
        } else {
            rc = streamOperator->ReleaseStreams(streamIds);
        }
        if (rc != HDI::Camera::V1_0::NO_ERROR) {
            printf("check Capture: ReleaseStreams fail, rc = %d\n", rc);
            CAMERA_LOGE("check Capture: ReleaseStreams fail, rc = %{public}d", rc);
        }
    }
}

void HdiCommonV1_1::StreamConsumer::GetTimeStamp(
    int64_t *g_timestamp, uint32_t lenght, int64_t timestamp, int32_t gotSize)
{
    if (gotSize != UT_PREVIEW_SIZE) {
        if (g_timestamp[0] == 0) {
            g_timestamp[0] = timestamp;
        } else {
            g_timestamp[1] = timestamp;
        }
    }
}

OHOS::sptr<OHOS::IBufferProducer> HdiCommonV1_1::StreamConsumer::CreateProducer(
    std::function<void(void*, uint32_t)> callback)
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
                    GetTimeStamp(g_timestamp, sizeof(g_timestamp) / sizeof(g_timestamp[0]), timestamp, gotSize);
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

OHOS::sptr<BufferProducerSequenceable> HdiCommonV1_1::StreamConsumer::CreateProducerSeq(
    std::function<void(void*, uint32_t)> callback)
{
    OHOS::sptr<OHOS::IBufferProducer> producer = CreateProducer(callback);
    if (producer == nullptr) {
        return nullptr;
    }

    return new BufferProducerSequenceable(producer);
}
}
