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

#include "common.h"

namespace OHOS {
namespace DistributedHardware {
class DCameraHostCallback : public ICameraHostCallback {
public:
    DCameraHostCallback() = default;
    virtual ~DCameraHostCallback() = default;

    int32_t OnCameraStatus(const std::string& cameraId, CameraStatus status)
    {
        (void)cameraId;
        (void)status;
        return 0;
    }

    int32_t OnFlashlightStatus(const std::string& cameraId, FlashlightStatus status)
    {
        (void)cameraId;
        (void)status;
        return 0;
    }

    int32_t OnCameraEvent(const std::string& cameraId, CameraEvent event)
    {
        (void)cameraId;
        (void)event;
        return 0;
    }
};

class DCameraDeviceCallback : public ICameraDeviceCallback {
public:
    DCameraDeviceCallback() = default;
    virtual ~DCameraDeviceCallback() = default;

    int32_t OnError(ErrorType type, int32_t errorCode)
    {
        (void)type;
        (void)errorCode;
        return 0;
    }

    int32_t OnResult(uint64_t timestamp, const std::vector<uint8_t>& result)
    {
        (void)timestamp;
        (void)result;
        return 0;
    }
};

class DStreamOperatorCallback : public IStreamOperatorCallback {
public:
    DStreamOperatorCallback() = default;
    virtual ~DStreamOperatorCallback() = default;

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds)
    {
        (void)captureId;
        (void)streamIds;
        return 0;
    }

    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos)
    {
        (void)captureId;
        (void)infos;
        return 0;
    }

    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos)
    {
        (void)captureId;
        (void)infos;
        return 0;
    }

    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp)
    {
        (void)captureId;
        (void)streamIds;
        (void)timestamp;
        return 0;
    }
};

uint64_t Test::GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return static_cast<uint64_t>(tmp.count());
}

int32_t Test::SaveYUV(const char* type, const void* buffer, int32_t size)
{
    if (strncmp(type, "preview", strlen(type)) == 0) {
        previewBufCnt += 1;
        int cycNum = 8;
        if (previewBufCnt % cycNum != 0) {
            std::cout << "receive preview buffer not save" << std::endl;
            return 0;
        }
    }
    char path[PATH_MAX] = {0};
    if (strncmp(type, "preview", strlen(type)) == 0) {
        system("mkdir -p /data/dcamera/preview");
        if (sprintf_s(path, sizeof(path) / sizeof(path[0]), "/data/dcamera/preview/%s_%lld.yuv",
            type, GetCurrentLocalTimeStamp()) < 0) {
            std::cout << "SaveYUV : preview sprintf_s fail." << std::endl;
            return -1;
        }
    } else {
        system("mkdir -p /data/dcamera/capture");
        if (sprintf_s(path, sizeof(path) / sizeof(path[0]), "/data/dcamera/capture/%s_%lld.jpg",
            type, GetCurrentLocalTimeStamp()) < 0) {
            std::cout << "SaveYUV : capture sprintf_s fail." << std::endl;
            return -1;
        }
    }
    std::cout << "save yuv to file:" << path << std::endl;

    int mode = 00766;
    int imgFd = open(path, O_RDWR | O_CREAT, mode);
    if (imgFd == -1) {
        std::cout << "open file failed, errno = " << strerror(errno) << std::endl;
        return -1;
    }

    int ret = write(imgFd, buffer, size);
    if (ret == -1) {
        std::cout << "write file failed, error = " << strerror(errno) << std::endl;
        close(imgFd);
        return -1;
    }
    close(imgFd);
    return 0;
}

int32_t Test::SaveVideoFile(const char* type, const void* buffer, int32_t size, int32_t operationMode)
{
    if (operationMode == 0) {
        char path[PATH_MAX] = {0};
        system("mkdir -p /data/dcamera/video");
        if (sprintf_s(path, sizeof(path) / sizeof(path[0]), "/data/dcamera/video/%s_%lld.h265",
            type, GetCurrentLocalTimeStamp()) < 0) {
            std::cout << "SaveVideoFile : video sprintf_s fail." << std::endl;
            return -1;
        }
        std::cout << "save yuv to file " << std::string(path) << std::endl;
        int mode = 00766;
        videoFd = open(path, O_RDWR | O_CREAT, mode);
        if (videoFd == -1) {
            std::cout << "open file failed, errno = " << strerror(errno) << std::endl;
            return -1;
        }
    } else if (operationMode == 1 && videoFd != -1) {
        int32_t ret = write(videoFd, buffer, size);
        if (ret == -1) {
            std::cout << "write file failed, error = " << strerror(errno) << std::endl;
            close(videoFd);
            return -1;
        }
    } else {
        if (videoFd != -1) {
            close(videoFd);
        }
    }
    return 0;
}

void Test::Init()
{
    if (service == nullptr) {
        service = ICameraHost::Get("distributed_camera_service");
        if (service == nullptr) {
            std::cout << "==========[test log]ICameraHost get failed."<< std::endl;
            return;
        } else {
            std::cout << "==========[test log]ICameraHost get success."<< std::endl;
        }
    }
    hostCallback = new DCameraHostCallback();
    service->SetCallback(hostCallback);
}

std::vector<uint8_t> Test::GetCameraAbility()
{
    if (cameraDevice == nullptr) {
        rc = service->GetCameraIds(cameraIds);
        if (rc != NO_ERROR) {
            std::cout << "==========[test log]GetCameraIds failed." << std::endl;
            return ability;
        } else {
            std::cout << "==========[test log]GetCameraIds success." << std::endl;
        }
        if (cameraIds.size() == 0) {
            std::cout << "==========[test log]camera device list is empty." << std::endl;
            return ability;
        }
        GetCameraMetadata();
    }
    return ability;
}

void Test::GetCameraMetadata()
{
    rc = service->GetCameraAbility(cameraIds.front(), ability);
    if (rc != NO_ERROR) {
        std::cout << "==========[test log]GetCameraAbility failed, rc = " << rc << std::endl;
    }
    std::shared_ptr<OHOS::Camera::CameraMetadata> abililyMeta = nullptr;
    OHOS::Camera::MetadataUtils::ConvertVecToMetadata(abilily, abililyMeta);
    common_metadata_header_t* data = abililyMeta->get();
    camera_metadata_item_t entry;
    int ret = OHOS::Camera::FindCameraMetadataItem(data, OHOS_CONTROL_AE_AVAILABLE_MODES, &entry);
    if (ret == 0) {
        std::cout << "==========[test log] get OHOS_CONTROL_AE_AVAILABLE_MODES success" << std::endl;
    }
}

void Test::Open()
{
    if (cameraDevice == nullptr) {
        service->GetCameraIds(cameraIds);
        if (cameraIds.size() == 0) {
            std::cout << "==========[test log]camera device list empty." << std::endl;
            return;
        }
        GetCameraMetadata();
        deviceCallback = new DCameraDeviceCallback();
        rc = service->OpenCamera(cameraIds.front(), deviceCallback, cameraDevice);
        if (rc != NO_ERROR || cameraDevice == nullptr) {
            std::cout << "==========[test log]OpenCamera failed, rc = " << rc << std::endl;
            return;
        }
        std::cout << "==========[test log]OpenCamera success." << std::endl;
    }
}

void Test::Close()
{
    if (cameraDevice != nullptr) {
        cameraDevice->Close();
        std::cout << "cameraDevice->Close" << std::endl;
        cameraDevice = nullptr;
    }
    consumerMap_.clear();
    if (hostCallback != nullptr) {
        hostCallback = nullptr;
    }
    if (deviceCallback != nullptr) {
        deviceCallback = nullptr;
    }
    if (streamOperatorCallback != nullptr) {
        streamOperatorCallback = nullptr;
    }
}

void Test::SetPreviewStreamInfo()
{
    int dataspace = 8;
    int tunneledMode = 5;
    int bufferQueueSize = 8;
    streamInfo_pre.streamId_ = streamId_preview;
    streamInfo_pre.width_ = preview_width;
    streamInfo_pre.height_ = preview_height;
    streamInfo_pre.format_ = preview_format;
    streamInfo_pre.dataspace_ = dataspace;
    streamInfo_pre.intent_ = PREVIEW;
    streamInfo_pre.tunneledMode_ = tunneledMode;
    std::shared_ptr<StreamConsumer> consumer_pre = std::make_shared<StreamConsumer>();
    std::cout << "==========[test log]received a preview buffer ... 0" << std::endl;
    streamInfo_pre.bufferQueue_ = new BufferProducerSequenceable();
    streamInfo_pre.bufferQueue_->producer_ = consumer_pre->CreateProducer([this](void* addr, uint32_t size) {
        SaveYUV("preview", addr, size);
    });
    streamInfo_pre.bufferQueue_->producer_->SetQueueSize(bufferQueueSize);
    consumerMap_[intent] = consumer_pre;
    streamInfos.push_back(streamInfo_pre);
}

void Test::SetVideoStreamInfo()
{
    int dataspace = 8;
    int tunneledMode = 5;
    int bufferQueueSize = 8;
    streamInfo_video.streamId_ = streamId_video;
    streamInfo_video.width_ = video_width;
    streamInfo_video.height_ = video_height;
    streamInfo_video.format_ = video_format;
    streamInfo_video.dataspace_ = dataspace;
    streamInfo_video.intent_ = VIDEO;
    streamInfo_video.encodeType_ = OHOS::HDI::Camera::V1_0::ENCODE_TYPE_H265;
    streamInfo_video.tunneledMode_ = tunneledMode;
    std::shared_ptr<StreamConsumer> consumer_video = std::make_shared<StreamConsumer>();
    std::cout << "==========[test log]received a video buffer ... 1" << std::endl;
    SaveVideoFile("video", nullptr, 0, 0);
    streamInfo_video.bufferQueue_ = new BufferProducerSequenceable();
    streamInfo_video.bufferQueue_->producer_ = consumer_video->CreateProducer([this](void* addr, uint32_t size) {
        SaveVideoFile("video", addr, size, 1);
    });
    streamInfo_video.bufferQueue_->producer_->SetQueueSize(bufferQueueSize);
    consumerMap_[intent] = consumer_video;
    streamInfos.push_back(streamInfo_video);
}

void Test::SetPhotoStreamInfo()
{
    int dataspace = 8;
    int tunneledMode = 5;
    int bufferQueueSize = 8;
    streamInfo_capture.streamId_ = streamId_capture;
    streamInfo_capture.width_ = snapshot_width;
    streamInfo_capture.height_ = snapshot_height;
    streamInfo_capture.format_ = snapshot_format;
    streamInfo_capture.dataspace_ = dataspace;
    streamInfo_capture.intent_ = STILL_CAPTURE;
    streamInfo_capture.encodeType_ = OHOS::HDI::Camera::V1_0::ENCODE_TYPE_JPEG;
    streamInfo_capture.tunneledMode_ = tunneledMode;
    std::shared_ptr<StreamConsumer> consumer_capture = std::make_shared<StreamConsumer>();
    std::cout << "==========[test log]received a capture buffer ... 2" << std::endl;
    streamInfo_capture.bufferQueue_ = new BufferProducerSequenceable();
    streamInfo_capture.bufferQueue_->producer_ =
        consumer_capture->CreateProducer([this](void* addr, uint32_t size) {
            SaveYUV("capture", addr, size);
    });
    streamInfo_capture.bufferQueue_->producer_->SetQueueSize(bufferQueueSize);
    consumerMap_[intent] = consumer_capture;
    streamInfos.push_back(streamInfo_capture);
}

void Test::StartStream(std::vector<StreamIntent> intents)
{
    streamOperatorCallback = new DStreamOperatorCallback();
    rc = cameraDevice->GetStreamOperator(streamOperatorCallback, streamOperator);
    if (rc == NO_ERROR) {
        std::cout << "==========[test log]GetStreamOperator success." << std::endl;
    } else {
        std::cout << "==========[test log]GetStreamOperator fail, rc = " << rc << std::endl;
    }
    int dataspace = 8;
    int tunneledMode = 5;
    int bufferQueueSize = 8;
    for (auto& intent : intents) {
        if (intent == 0) {
            SetPreviewStreamInfo();
        } else if (intent == 1) {
            SetVideoStreamInfo();
        } else {
            SetPhotoStreamInfo();
        }
    }

    rc = streamOperator->CreateStreams(streamInfos);
    if (rc == NO_ERROR) {
        std::cout << "==========[test log]CreateStreams success." << std::endl;
    } else {
        std::cout << "==========[test log]CreateStreams fail, rc = " << rc << std::endl;
    }
    rc = streamOperator->CommitStreams(NORMAL, ability);
    if (rc == NO_ERROR) {
        std::cout << "==========[test log]CommitStreams success." << std::endl;
    } else {
        std::cout << "==========[test log]CommitStreams fail, rc = " << rc << std::endl;
    }
    unsigned int sleepSeconds = 2;
    sleep(sleepSeconds);
    std::vector<std::shared_ptr<StreamInfo>>().swap(streamInfos);
}

void Test::StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming)
{
    captureInfo.streamIds_ = { streamId };
    captureInfo.captureSetting_ = ability;
    captureInfo.enableShutterCallback_ = shutterCallback;
    rc = streamOperator->Capture(captureId, captureInfo, isStreaming);
    if (rc == NO_ERROR) {
        std::cout << "==========[test log]check Capture: Capture success, " << captureId << std::endl;
    } else {
        std::cout << "==========[test log]check Capture: Capture fail, rc = " << rc << std::endl;
    }
    unsigned int sleepSeconds = 5;
    sleep(sleepSeconds);
}

void Test::StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds)
{
    if (sizeof(captureIds) > 0) {
        for (auto &captureId : captureIds) {
            rc = streamOperator->CancelCapture(captureId);
            if (rc == NO_ERROR) {
                std::cout << "==========[test log]check Capture: CancelCapture success," << captureId << std::endl;
            } else {
                std::cout << "==========[test log]check Capture: CancelCapture fail, rc = " << rc;
                std::cout << "captureId = " << captureId << std::endl;
            }
        }
    }
    int32_t operationMode = 2;
    SaveVideoFile("video", nullptr, 0, operationMode);
    if (sizeof(streamIds) > 0) {
        rc = streamOperator->ReleaseStreams(streamIds);
        if (rc == NO_ERROR) {
            std::cout << "==========[test log]check Capture: ReleaseStreams success." << std::endl;
        } else {
            std::cout << "==========[test log]check Capture: ReleaseStreams fail, rc = " << rc << std::endl;
        }
    }
}

void Test::StopOfflineStream(int captureId)
{
    rc = offlineStreamOperator->CancelCapture(captureId);
    if (rc == NO_ERROR) {
        std::cout << "==========[test log]check offline: CancelCapture success," << captureId << std::endl;
    } else {
        std::cout << "==========[test log]check offline: CancelCapture fail, rc = " << rc;
        std::cout << "captureId = " << captureId << std::endl;
    }
    rc = offlineStreamOperator->Release();
    if (rc == NO_ERROR) {
        std::cout << "==========[test log]Check offline stream: offline Release success." << std::endl;
    } else {
        std::cout << "==========[test log]Check offline stream: offline Release fail, rc = " << rc << std::endl;
    }
}

OHOS::sptr<OHOS::IBufferProducer> Test::StreamConsumer::CreateProducer(std::function<void(void*, uint32_t)> callback)
{
    consumer_ = OHOS::Surface::CreateSurfaceAsConsumer();
    if (consumer_ == nullptr) {
        return nullptr;
    }
    sptr<IBufferConsumerListener> listener = new TestBufferConsumerListener();
    consumer_->RegisterConsumerListener(listener);
    auto producer = consumer_->GetProducer();
    std::cout << "create a buffer queue producer:" << producer.GetRefPtr() << std::endl;
    if (producer == nullptr) {
        return nullptr;
    }
    callback_ = callback;
    consumerThread_ = new std::thread([this] {
        int32_t flushFence = 0;
        int64_t timestamp = 0;
        OHOS::Rect damage;
        while (running_) {
            OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
            consumer_->AcquireBuffer(buffer, flushFence, timestamp, damage);
            if (buffer != nullptr) {
                void* addr = buffer->GetVirAddr();
                uint32_t size = buffer->GetSize();

                int32_t gotSize = 0;
                int32_t isKey = 0;
                int64_t timestamp;
                buffer->ExtraGet("dataSize", gotSize);
                buffer->ExtraGet("isKeyFrame", isKey);
                buffer->ExtraGet("timeStamp", timestamp);
                if (gotSize) {
                    std::cout << "dataSize: " << gotSize << ", isKeyFrame: "
                             << isKey << " timeStamp:" << timestamp << endl;
                }

                callback_(addr, size);
                consumer_->ReleaseBuffer(buffer, -1);
                shotCount_--;
                if (shotCount_ == 0) {
                    std::unique_lock<std::mutex> l(l_);
                    cv_.notify_one();
                }
            }
            if (!running_) {
                break;
            }
            std::this_thread::sleep_for(1ms);
        }
    });
    return producer;
}
} // namespace DistributedHardware
} // namespace OHOS
