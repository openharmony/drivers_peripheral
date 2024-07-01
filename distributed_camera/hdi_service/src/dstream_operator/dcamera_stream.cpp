/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "dcamera_stream.h"

#include "constants.h"
#include "dcamera.h"
#include "distributed_hardware_log.h"
#include "securec.h"

namespace OHOS {
namespace DistributedHardware {
DCamRetCode DCameraStream::InitDCameraStream(const StreamInfo &info)
{
    if ((info.streamId_ < 0) || (info.width_ < 0) || (info.height_ < 0) ||
        (info.format_ < 0) || (info.dataspace_ < 0)) {
        DHLOGE("Stream info is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    dcStreamId_ = info.streamId_;
    dcStreamInfo_ = std::make_shared<StreamInfo>();
    dcStreamInfo_->streamId_ = info.streamId_;
    dcStreamInfo_->width_ = info.width_;
    dcStreamInfo_->height_ = info.height_;
    dcStreamInfo_->format_ = info.format_;
    dcStreamInfo_->dataspace_ = info.dataspace_;
    dcStreamInfo_->intent_ = info.intent_;
    dcStreamInfo_->tunneledMode_ = info.tunneledMode_;
    dcStreamInfo_->bufferQueue_ = info.bufferQueue_;
    dcStreamInfo_->minFrameDuration_ = info.minFrameDuration_;

    dcStreamAttribute_.streamId_ = dcStreamInfo_->streamId_;
    dcStreamAttribute_.width_ = dcStreamInfo_->width_;
    dcStreamAttribute_.height_ = dcStreamInfo_->height_;
    dcStreamAttribute_.overrideFormat_ = dcStreamInfo_->format_;
    dcStreamAttribute_.overrideDataspace_ = dcStreamInfo_->dataspace_;
    dcStreamAttribute_.producerUsage_ = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA;

    dcStreamAttribute_.producerBufferCount_ = BUFFER_QUEUE_SIZE;
    dcStreamAttribute_.maxBatchCaptureCount_ = BUFFER_QUEUE_SIZE;
    dcStreamAttribute_.maxCaptureCount_ = 1;

    DCamRetCode ret = DCamRetCode::SUCCESS;
    if (dcStreamInfo_->bufferQueue_ != nullptr) {
        ret = InitDCameraBufferManager();
        if (ret != DCamRetCode::SUCCESS) {
            DHLOGE("Cannot init buffer manager.");
        }
    }
    isCancelBuffer_ = false;
    isCancelCapture_ = false;
    return ret;
}

DCamRetCode DCameraStream::InitDCameraBufferManager()
{
    if (dcStreamInfo_ == nullptr) {
        DHLOGE("Distributed camera stream info is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    if (dcStreamInfo_->bufferQueue_ != nullptr && dcStreamInfo_->bufferQueue_->producer_ != nullptr) {
        dcStreamProducer_ = OHOS::Surface::CreateSurfaceAsProducer(dcStreamInfo_->bufferQueue_->producer_);
    }
    if (dcStreamProducer_ == nullptr) {
        DHLOGE("Distributed camera stream producer is invalid.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    dcStreamBufferMgr_ = std::make_shared<DBufferManager>();

    DCamRetCode ret = DCamRetCode::SUCCESS;
    if (!isBufferMgrInited_) {
        ret = FinishCommitStream();
    }
    return ret;
}

DCamRetCode DCameraStream::GetDCameraStreamInfo(shared_ptr<StreamInfo> &info)
{
    if (!dcStreamInfo_) {
        DHLOGE("Distributed camera stream info is not init.");
        return DCamRetCode::FAILED;
    }
    info = dcStreamInfo_;
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraStream::SetDCameraBufferQueue(const OHOS::sptr<BufferProducerSequenceable> &producer)
{
    CHECK_AND_RETURN_RET_LOG(dcStreamInfo_ == nullptr, DCamRetCode::FAILED, "dcStreamInfo_ is nullptr");
    if (dcStreamInfo_->bufferQueue_) {
        DHLOGE("Stream [%{public}d] has already have bufferQueue.", dcStreamId_);
        return DCamRetCode::SUCCESS;
    }

    dcStreamInfo_->bufferQueue_ = producer;
    DCamRetCode ret = InitDCameraBufferManager();
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("Init distributed camera buffer manager failed.");
    }
    return ret;
}

DCamRetCode DCameraStream::ReleaseDCameraBufferQueue()
{
    DCamRetCode ret = CancelDCameraBuffer();
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("Release distributed camera buffer queue failed.");
        return ret;
    }

    std::lock_guard<std::mutex> lockBuffer(bufferQueueMutex_);
    if (dcStreamInfo_ != nullptr && dcStreamInfo_->bufferQueue_ != nullptr) {
        dcStreamInfo_->bufferQueue_->producer_ = nullptr;
        dcStreamInfo_->bufferQueue_ = nullptr;
    }
    if (dcStreamProducer_ != nullptr) {
        dcStreamProducer_->CleanCache();
        dcStreamProducer_ = nullptr;
    }
    dcStreamBufferMgr_ = nullptr;

    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraStream::GetDCameraStreamAttribute(StreamAttribute &attribute)
{
    attribute = dcStreamAttribute_;
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraStream::FinishCommitStream()
{
    if (isBufferMgrInited_) {
        DHLOGI("Stream already inited.");
        return DCamRetCode::SUCCESS;
    }
    if (dcStreamProducer_ == nullptr) {
        DHLOGI("No bufferQueue.");
        return DCamRetCode::SUCCESS;
    }
    dcStreamProducer_->SetQueueSize(BUFFER_QUEUE_SIZE);
    isBufferMgrInited_ = true;

    for (uint32_t i = 0; i < BUFFER_QUEUE_SIZE; i++) {
        GetNextRequest();
    }
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraStream::CheckRequestParam()
{
    if (!isBufferMgrInited_) {
        DHLOGE("BufferManager not be init.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (dcStreamInfo_ == nullptr) {
        DHLOGE("Cannot create buffer manager by invalid streaminfo.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    if (dcStreamProducer_ == nullptr) {
        DHLOGE("Cannot create a buffer manager by invalid bufferqueue.");
        return DCamRetCode::INVALID_ARGUMENT;
    }

    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraStream::GetNextRequest()
{
    if (CheckRequestParam() != DCamRetCode::SUCCESS) {
        return DCamRetCode::INVALID_ARGUMENT;
    }

    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    OHOS::sptr<OHOS::SyncFence> syncFence = nullptr;
    int32_t usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA;
    CHECK_AND_RETURN_RET_LOG(dcStreamInfo_ == nullptr, DCamRetCode::INVALID_ARGUMENT, "dcStreamInfo_ is nullptr");
    OHOS::BufferRequestConfig config = {
        .width = dcStreamInfo_->width_,
        .height = dcStreamInfo_->height_,
        .strideAlignment = 8,
        .format = dcStreamInfo_->format_,
        .usage = usage,
        .timeout = 0
    };

    if (dcStreamInfo_->intent_ == StreamIntent::STILL_CAPTURE) {
        config.width = JPEG_MAX_SIZE;
        config.height = 1;
        config.format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_BLOB;
    }
    CHECK_AND_RETURN_RET_LOG(
        dcStreamProducer_ == nullptr, DCamRetCode::INVALID_ARGUMENT, "dcStreamProducer_ is nullptr");
    OHOS::SurfaceError surfaceError = dcStreamProducer_->RequestBuffer(surfaceBuffer, syncFence, config);
    if (surfaceError == OHOS::SURFACE_ERROR_NO_BUFFER) {
        DHLOGE("No available buffer to request in surface.");
        return DCamRetCode::EXCEED_MAX_NUMBER;
    }

    if (surfaceError != OHOS::SURFACE_ERROR_OK || surfaceBuffer == nullptr) {
        DHLOGE("Get producer buffer failed. [streamId = %{public}d] [sfError = %{public}d]",
            dcStreamInfo_->streamId_, surfaceError);
        return DCamRetCode::EXCEED_MAX_NUMBER;
    }
    return SurfaceBufferToDImageBuffer(surfaceBuffer, syncFence);
}

DCamRetCode DCameraStream::SurfaceBufferToDImageBuffer(OHOS::sptr<OHOS::SurfaceBuffer> &surfaceBuffer,
    OHOS::sptr<OHOS::SyncFence> &syncFence)
{
    std::shared_ptr<DImageBuffer> imageBuffer = std::make_shared<DImageBuffer>();
    RetCode ret = DBufferManager::SurfaceBufferToDImageBuffer(surfaceBuffer, imageBuffer);
    if (ret != RC_OK) {
        DHLOGE("Convert surfacebuffer to image buffer failed, streamId = %{public}d.", dcStreamInfo_->streamId_);
        dcStreamProducer_->CancelBuffer(surfaceBuffer);
        return DCamRetCode::EXCEED_MAX_NUMBER;
    }

    imageBuffer->SetIndex(++index_);
    imageBuffer->SetSyncFence(syncFence);
    CHECK_AND_RETURN_RET_LOG(
        dcStreamBufferMgr_ == nullptr, DCamRetCode::INVALID_ARGUMENT, "dcStreamBufferMgr_ is nullptr");
    ret = dcStreamBufferMgr_->AddBuffer(imageBuffer);
    if (ret != RC_OK) {
        DHLOGE("Add buffer to buffer manager failed. [streamId = %{public}d]", dcStreamInfo_->streamId_);
        dcStreamProducer_->CancelBuffer(surfaceBuffer);
        return DCamRetCode::EXCEED_MAX_NUMBER;
    }
    DHLOGD("Add new image buffer success: index = %{public}d, fenceFd = %{public}d", imageBuffer->GetIndex(),
        syncFence->Get());
    auto itr = bufferConfigMap_.find(imageBuffer);
    if (itr == bufferConfigMap_.end()) {
        int32_t usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA;
        auto bufferCfg = std::make_tuple(surfaceBuffer, usage);
        bufferConfigMap_.insert(std::make_pair(imageBuffer, bufferCfg));
    }
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraStream::GetDCameraBuffer(DCameraBuffer &buffer)
{
    std::lock_guard<std::mutex> lockRequest(requestMutex_);
    if (isCancelBuffer_ || isCancelCapture_) {
        DHLOGE("Buffer has already canceled.");
        return DCamRetCode::FAILED;
    }
    {
        std::lock_guard<std::mutex> lockBuffer(bufferQueueMutex_);
        DCamRetCode retCode = GetNextRequest();
        if (retCode != DCamRetCode::SUCCESS && retCode != DCamRetCode::EXCEED_MAX_NUMBER) {
            DHLOGE("Get next request failed.");
            return retCode;
        }

        if (dcStreamBufferMgr_ == nullptr) {
            DHLOGE("dcStreamBufferMgr_ is nullptr");
            return DCamRetCode::FAILED;
        }
        std::shared_ptr<DImageBuffer> imageBuffer = dcStreamBufferMgr_->AcquireBuffer();
        if (imageBuffer == nullptr) {
            DHLOGE("Cannot get idle buffer.");
            return DCamRetCode::EXCEED_MAX_NUMBER;
        }
        auto syncFence = imageBuffer->GetSyncFence();
        if (syncFence != nullptr) {
            syncFence->Wait(BUFFER_SYNC_FENCE_TIMEOUT);
        }
        RetCode ret = DBufferManager::DImageBufferToDCameraBuffer(imageBuffer, buffer);
        if (ret != RC_OK) {
            DHLOGE("Convert image buffer to distributed camera buffer failed.");
            return DCamRetCode::FAILED;
        }
    }

    {
        std::lock_guard<std::mutex> lockSync(lockSync_);
        captureBufferCount_++;
    }
    DHLOGD("Get buffer success. index = %{public}d, size = %{public}d", buffer.index_, buffer.size_);
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraStream::FlushDCameraBuffer(const DCameraBuffer &buffer)
{
    std::lock_guard<std::mutex> lockBuffer(bufferQueueMutex_);
    shared_ptr<DImageBuffer> imageBuffer = nullptr;
    for (auto iter = bufferConfigMap_.begin(); iter != bufferConfigMap_.end(); ++iter) {
        if (buffer.index_ == iter->first->GetIndex()) {
            imageBuffer = iter->first;
            break;
        }
    }
    if (imageBuffer == nullptr) {
        DHLOGE("Cannot found image buffer, buffer index = %{public}d.", buffer.index_);
        return DCamRetCode::INVALID_ARGUMENT;
    }

    if (dcStreamBufferMgr_ != nullptr) {
        RetCode ret = dcStreamBufferMgr_->RemoveBuffer(imageBuffer);
        if (ret != RC_OK) {
            DHLOGE("Buffer manager remove buffer failed: %{public}d", ret);
        }
    }

    auto bufCfg = bufferConfigMap_.find(imageBuffer);
    if (bufCfg == bufferConfigMap_.end()) {
        DHLOGE("Cannot get bufferConfig.");
        return DCamRetCode::INVALID_ARGUMENT;
    }
    auto surfaceBuffer = std::get<0>(bufCfg->second);
    int64_t timeStamp = static_cast<int64_t>(GetVideoTimeStamp());
    OHOS::BufferFlushConfig flushConf = {
        .damage = { .x = 0, .y = 0, .w = dcStreamInfo_->width_, .h = dcStreamInfo_->height_ },
        .timestamp = timeStamp
    };
    if (dcStreamProducer_ != nullptr) {
        SetSurfaceBuffer(surfaceBuffer, buffer);
        OHOS::sptr<OHOS::SyncFence> autoFence(new(std::nothrow) OHOS::SyncFence(-1));
        int ret = dcStreamProducer_->FlushBuffer(surfaceBuffer, autoFence, flushConf);
        if (ret != 0) {
            DHLOGI("FlushBuffer error: %{public}d", ret);
        }
    }
    bufferConfigMap_.erase(bufCfg);
    return DCamRetCode::SUCCESS;
}

DCamRetCode DCameraStream::ReturnDCameraBuffer(const DCameraBuffer &buffer)
{
    DCamRetCode ret = FlushDCameraBuffer(buffer);
    if (ret != DCamRetCode::SUCCESS) {
        DHLOGE("Flush Buffer failed, ret: %{public}d", ret);
        return ret;
    }

    {
        std::lock_guard<std::mutex> lockSync(lockSync_);
        captureBufferCount_--;
    }
    cv_.notify_one();
    return DCamRetCode::SUCCESS;
}

void DCameraStream::SetSurfaceBuffer(OHOS::sptr<OHOS::SurfaceBuffer>& surfaceBuffer, const DCameraBuffer &buffer)
{
    if (dcStreamInfo_->intent_ == StreamIntent::VIDEO) {
        int32_t size = (dcStreamInfo_->width_) * (dcStreamInfo_->height_) * YUV_WIDTH_RATIO / YUV_HEIGHT_RATIO;
        int64_t timeStamp = static_cast<int64_t>(GetVideoTimeStamp());
        surfaceBuffer->GetExtraData()->ExtraSet("dataSize", size);
        surfaceBuffer->GetExtraData()->ExtraSet("isKeyFrame", (int32_t)0);
        surfaceBuffer->GetExtraData()->ExtraSet("timeStamp", timeStamp);
    } else if (dcStreamInfo_->intent_ == StreamIntent::STILL_CAPTURE) {
        int32_t size = buffer.size_;
        int64_t timeStamp = static_cast<int64_t>(GetCurrentLocalTimeStamp());
        surfaceBuffer->GetExtraData()->ExtraSet("dataSize", size);
        surfaceBuffer->GetExtraData()->ExtraSet("isKeyFrame", (int32_t)0);
        surfaceBuffer->GetExtraData()->ExtraSet("timeStamp", timeStamp);
    }
}

uint64_t DCameraStream::GetVideoTimeStamp()
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return tp.tv_sec * SEC_TO_NSEC_TIMES + tp.tv_nsec;
}

void DCameraStream::DoCapture()
{
    DHLOGI("Do capture, streamId %{public}d", dcStreamInfo_->streamId_);
    std::lock_guard<std::mutex> lockRequest(requestMutex_);
    isCancelCapture_ = false;
}

void DCameraStream::CancelCaptureWait()
{
    DHLOGI("Cancel capture wait for, streamId %{public}d", dcStreamInfo_->streamId_);
    std::lock_guard<std::mutex> lockRequest(requestMutex_);
    if (isCancelCapture_) {
        DHLOGI("CacelCapture has already execute");
        return;
    }
    if (captureBufferCount_ != 0) {
        DHLOGI("StreamId:%{public}d has request that not return and wait, captureBufferCount=%{public}d",
            dcStreamInfo_->streamId_, captureBufferCount_);
    }
    {
        std::unique_lock<std::mutex> lockSync(lockSync_);
        cv_.wait(lockSync, [this] { return !captureBufferCount_; });
    }
    isCancelCapture_ = true;
    DHLOGI("Cancel capture wait for success, streamId %{public}d", dcStreamInfo_->streamId_);
    return;
}

DCamRetCode DCameraStream::CancelDCameraBuffer()
{
    DHLOGI("Cancel dcamera buffer wait for, streamId %{public}d", dcStreamInfo_->streamId_);
    std::lock_guard<std::mutex> lockRequest(requestMutex_);
    if (dcStreamBufferMgr_ == nullptr || dcStreamProducer_ == nullptr || isCancelBuffer_) {
        DHLOGE("BufferManager or Producer is null or isCanceled is true.");
        return DCamRetCode::SUCCESS;
    }

    if (captureBufferCount_ != 0) {
        DHLOGI("StreamId:%{public}d has request that not return, captureBufferCount=%{public}d",
            dcStreamInfo_->streamId_, captureBufferCount_);
    }
    {
        std::unique_lock<std::mutex> lockSync(lockSync_);
        cv_.wait(lockSync, [this] { return !captureBufferCount_; });
    }

    {
        std::lock_guard<std::mutex> lockBuffer(bufferQueueMutex_);
        while (true) {
            std::shared_ptr<DImageBuffer> imageBuffer = dcStreamBufferMgr_->AcquireBuffer();
            if (imageBuffer != nullptr) {
                auto bufCfg = bufferConfigMap_.find(imageBuffer);
                if (bufCfg == bufferConfigMap_.end()) {
                    DHLOGE("Buffer not in map.");
                    return DCamRetCode::INVALID_ARGUMENT;
                }
                auto surfaceBuffer = std::get<0>(bufCfg->second);
                if (dcStreamProducer_ != nullptr) {
                    dcStreamProducer_->CancelBuffer(surfaceBuffer);
                }
                bufferConfigMap_.erase(bufCfg);
            } else {
                break;
            }
        }
        index_ = -1;
    }
    captureBufferCount_ = 0;
    isCancelBuffer_ = true;
    DHLOGI("Cancel dcamera buffer wait for success, streamId %{public}d", dcStreamInfo_->streamId_);
    return DCamRetCode::SUCCESS;
}

bool DCameraStream::HasBufferQueue()
{
    if (dcStreamProducer_ == nullptr || !isBufferMgrInited_) {
        return false;
    }
    return true;
}
} // namespace DistributedHardware
} // namespace OHOS
