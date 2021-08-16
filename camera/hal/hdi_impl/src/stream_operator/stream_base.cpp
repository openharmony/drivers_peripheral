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

#include "stream_base.h"
#include <cstdio>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <display_type.h>
#include <surface_type.h>
#include "buffer_manager.h"
#include "buffer_adapter.h"
#include "image_buffer.h"

namespace {
    constexpr uint32_t BUFFER_QUEUE_SIZE = 8;
    constexpr uint32_t STRIDER_ALIGNMENT = 8;
}

namespace OHOS::Camera {
StreamBase::StreamBase()
{
}

StreamBase::~StreamBase()
{
}

RetCode StreamBase::Init(const std::shared_ptr<StreamInfo> &streamInfo)
{
    RetCode rc = RC_ERROR;
    if (streamInfo == nullptr) {
        CAMERA_LOGE("input param is null.");
        return rc;
    }
    streamInfo_ = streamInfo;
    if (streamInfo_->bufferQueue_ != nullptr) {
        producer_ = OHOS::Surface::CreateSurfaceAsProducer(streamInfo_->bufferQueue_);
    }

    CAMERA_LOGD("init stream id = %d", streamInfo_->streamId_);
    rc = CreateBufferPool();
    if (rc != RC_OK) {
        CAMERA_LOGE("create buffer pool failed.");
        return rc;
    }

    if (attribute_ == nullptr) {
        attribute_ = std::make_shared<StreamAttribute>();
        if (attribute_ == nullptr) {
            return RC_ERROR;
        }
    }

    attribute_->streamId_ = streamInfo_->streamId_;
    attribute_->width_ = streamInfo_->width_;
    attribute_->height_ = streamInfo_->height_;
    attribute_->overrideFormat_ = streamInfo_->format_;
    attribute_->overrideDatasapce_ = streamInfo_->datasapce_;
    attribute_->producerUsage_ = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA;
    attribute_->producerBufferCount_ = GetQueueSize();
    attribute_->maxBatchCaptureCount_ = GetQueueSize();
    attribute_->maxCaptureCount_ = 1;

    return RC_OK;
}

RetCode StreamBase::RequestCheck()
{
    if (streamInfo_ == nullptr) {
        CAMERA_LOGW("stream info is null.");
        return RC_ERROR;
    }

    if (producer_ == nullptr) {
        CAMERA_LOGW("buffer queue is null.");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode StreamBase::Request()
{
    if (!isOnline) {
        return RC_OK;
    }

    if (RequestCheck() == RC_ERROR) {
        return RC_ERROR;
    }

    if (!requestFlag_) {
        return RC_OK;
    }

    OHOS::sptr<OHOS::SurfaceBuffer> sb = nullptr;
    // get surface buffer from producer client
    int32_t fence = 0;
    OHOS::BufferRequestConfig config = {
        .width = streamInfo_->width_,
        .height = streamInfo_->height_,
        .strideAlignment = STRIDER_ALIGNMENT,
        .format = streamInfo_->format_,
        .usage = attribute_->producerUsage_,
        .timeout = 0
    };
    OHOS::SurfaceError sfError = producer_->RequestBuffer(sb, fence, config);
    if (sfError == OHOS::SURFACE_ERROR_NO_BUFFER) {
        return RC_OK;
    }
    if (sfError != OHOS::SURFACE_ERROR_OK) {
        CAMERA_LOGE("get producer buffer failed. [streamId = %{public}d] [sfError = %{public}d]",
            streamInfo_->streamId_, sfError);
        return RC_ERROR;
    }

    std::shared_ptr<IBuffer> cameraBuffer = nullptr;
    {
        std::unique_lock<std::mutex> l(bmLock_);
        auto it = std::find_if(bufferMap_.begin(), bufferMap_.end(),
            [&sb](const std::pair<std::shared_ptr<IBuffer>, OHOS::sptr<OHOS::SurfaceBuffer>>& p) {
                return sb == p.second;
            });
        if (it == bufferMap_.end()) {
            // surface buffer change to camera buffer
            cameraBuffer = std::make_shared<ImageBuffer>(CAMERA_BUFFER_SOURCE_TYPE_EXTERNAL);
            RetCode rc = BufferAdapter::SurfaceBufferToCameraBuffer(sb, cameraBuffer);
            if (rc != RC_OK) {
                CAMERA_LOGE("surface buffer change failed. [streamId = %{public}d]", streamInfo_->streamId_);
                return RC_ERROR;
            }
            cameraBuffer->SetIndex(++bufferIndex);
            bufferMap_[cameraBuffer] = sb;
        } else {
            cameraBuffer = it->first;
        }
    }

    // add buffer to buffer pool
    if (streamInfo_->encodeType_ != 0) {
        cameraBuffer->SetEncodeType(streamInfo_->encodeType_);
    }
    cameraBuffer->SetFenceId(fence);
    RetCode rc = bufferPool_->AddBuffer(cameraBuffer);
    if (rc != RC_OK) {
        CAMERA_LOGE("buffer enq failed. [streamId = %{public}d]", streamInfo_->streamId_);
        return RC_ERROR;
    }

    {
        std::lock_guard<std::mutex> l(frameLock_);
        frameCount_++;
        pipeBuffer_.emplace_back(cameraBuffer);
        CAMERA_LOGD("buffer enqueue. [index = %d, streamId = %d, addr = %p]",
            cameraBuffer->GetIndex(), streamInfo_->streamId_, sb->GetVirAddr());
    }
    return RC_OK;
}

RetCode StreamBase::Result(const std::shared_ptr<IBuffer> &buffer, OperationType optType)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("result buffer is null. [streamId = %d]", streamInfo_->streamId_);
        return RC_ERROR;
    }

    int32_t index = buffer->GetIndex();
    std::shared_ptr<IBuffer> cameraBuffer = nullptr;
    {
        std::lock_guard<std::mutex> l(frameLock_);
        auto itcb = std::find(pipeBuffer_.begin(), pipeBuffer_.end(), buffer);
        if (itcb == pipeBuffer_.end()) {
            CAMERA_LOGE("fatal error, can't find camera buffer [index:%{public}d] [streamId = %{public}d]",
                index, streamInfo_->streamId_);
            return RC_ERROR;
        }
        cameraBuffer = *itcb;
        pipeBuffer_.erase(itcb);
    }

    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer = nullptr;
    {
        std::unique_lock<std::mutex> l(bmLock_);
        auto itsb = bufferMap_.find(cameraBuffer);
        if (itsb == bufferMap_.end()) {
            CAMERA_LOGE("fatal error, can't find surface buffer [index:%{public}d] [streamId = %{public}d]",
                __FUNCTION__, index, streamInfo_->streamId_);
            return RC_ERROR;
        }
        surfaceBuffer = bufferMap_[cameraBuffer];
    }

    RetCode rc = bufferPool_->ReturnBuffer(cameraBuffer);
    if (rc != RC_OK) {
        CAMERA_LOGE("buffpool return buffer failed");
    }

    int32_t fence = 0;
    OHOS::BufferFlushConfig flushConf = {
        .damage = {
            .x = 0,
            .y = 0,
            .w = streamInfo_->width_,
            .h = streamInfo_->height_
        },
        .timestamp = 0
    };
    if (producer_ != nullptr) {
        if (optType == STREAM_BUFFER_FLUSH) {
            CAMERA_LOGD("buffer dequeue. [index = %d, streamId = %d, addr = %p]",
                index, streamInfo_->streamId_, surfaceBuffer->GetVirAddr());
            producer_->FlushBuffer(surfaceBuffer, fence, flushConf);
        } else {
            CAMERA_LOGD("buffer cancel. [index = %d, streamId = %d, addr = %p]",
                index, streamInfo_->streamId_, surfaceBuffer->GetVirAddr());
            producer_->CancelBuffer(surfaceBuffer);
        }
    }

    std::unique_lock<std::mutex> l(frameLock_);
    frameCount_--;
    return RC_OK;
}

RetCode StreamBase::CreateBufferPool()
{
    if (streamInfo_ == nullptr) {
        CAMERA_LOGE("cannot create bufferpool by invalid streaminfo");
        return RC_ERROR;
    }

    BufferManager *bufMgr = BufferManager::GetInstance();
    if (bufMgr == nullptr) {
        CAMERA_LOGW("buffer manager is null.");
        return RC_ERROR;
    }

    int64_t bufPoolId = bufMgr->GenerateBufferPoolId();
    if (bufPoolId == 0) {
        CAMERA_LOGW("generate buffer poolId failed.");
        return RC_ERROR;
    }

    bufferPool_ = bufMgr->GetBufferPool(bufPoolId);
    if (bufferPool_ == nullptr) {
        CAMERA_LOGE("get buffer pool is null.");
        return RC_ERROR;
    }

    CAMERA_LOGV("get buffer pool id = %lld, instance = %p", bufPoolId, bufferPool_.get());
    bufferPoolId_ = static_cast<uint64_t>(bufPoolId);

    uint32_t nCount = GetQueueSize();
    if (producer_ != nullptr) {
        producer_->SetQueueSize(nCount);
    }

    uint32_t nUsage = CAMERA_USAGE_SW_WRITE_OFTEN |
        CAMERA_USAGE_SW_READ_OFTEN | CAMERA_USAGE_MEM_DMA;

    PixelFormat pf = static_cast<PixelFormat>(streamInfo_->format_);
    uint32_t format = BufferAdapter::PixelFormatToCameraFormat(pf);

    RetCode rc = bufferPool_->Init(streamInfo_->width_, streamInfo_->height_,
        nUsage, format, nCount, CAMERA_BUFFER_SOURCE_TYPE_EXTERNAL);

    return rc;
}

uint64_t StreamBase::GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return static_cast<uint64_t>(tmp.count());
}

RetCode StreamBase::AttachBufferQueue(const OHOS::sptr<OHOS::IBufferProducer> &producer)
{
    if (streamInfo_ == nullptr) {
        CAMERA_LOGE("stream info is null.");
        return RC_ERROR;
    }

    streamInfo_->bufferQueue_ = producer;
    if (streamInfo_->bufferQueue_ != nullptr) {
        producer_ = OHOS::Surface::CreateSurfaceAsProducer(streamInfo_->bufferQueue_);
    }
    return RC_OK;
}

RetCode StreamBase::DetachBufferQueue()
{
    if (streamInfo_ == nullptr) {
        CAMERA_LOGE("stream info is null.");
        return RC_ERROR;
    }

    streamInfo_->bufferQueue_ = nullptr;
    producer_ = nullptr;
    return RC_OK;
}

RetCode StreamBase::GetStreamAttribute(std::shared_ptr<StreamAttribute> &attribute) const
{
    attribute = attribute_;
    if (attribute == nullptr) {
        return RC_ERROR;
    }
    return RC_OK;
}

std::shared_ptr<StreamInfo>& StreamBase::GetStreamInfo()
{
    return streamInfo_;
}

RetCode StreamBase::Release()
{
    bufferPoolId_ = 0;
    // stop reques buffer,destroy producer
    return RC_OK;
}

uint64_t StreamBase::GetBufferPoolId() const
{
    return bufferPoolId_;
}

void StreamBase::Stop()
{
    requestFlag_ = false;

    if (!isOnline) {
        return;
    }

    if (bufferPool_ == nullptr || producer_ == nullptr) {
        return;
    }

    // FIXME: call device to flush buffer
    {
        std::lock_guard<std::mutex> l(frameLock_);
        for (auto it : pipeBuffer_) {
            RetCode rc = bufferPool_->ReturnBuffer(it);
            if (rc != RC_OK) {
                CAMERA_LOGE("buffpool return buffer failed");
            }
            std::unique_lock<std::mutex> cl(bmLock_);
            auto itsb = bufferMap_.find(it);
            if (itsb == bufferMap_.end()) {
                continue;
            }
             CAMERA_LOGI("buffer cancel. [index = %d, streamId = %d, addr = %p]",
                it->GetIndex(), streamInfo_->streamId_, bufferMap_[it]->GetVirAddr());
            producer_->CancelBuffer(bufferMap_[it]);
        }
        pipeBuffer_.clear();
    }

    {
        std::unique_lock<std::mutex> cl(bmLock_);
        bufferMap_.clear();
    }
}

RetCode StreamBase::HandleOverStaticContext(const std::shared_ptr<OfflineStreamContext>& context)
{
    return RC_ERROR;
}

RetCode StreamBase::HandleOverDynamicContext(const std::shared_ptr<OfflineStreamContext>& context)
{
    return RC_ERROR;
}

RetCode StreamBase::SwitchToOffline()
{
    return RC_ERROR;
}

uint32_t StreamBase::GetQueueSize() const
{
    return BUFFER_QUEUE_SIZE;
}
} // namespace OHOS::Camera
