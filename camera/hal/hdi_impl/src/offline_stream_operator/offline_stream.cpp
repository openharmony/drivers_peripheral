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

#include "offline_stream.h"
#include "offline_pipeline_manager.h"

namespace OHOS::Camera {
OfflineStream::OfflineStream(int32_t id,
                             std::shared_ptr<OfflineStreamContext>& context,
                             OHOS::wptr<IStreamOperatorCallback>& callback)
{
    streamId_ = id;
    context_ = context;
    operatorCallback_ = callback;
}

OfflineStream::~OfflineStream() {}

RetCode OfflineStream::Init()
{
    OfflinePipelineManager& manager = OfflinePipelineManager::GetInstance();
    std::shared_ptr<IStreamPipelineCore> pipeline = context_->pipeline.lock();
    auto cb = [this](std::shared_ptr<IBuffer>& buffer) { ReceiveOfflineBuffer(buffer); };
    RetCode ret =
        manager.SwitchToOfflinePipeline(streamId_, context_->streamInfo->intent_, pipeline, cb);
    if (ret != RC_OK) {
        CAMERA_LOGE("switch to offline stream failed.");
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode OfflineStream::CancelCapture(int32_t captureId)
{
    OfflinePipelineManager& manager = OfflinePipelineManager::GetInstance();
    RetCode ret = manager.CancelCapture(streamId_, captureId);
    if (ret != RC_OK) {
        CAMERA_LOGE("cancel capture %{public}d failed", captureId);
        return RC_ERROR;
    }

    return RC_OK;
}

RetCode OfflineStream::Release()
{
    {
        std::unique_lock<std::mutex> l(lock_);
        cv_.wait(l, [this]{ return context_->restBufferCount <= 0; });
    }

    OfflinePipelineManager& manager = OfflinePipelineManager::GetInstance();
    RetCode ret = manager.DestoryOfflinePipeline(streamId_);
    if (ret != RC_OK) {
        CAMERA_LOGE("release offline pipeline %{public}d failed", streamId_);
        return RC_ERROR;
    }

    return RC_OK;
}

void OfflineStream::ReceiveOfflineBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (context_ == nullptr) {
        return;
    }

    if (buffer == nullptr) {
        CAMERA_LOGE("fatal error, buffer should not be null");
        return;
    }

    ReturnBuffer(buffer);
    return;
}

RetCode OfflineStream::ReturnBuffer(std::shared_ptr<IBuffer>& buffer)
{
    auto producer = context_->bufferQueue;
    if (producer == nullptr) {
        CAMERA_LOGE("fatal error, buffer queue is null.");
        return RC_ERROR;
    }

    auto bufferPool = context_->bufferPool;
    if (bufferPool == nullptr) {
        CAMERA_LOGE("fatal error, buffer pool is null");
        return RC_ERROR;
    }

    RetCode rc = bufferPool->ReturnBuffer(buffer);
    if (rc != RC_OK) {
        CAMERA_LOGE("buffpool return buffer failed");
    }

    auto itsb = context_->restBuffers.find(buffer);
    if (itsb == context_->restBuffers.end()) {
        CAMERA_LOGE("buffer %{public}p doesn't belong to stream %{public}p", buffer.get(), this);
        return RC_ERROR;
    }
    auto sb = context_->restBuffers[buffer];
    int32_t fence = 0;
    OHOS::BufferFlushConfig flushConfig = {
        .damage = {.x = 0, .y = 0, .w = context_->streamInfo->width_, .h = context_->streamInfo->height_},
        .timestamp = 0
    };

    if (buffer->GetValidFlag()) {
        producer->FlushBuffer(sb, fence, flushConfig);
    } else {
        producer->CancelBuffer(sb);
        std::shared_ptr<CaptureErrorInfo> info = std::make_shared<CaptureErrorInfo>();
        info->streamId_ = streamId_;
        info->error_ = BUFFER_LOST;
        std::vector<std::shared_ptr<CaptureErrorInfo>> errorInfo = {};
        errorInfo.emplace_back(info);
        if (operatorCallback_ != nullptr) {
            auto cb = operatorCallback_.promote();
            cb->OnCaptureError(buffer->GetCaptureId(), errorInfo);
        }
    }

    uint64_t fs = buffer->GetFrameNumber();
    if (fs > frameCount_) {
        frameCount_ = fs;
    }

    std::unique_lock<std::mutex> l(lock_);
    context_->restBufferCount--;
    currentCaptureId_ = buffer->GetCaptureId();

    if (context_->restBufferCount <= 0) {
        std::shared_ptr<CaptureEndedInfo> info = std::make_shared<CaptureEndedInfo>();
        info->streamId_ = streamId_;
        info->frameCount_ = static_cast<int>(frameCount_);
        std::vector<std::shared_ptr<CaptureEndedInfo>> endInfo = {};
        endInfo.emplace_back(info);
        if (operatorCallback_ != nullptr) {
            auto cb = operatorCallback_.promote();
            cb->OnCaptureEnded(currentCaptureId_, endInfo);
        }
    }

    return RC_OK;
}

bool OfflineStream::CheckCaptureIdExist(int32_t captureId)
{
    OfflinePipelineManager& manager = OfflinePipelineManager::GetInstance();
    return manager.CheckCaptureIdExist(streamId_, captureId);
}
} // namespace OHOS::Camera
