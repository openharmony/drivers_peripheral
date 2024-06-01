/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fork_node.h"
#include "securec.h"
#include <thread>

namespace OHOS::Camera {
ForkNode::ForkNode(const std::string& name, const std::string& type, const std::string &cameraId)
    : NodeBase(name, type, cameraId)
{
    CAMERA_LOGV("%{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
    isDeliveryForkBufferInAloneThread_ = true;
}

ForkNode::~ForkNode()
{
}

RetCode ForkNode::Start(const int32_t streamId)
{
    int32_t id = 0;
    uint64_t bufferPoolId = 0;
    {
        std::unique_lock<std::mutex> l(bufferMtx);
        stopForkThread_ = false;
    }
    CAMERA_LOGI("ForkNode::Start streamId = %{public}d this:[%{public}p] streamRunning_ = %{public}d\n",
        streamId, this, streamRunning_ ? 0 : 1);
    if (streamRunning_) {
        return RC_OK;
    }
    inPutPorts_ = GetInPorts();
    outPutPorts_ = GetOutPorts();
    for (const auto& in : inPutPorts_) {
        for (auto& out : outPutPorts_) {
            if (out->format_.streamId_ != in->format_.streamId_) {
                id = out->format_.streamId_;
                bufferPoolId = out->format_.bufferPoolId_;
                CAMERA_LOGI("fork buffer get buffer streamId = %{public}d", out->format_.streamId_);
            }
        }
    }
    BufferManager* bufferManager = Camera::BufferManager::GetInstance();
    if (bufferManager == nullptr) {
        CAMERA_LOGE("fork buffer get instance failed");
        return RC_ERROR;
    }

    bufferPool_ = bufferManager->GetBufferPool(bufferPoolId);
    if (bufferPool_ == nullptr) {
        CAMERA_LOGE("get bufferpool failed: %{public}zu", bufferPoolId);
        return RC_ERROR;
    }

    forkThread_ = std::make_shared<std::thread>([this]() {
        while (!stopForkThread_) {
            DeliverBufferToNextNode();
        }
    });
    if (forkThread_ == nullptr) {
        CAMERA_LOGE("create thread worker DeliverBufferToNextNode() failed!!!");
        return RC_ERROR;
    }
    streamId_ = id;
    streamRunning_ = true;
    return RC_OK;
}

RetCode ForkNode::Stop(const int32_t streamId)
{
    CAMERA_LOGI("ForkNode::Stop streamId = %{public}d\n", streamId);

    if (!streamRunning_) {
        return RC_OK;
    }

    {
        std::unique_lock<std::mutex> l(bufferMtx);
        stopForkThread_ = true;
        bqcv_.notify_all();
        CAMERA_LOGD("ForkNode Stop streamId:%{public}d bqcv_:%{public}p this:%{public}p", &bqcv_, this, streamId);
    }

    if (forkThread_ != nullptr) {
        forkThread_->join();
        forkThread_ = nullptr;
    }

    if (bufferPool_ != nullptr) {
        DrainForkBufferPool();
    }

    streamRunning_ = false;

    return RC_OK;
}

RetCode ForkNode::Flush(const int32_t streamId)
{
    if (streamId_ == streamId) {
        DrainForkBufferPool();
    }

    return RC_OK;
}

static void CopyBufferToForkBuffer(std::shared_ptr<IBuffer>& buffer, std::shared_ptr<IBuffer>& forkBuffer)
{
    if (forkBuffer->GetVirAddress() == forkBuffer->GetSuffaceBufferAddr()) {
        CAMERA_LOGI("ForkNode::DeliverBuffer begin malloc buffer");
        uint32_t bufferSize = buffer->GetSize();
        if (bufferSize == 0) {
            CAMERA_LOGE("PcForkNode::DeliverBuffer error,  buffer->GetSize() == 0");
            return;
        }
        auto bufferAddr = malloc(bufferSize);
        if (bufferAddr != nullptr) {
            forkBuffer->SetVirAddress(bufferAddr);
            forkBuffer->SetSize(bufferSize);
        } else {
            CAMERA_LOGE("ForkNode::DeliverBuffer malloc buffer fail");
        }
    }
    if (forkBuffer->GetVirAddress() != forkBuffer->GetSuffaceBufferAddr()) {
        auto err = memcpy_s(forkBuffer->GetVirAddress(), forkBuffer->GetSize(),
            buffer->GetVirAddress(), buffer->GetSize());
        if (err != EOK) {
            CAMERA_LOGE("ForkNode::DeliverBuffer memcpy_s is fail");
        }
    }
}

void ForkNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("frameSpec is null");
        return;
    }
    CAMERA_LOGD("ForkNode forkBuffer streamId:%{public}d this:%{public}p start", buffer->GetStreamId(), this);
    if (buffer->GetBufferStatus() == CAMERA_BUFFER_STATUS_OK && bufferPool_ != nullptr) {
        std::shared_ptr<IBuffer> forkBuffer = bufferPool_->AcquireBuffer(0);
        if (forkBuffer != nullptr) {
            CopyBufferToForkBuffer(buffer, forkBuffer);
            forkBuffer->SetCurFormat(buffer->GetCurFormat());
            forkBuffer->SetCurWidth(buffer->GetCurWidth());
            forkBuffer->SetCurHeight(buffer->GetCurHeight());
            CAMERA_LOGI("ForkNode DeliverBuffer width:%{public}d height:%{public}d", buffer->GetCurWidth(), buffer->GetCurHeight());
            forkBuffer->SetIsValidDataInSurfaceBuffer(false);
            if (isDeliveryForkBufferInAloneThread_) {
                std::lock_guard<std::mutex> l(mtx_);
                bufferQueue_.push(forkBuffer);
                CAMERA_LOGI("fork node deliver buffer streamid = %{public}d, in alone thread, index = %{public}d",
                    forkBuffer->GetStreamId(), forkBuffer->GetIndex());
                bqcv_.notify_one();
                CAMERA_LOGD("ForkNode forkBuffer bqcv_:%{public}p this:%{public}p streamId:%{public}d",
                    &bqcv_, this, forkBuffer->GetStreamId());
            } else {
                CAMERA_LOGE("Deliver fork buffer, streamId[%{public}d], index[%{public}d], status = %{public}d",
                    forkBuffer->GetStreamId(), forkBuffer->GetIndex(), forkBuffer->GetBufferStatus());
                DeliverForkBuffer(forkBuffer);
            }
        }
    }
    return NodeBase::DeliverBuffer(buffer);
}

RetCode ForkNode::Capture(const int32_t streamId, const int32_t captureId)
{
    CAMERA_LOGD("ForkNode::received a request from stream [id:%{public}d], queue size:%{public}u",
        streamId, captureRequests_[streamId].size());

    for (auto& in : inPutPorts_) {
        CAMERA_LOGI("ForkNode::Capture in->format_.streamId_ = %{public}d", in->format_.streamId_);
        if (streamId == in->format_.streamId_) {
            return RC_OK;
        }
    }

    std::lock_guard<std::mutex> l(requestLock_);
    if (captureRequests_.count(streamId) == 0) {
        captureRequests_[streamId] = {captureId};
    } else {
        captureRequests_[streamId].emplace_back(captureId);
    }

    return RC_OK;
}

void ForkNode::DeliverForkBuffer(std::shared_ptr<IBuffer>& forkBuffer)
{
    int32_t id = forkBuffer->GetStreamId();
    CAMERA_LOGD("ForkNode DeliverBufferToNextNode streamId:%{public}d", id);
    {
        std::lock_guard<std::mutex> l(requestLock_);
        if (captureRequests_.count(id) == 0 || captureRequests_[id].empty()) {
            forkBuffer->SetBufferStatus(CAMERA_BUFFER_STATUS_INVALID);
        } else {
            forkBuffer->SetCaptureId(captureRequests_[id].front());
            captureRequests_[id].pop_front();
        }
    }
    NodeBase::DeliverBuffer(forkBuffer);
}

void ForkNode::DeliverBufferToNextNode()
{
    {
        std::unique_lock<std::mutex> l(bufferMtx);
        CAMERA_LOGD("ForkNode DeliverBufferToNextNode bqcv_:%{public}p this:%{public}p", &bqcv_, this);
        bqcv_.wait(l, [this] {
            CAMERA_LOGD("ForkNode DeliverBufferToNextNode stopForkThread_:%{public}d, bufferQueue_:%{public}d",
                stopForkThread_ ? 0 : 1, bufferQueue_.empty() ? 0 : 1);
            return stopForkThread_ || !bufferQueue_.empty();
        });
    }

    mtx_.lock();
    if (bufferQueue_.empty()) {
        mtx_.unlock();
        return;
    }
    std::shared_ptr<IBuffer> forkBuffer = bufferQueue_.front();
    bufferQueue_.pop();
    mtx_.unlock();
    DeliverForkBuffer(forkBuffer);
}

RetCode ForkNode::CancelCapture(const int32_t streamId)
{
    CAMERA_LOGI("ForkNode::CancelCapture streamid = %{public}d", streamId);

    return RC_OK;
}

void ForkNode::DrainForkBufferPool()
{
    // Drain all buffers from Buffer Pool to Stream Tunnel.
    if (bufferPool_ != nullptr) {
        std::shared_ptr<IBuffer> buffer = nullptr;

        while ((buffer = bufferPool_->AcquireBuffer(0)) != nullptr) {
            buffer->SetBufferStatus(CAMERA_BUFFER_STATUS_INVALID);

            for (auto& it : outPutPorts_) {
                if (it->format_.streamId_ == streamId_) {
                    it->DeliverBuffer(buffer);
                    break;
                }
            }
        }
    }
}
REGISTERNODE(ForkNode, {"fork"})
} // namespace OHOS::Camera
