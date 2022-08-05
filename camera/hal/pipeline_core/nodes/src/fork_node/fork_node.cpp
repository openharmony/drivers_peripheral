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

namespace OHOS::Camera {
ForkNode::ForkNode(const std::string& name, const std::string& type) : NodeBase(name, type)
{
    CAMERA_LOGV("%{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
}

ForkNode::~ForkNode()
{
    StopForkThread();
}

RetCode ForkNode::Start(const int32_t streamId)
{
    int32_t id = 0;
    uint64_t bufferPoolId = 0;

    CAMERA_LOGI("ForkNode::Start streamId = %{public}d\n", streamId);

    if (streamRunning_) {
        return RC_OK;
    }

    inPutPorts_ = GetInPorts();
    outPutPorts_ = GetOutPorts();

    for (auto& in : inPutPorts_) {
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

    streamId_ = id;
    RunForkThread();
    streamRunning_ = true;

    return RC_OK;
}

RetCode ForkNode::Stop(const int32_t streamId)
{
    CAMERA_LOGI("ForkNode::Stop streamId = %{public}d\n", streamId);

    if (!streamRunning_) {
        return RC_OK;
    }

    StopForkThread();
    DrainForkBufferPool();

    streamRunning_ = false;

    return RC_OK;
}

RetCode ForkNode::Flush(const int32_t streamId)
{
    if (streamId_ == streamId) {
        StopForkThread();
        DrainForkBufferPool();
    }

    return RC_OK;
}

void ForkNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("frameSpec is null");
        return;
    }

    if (buffer->GetBufferStatus() == CAMERA_BUFFER_STATUS_OK && bufferPool_ != nullptr) {
        std::unique_lock <std::mutex> lck(mtx_);
        // If previous pending buffer was not handled, do not replace it.
        if (pendingBuffer_ == nullptr) {
            pendingBuffer_ = bufferPool_->AcquireBuffer(0);
            if (pendingBuffer_ != nullptr) {
                if (memcpy_s(pendingBuffer_->GetVirAddress(), pendingBuffer_->GetSize(),
                    buffer->GetVirAddress(), buffer->GetSize()) != 0) {
                    pendingBuffer_->SetBufferStatus(CAMERA_BUFFER_STATUS_INVALID);
                    CAMERA_LOGE("memcpy_s failed.");
                }
                cv_.notify_all();
            }
        }
    }

    int32_t id = buffer->GetStreamId();
    for (auto& it : outPutPorts_) {
        if (it->format_.streamId_ == id) {
            it->DeliverBuffer(buffer);
            CAMERA_LOGI("fork node deliver buffer streamid = %{public}d", it->format_.streamId_);
            return;
        }
    }
}

RetCode ForkNode::Capture(const int32_t streamId, const int32_t captureId)
{
    CAMERA_LOGV("ForkNode::received a request from stream [id:%{public}d], queue size:%{public}u",
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

RetCode ForkNode::CancelCapture(const int32_t streamId)
{
    CAMERA_LOGI("ForkNode::CancelCapture streamid = %{public}d", streamId);
    cv_.notify_all();

    return RC_OK;
}

void ForkNode::RunForkThread()
{
    if (forkThread_ != nullptr) {
        CAMERA_LOGI("Fork thread is running.");
        return;
    }

    forkThreadRunFlag_ = true;

    forkThread_ = std::make_shared<std::thread>([this] {
        prctl(PR_SET_NAME, "deliver_fork_buffers");
        std::shared_ptr<IBuffer> buffer = nullptr;
        int32_t id = streamId_;

        while (true) {
            {
                std::unique_lock <std::mutex> lck(mtx_);
                // Break the loop when stream was stopped and there was no pending buffer.
                if (!forkThreadRunFlag_ && (pendingBuffer_ == nullptr)) {
                    break;
                }

                if (pendingBuffer_ == nullptr) {
                    cv_.wait(lck);
                    continue; // rewind to the front of loop to check breaking condition.
                }
                // go ahead to deliver buffer.
                buffer = pendingBuffer_;
                pendingBuffer_ = nullptr;
            }

            for (auto& it : outPutPorts_) {
                if (it->format_.streamId_ == id) {
                    CAMERA_LOGI("fork node deliver buffer streamid = %{public}d begin", it->format_.streamId_);

                    int32_t id = buffer->GetStreamId();
                    {
                        std::lock_guard<std::mutex> l(requestLock_);
                        CAMERA_LOGV("ForkNode::deliver a buffer to stream id:%{public}d, queue size:%{public}u",
                            id, captureRequests_[id].size());
                        if (captureRequests_.count(id) == 0 || captureRequests_[id].empty()) {
                            buffer->SetBufferStatus(CAMERA_BUFFER_STATUS_INVALID);
                        } else {
                            buffer->SetCaptureId(captureRequests_[id].front());
                            captureRequests_[id].pop_front();
                        }
                    }
                    it->DeliverBuffer(buffer);
                    break;
                }
            }
        }
        CAMERA_LOGI("ForkNode RunForkThread closed");
        return RC_OK;
    });
    return;
}

void ForkNode::StopForkThread()
{
    if (forkThread_ != nullptr) {
        std::unique_lock <std::mutex> lck(mtx_);
        forkThreadRunFlag_ = false;
        cv_.notify_all();
        forkThread_->join();
        forkThread_ = nullptr;
    }
    CAMERA_LOGI("ForkNode::StopForkThread exit");
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
