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
#include "codec_node.h"

namespace OHOS::Camera {
PcForkNode::PcForkNode(const std::string& name, const std::string& type, const std::string &cameraId)
    : NodeBase(name, type, cameraId)
{
    CAMERA_LOGV("%{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
}

PcForkNode::~PcForkNode()
{
}

RetCode PcForkNode::Start(const int32_t streamId)
{
    int32_t id = 0;
    uint64_t bufferPoolId = 0;

    CAMERA_LOGI("PcForkNode::Start streamId = %{public}d\n", streamId);

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

    streamId_ = id;
    streamRunning_ = true;

    return RC_OK;
}

RetCode PcForkNode::Stop(const int32_t streamId)
{
    CAMERA_LOGI("PcForkNode::Stop streamId = %{public}d\n", streamId);

    if (!streamRunning_) {
        return RC_OK;
    }

    DrainForkBufferPool();

    streamRunning_ = false;

    return RC_OK;
}

RetCode PcForkNode::Flush(const int32_t streamId)
{
    if (streamId_ == streamId) {
        DrainForkBufferPool();
    }

    return RC_OK;
}

void PcForkNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("frameSpec is null");
        return;
    }

    if (buffer->GetBufferStatus() == CAMERA_BUFFER_STATUS_OK && bufferPool_ != nullptr) {
        std::shared_ptr<IBuffer> forkBuffer = bufferPool_->AcquireBuffer(0);
        if (forkBuffer != nullptr) {
            if (forkBuffer->GetEncodeType() == ENCODE_TYPE_H264 &&
                forkBuffer->GetFormat() == CAMERA_FORMAT_YCRCB_420_SP) {
                CodecNode::Yuv422ToYuv420(buffer, forkBuffer);
            } else if (memcpy_s(forkBuffer->GetVirAddress(), forkBuffer->GetSize(),
                buffer->GetVirAddress(), buffer->GetSize()) != 0) {
                forkBuffer->SetBufferStatus(CAMERA_BUFFER_STATUS_INVALID);
                CAMERA_LOGW("PcForkNode::memcpy_s failed.");
            }
            for (auto& it : outPutPorts_) {
                if (it->format_.streamId_ != streamId_) {
                    continue;
                }
                CAMERA_LOGI("deliver fork buffer for streamid = %{public}d", it->format_.streamId_);
                int32_t id = forkBuffer->GetStreamId();
                {
                    std::lock_guard<std::mutex> l(requestLock_);
                    CAMERA_LOGV("deliver a fork buffer of stream id:%{public}d, queue size:%{public}u",
                        id, captureRequests_[id].size());
                    if (captureRequests_.count(id) == 0 || captureRequests_[id].empty()) {
                        forkBuffer->SetBufferStatus(CAMERA_BUFFER_STATUS_INVALID);
                    } else {
                        forkBuffer->SetCaptureId(captureRequests_[id].front());
                        captureRequests_[id].pop_front();
                    }
                }
                it->DeliverBuffer(forkBuffer);
                break;
            }
        }
    }

    for (auto& it : outPutPorts_) {
        if (it->format_.streamId_ == buffer->GetStreamId()) {
            it->DeliverBuffer(buffer);
            CAMERA_LOGI("fork node deliver buffer streamid = %{public}d", it->format_.streamId_);
            return;
        }
    }
}

RetCode PcForkNode::Capture(const int32_t streamId, const int32_t captureId)
{
    CAMERA_LOGV("PcForkNode::received a request from stream [id:%{public}d], queue size:%{public}u",
        streamId, captureRequests_[streamId].size());

    for (auto& in : inPutPorts_) {
        CAMERA_LOGI("PcForkNode::Capture in->format_.streamId_ = %{public}d", in->format_.streamId_);
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

RetCode PcForkNode::CancelCapture(const int32_t streamId)
{
    CAMERA_LOGI("PcForkNode::CancelCapture streamid = %{public}d", streamId);

    return RC_OK;
}

void PcForkNode::DrainForkBufferPool()
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
REGISTERNODE(PcForkNode, {"fork"})
} // namespace OHOS::Camera
