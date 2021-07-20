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

#include "node_base.h"

namespace OHOS::Camera {
std::string PortBase::GetName() const
{
    return name_;
}

RetCode PortBase::SetFormat(const PortFormat& format)
{
    format_ = format;
    return RC_OK;
}

RetCode PortBase::GetFormat(PortFormat& format) const
{
    format = format_;
    return RC_OK;
}

RetCode PortBase::Connect(const std::shared_ptr<IPort>& peer)
{
    peer_ = peer;
    return RC_OK;
}

RetCode PortBase::DisConnect()
{
    peer_.reset();
    return RC_OK;
}

int32_t PortBase::Direction() const
{
    if (name_.empty()) {
        return 0;
    }

    if (name_[0] == 'i') {
        return 0;
    } else {
        return 1;
    }
}

std::shared_ptr<INode> PortBase::GetNode() const
{
    return owner_.lock();
}

std::shared_ptr<IPort> PortBase::Peer() const
{
    return peer_;
}

void PortBase::DeliverBuffer(std::shared_ptr<FrameSpec> frameSpec)
{
    Peer()->GetNode()->DeliverBuffers(frameSpec);
    return;
}

void PortBase::DeliverBuffers(std::vector<std::shared_ptr<FrameSpec>> mergeVec)
{
    Peer()->GetNode()->DeliverBuffers(mergeVec);
    return;
}

void PortBase::SetCaptureId(const int32_t captureId)
{
    captureId_ = captureId;
}

int32_t PortBase::GetCaptureId() const
{
    return captureId_.load();
}

std::string NodeBase::GetName() const
{
    return name_;
}

std::string NodeBase::GetType() const
{
    return type_;
}

int NodeBase::GetStreamId() const
{
    return streamId_;
}

void NodeBase::AchieveBuffer(std::shared_ptr<FrameSpec> frameSpec)
{
    CAMERA_LOGI("achieve buffer enter");
    if (frameSpec == nullptr) {
        CAMERA_LOGE("frame Spec is null");
        return;
    }
    {
        std::lock_guard<std::mutex> l(streamLock_);
        frameVec_.push_back(frameSpec);
        CAMERA_LOGI("AchieveBuffer : bufferpool id = %llu", frameSpec->bufferPoolId_);
    }

    return;
}

std::shared_ptr<IPort> NodeBase::GetPort(const std::string& name)
{
    auto it = std::find_if(portVec_.begin(), portVec_.end(),
        [name](std::shared_ptr<IPort> p) {
            return p->GetName() == name;
        });
    if (it != portVec_.end()) {
        return *it;
    }
    std::shared_ptr<IPort> port = std::make_shared<PortBase>(name, shared_from_this());
    portVec_.push_back(port);
    return port;
}

RetCode NodeBase::Init()
{
    return RC_OK;
}

RetCode NodeBase::Start()
{
    CAMERA_LOGI("name:%s start enter\n", name_.c_str());
    return RC_OK;
}

RetCode NodeBase::Stop()
{
    if (streamRunning_ == false) {
        CAMERA_LOGI("streamrunning is already false");
        return RC_OK;
    }
    streamRunning_ = false;
    if (collectThread_ != nullptr) {
        CAMERA_LOGI("collectThread need join");
        collectThread_->join();
        collectThread_ = nullptr;
    }

    for (auto& it : streamVec_) {
        if (it.deliverThread_ != nullptr) {
            CAMERA_LOGI("deliver thread need join");
            it.deliverThread_->join();
            delete it.deliverThread_;
            it.deliverThread_ = nullptr;
        }
    }
    return RC_OK;
}

RetCode NodeBase::Config()
{
    CAMERA_LOGI("name:%s config enter\n", name_.c_str());
    return RC_OK;
}

int32_t NodeBase::GetNumberOfInPorts() const
{
    int32_t re = 0;
    for (const auto& it : portVec_) {
        if (it->Direction() == 0) {
            re++;
        }
    }
    return re;
}

int32_t NodeBase::GetNumberOfOutPorts() const
{
    int32_t re = 0;
    for (const auto& it : portVec_) {
        if (it->Direction() == 1) {
            re++;
        }
    }
    return re;
}

std::vector<std::shared_ptr<IPort>> NodeBase::GetInPorts() const
{
    std::vector<std::shared_ptr<IPort>> re;
    for (const auto& it : portVec_) {
        if (it->Direction() == 0) {
            re.push_back(it);
        }
    }
    return re;
}

std::vector<std::shared_ptr<IPort>> NodeBase::GetOutPorts()
{
    CAMERA_LOGI("port num = %d", portVec_.size());
    for (const auto& it : portVec_) {
        if (it->Direction() == 1) {
            outPutPorts_.push_back(it);
        }
    }
    return outPutPorts_;
}

std::shared_ptr<IPort> NodeBase::GetOutPortById(const int32_t id)
{
    int32_t count = 0;
    auto ports = GetOutPorts();
    for (auto& it : ports) {
        if (count == id) {
            return it;
        }
        count++;
    }

    return nullptr;
}

RetCode NodeBase::GetDeviceManager()
{
    deviceManager_ = IDeviceManager::GetInstance();
    if (deviceManager_ == nullptr) {
        CAMERA_LOGE("get device manager failed.");
        return RC_ERROR;
    }
    return RC_OK;
}

void NodeBase::GetFrameInfo()
{
    StreamSpec streamSpec;
    int32_t portnum = GetNumberOfOutPorts();
    CAMERA_LOGI("portnum = %d ", portnum);
    if (bufferPoolIdVec_.size() >= portnum) {
        return;
    }
    for (auto& it : outPutPorts_) {
        streamSpec.bufferPoolId_ = it->format_.bufferPoolId_;
        streamSpec.deliverThread_ = nullptr;
        streamVec_.push_back(streamSpec);
        bufferPoolIdVec_.push_back(it->format_.bufferPoolId_);
        CAMERA_LOGI("get frameinfo bufferpool id = %llu ", streamSpec.bufferPoolId_);
    }
    return;
}

RetCode NodeBase::SetMetadata(std::shared_ptr<CameraStandard::CameraMetadata> meta)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is null");
        return RC_ERROR;
    }
    meta_ = meta;
    return RC_OK;
}


RetCode NodeBase::CollectBuffers()
{
    CAMERA_LOGI("collect buffers enter");
    collectThread_ = std::make_shared<std::thread>([this] {
        RetCode rc = RC_ERROR;
        BufferManager* bufferManager = Camera::BufferManager::GetInstance();
        int i = 0;
        std::shared_ptr<IPort> port = GetPort("out0");
        uint32_t bufferCount = port->format_.bufferCount_;
        while (streamRunning_ == true) {
            for (auto it : bufferPoolIdVec_) {
                std::shared_ptr<IBufferPool> bufferPool = bufferManager->GetBufferPool(it);
                if (bufferPool == nullptr) {
                    CAMERA_LOGE("get bufferpool failed, id = %llu", it);
                    return RC_ERROR;
                }
                std::shared_ptr<IBuffer> buffer = bufferPool->AcquireBuffer();
                if (buffer == nullptr) {
                    continue;
                }
                if (port->format_.bufferPoolId_ == it) {
                    bufferCount = port->format_.bufferCount_;
                } else {
                    port = GetPort("out1");
                    bufferCount = port->format_.bufferCount_;
                }

                UpdateCaptureId(buffer);
                std::shared_ptr<FrameSpec> frameSpec = std::make_shared<FrameSpec>();
                frameSpec->bufferPoolId_ = it;
                frameSpec->bufferCount_ = bufferCount;
                frameSpec->buffer_ = buffer;
                if (i < bufferCount) {
                    frameSpec->buffer_->SetIndex(i++);
                } else {
                    i = 0;
                    frameSpec->buffer_->SetIndex(i++);
                }
                rc = ProvideBuffers(frameSpec);
                CAMERA_LOGI("provide bffer:bufferpool id = %llu", frameSpec->bufferPoolId_);
                if (rc == RC_ERROR) {
                    CAMERA_LOGE("provide buffer failed.");
                } else {
                    // bufferNum_++;
                }
            }
        }
        CAMERA_LOGI("collect buffer thread closed");
        return RC_OK;
    });


    return RC_OK;
}

void NodeBase::DeliverBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    CAMERA_LOGI("deliver buffers enter");
    if (GetNumberOfOutPorts() == 0) {
        cb_(frameSpec->buffer_);
    }
    for (auto it : outPutPorts_) {
        if (it->format_.bufferPoolId_ == frameSpec->bufferPoolId_) {
            it->DeliverBuffer(frameSpec);
            return;
        }
    }
    return;
}

RetCode NodeBase::ProvideBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    CAMERA_LOGI("base node provideBuffers enter");
    return RC_OK;
}

RetCode NodeBase::Capture(const std::vector<int32_t>& streamIds, const int32_t captureId)
{
    // FIXME: replace streamIds by one streamId, and configure one port.
    for (auto streamId : streamIds) {
        CAMERA_LOGV("stream id = %d, capture id = %d", streamId, captureId);
        std::shared_ptr<IPort> port = nullptr;
        for (auto& it : outPutPorts_) {
            PortFormat f {};
            it->GetFormat(f);
            if (f.streamId_ == streamId) {
                port = it;
            }
            CAMERA_LOGI("acquire id = %d, port stream id = %d", streamId, f.streamId_);
        }
        if (port == nullptr) {
            return RC_OK;
        }
        port->SetCaptureId(captureId);
    }
    return RC_OK;
}

RetCode NodeBase::UpdateCaptureId(const std::shared_ptr<IBuffer>& buffer)
{
    auto poolId = buffer->GetPoolId();
    std::shared_ptr<IPort> port = nullptr;
    for (auto& it : outPutPorts_) {
        PortFormat f {};
        it->GetFormat(f);
        if (f.bufferPoolId_ == poolId) {
            port = it;
        }
    }
    if (port == nullptr) {
        return RC_OK;
    }
    buffer->SetCaptureId(port->GetCaptureId());

    return RC_OK;
}
} //namespace OHOS::Camera
