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

#include "v4l2_source_node.h"
#include <unistd.h>

namespace OHOS::Camera{
V4L2SourceNode::V4L2SourceNode(const std::string& name, const std::string& type)
    :V4L2SourceNode(name, type)
{
    CAMERA_LOGI("%s enter, type(%s)\n", name_.c_str(), type_.c_str());
}

RetCode V4L2SourceNode::GetDeviceController()
{
    CameraId cameraId = CAMERA_FIRST;
    sleep(2);
    sensorController_ = std::static_pointer_cast<SensorController>
        (deviceManager_->GetController(cameraId, DM_M_SENSOR, DM_C_SENSOR));
    if (sensorController_ == nullptr) {
        CAMERA_LOGE("get device controller failed");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode V4L2SourceNode::Init(const int32_t streamId)
{
    int32_t n = GetNumberOfOutPorts();
    for (int32_t i = 0; i < n; i++) {
        auto port = GetOutPortById(i);
        auto bufferCount = port->format_.bufferCount_;
        auto poolId = port->format_.bufferPoolId_;
        auto pool = BufferManager::GetInstance()->GetBufferPool(poolId);
        for (uint32_t count = 0; count < bufferCount; count++) {
            std::shared_ptr<IBuffer> buffer = pool->AcquireBuffer();
            std::shared_ptr<FrameSpec> frameSpec = std::make_shared<FrameSpec>();
            frameSpec->bufferPoolId_ = poolId;
            frameSpec->bufferCount_ = bufferCount;
            frameSpec->buffer_ = buffer;
            ProvideBuffers(frameSpec);
        }
    }
    return RC_OK;
}

RetCode V4L2SourceNode::Start(const int32_t streamId)
{
    RetCode rc = RC_OK;
    GetDeviceManager();
    rc = GetDeviceController();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("GetDeviceController failed.");
        return RC_ERROR;
    }
    GetOutPorts();
    for (auto& it : outPutPorts_) {
        DeviceFormat format;
        format.fmtdesc.pixelformat = V4L2_PIX_FMT_YUYV;
        format.fmtdesc.width = it->format_.w_;
        format.fmtdesc.height = it->format_.h_;
        int bufCnt = it->format_.bufferCount_;
        rc = sensorController_->Start(bufCnt, format);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("start failed.");
            return RC_ERROR;
        }
    }
    SendCallBack();
    GetFrameInfo();
    if (streamRunning_ == false) {
        CAMERA_LOGI("V4L2SourceNode streamrunning = false");
        streamRunning_ = true;
        CollectBuffers();
        DistributeBuffers();
    }
    return RC_OK;
}

V4L2SourceNode::~V4L2SourceNode()
{
    NodeBase::Stop();
    CAMERA_LOGI("~source Node exit.");
}

RetCode V4L2SourceNode::Flush(const int32_t streamId)
{
    return RC_OK;
}

RetCode V4L2SourceNode::Stop(const int32_t streamId)
{
    RetCode rc = RC_OK;
    rc = sensorController_->Stop();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("stopvi failed!");
        return RC_ERROR;
    }
    return NodeBase::Stop();
}

RetCode V4L2SourceNode::Configure(std::shared_ptr<CameraStandard::CameraMetadata> meta)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(meta, RC_ERROR);
    return sensorController_->Configure(meta);
}

void V4L2SourceNode::DistributeBuffers()
{
    CAMERA_LOGI("source node distribute buffers enter");
    for (auto& it : streamVec_) {
        CAMERA_LOGI("source node distribute thread bufferpool id = %llu", it.bufferPoolId_);
        it.deliverThread_ = new std::thread([this, it] {
            prctl(PR_SET_NAME, "source_node");
            std::shared_ptr<FrameSpec> f = nullptr;
            while (streamRunning_ == true) {
            {
                std::lock_guard<std::mutex> l(streamLock_);
                if (frameVec_.size() > 0) {
                    CAMERA_LOGI("distribute buffer Num = %d", frameVec_.size());
                    auto frameSpec = std::find_if(frameVec_.begin(), frameVec_.end(),
                        [it](std::shared_ptr<FrameSpec> fs) {
                            CAMERA_LOGI("source node port bufferPoolId = %llu, frame bufferPool Id = %llu",
                                it.bufferPoolId_, fs->bufferPoolId_);
                            return it.bufferPoolId_ == fs->bufferPoolId_;
                        });
                        if (frameSpec != frameVec_.end()) {
                            f = *frameSpec;
                            frameVec_.erase(frameSpec);
                        }
                }
            }
                if (f != nullptr) {
                    DeliverBuffers(f);
                    f = nullptr;
                    continue;
                }
                usleep(10);
            }
            CAMERA_LOGI("distribute buffer thread %llu  closed", it.bufferPoolId_);
            return;
        });
    }
    return;
}

void VpssNode::DeliverBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    CHECK_IF_PTR_NULL_RETURN_VOID(frameSpec);
    int32_t id = frameSpec->buffer_->GetStreamId();
    {
        std::lock_guard<std::mutex> l(requestLock_);
        if (captureRequests_.count(id) == 0) {
            frameSpec->buffer_->SetBufferStatus(CAMERA_BUFFER_STATUS_INVALID);
        } else if (captureRequests_[id].empty()) {
            frameSpec->buffer_->SetBufferStatus(CAMERA_BUFFER_STATUS_INVALID);
        } else {
            frameSpec->buffer_->SetCaptureId(captureRequests_[id].front());
            captureRequests_[id].pop_front();
        }
    }
    NodeBase::DeliverBuffers(frameSpec);
}

void V4L2SourceNode::AchieveBuffer(std::shared_ptr<FrameSpec> frameSpec)
{
    NodeBase::AchieveBuffer(frameSpec);
}

void V4L2SourceNode::SendCallBack()
{
    sensorController_->SetNodeCallBack([&](std::shared_ptr<FrameSpec> frameSpec) {
        AchieveBuffer(frameSpec);
    });
    return;
}

RetCode V4L2SourceNode::ProvideBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    CAMERA_LOGI("provide buffers enter.");
    if (sensorController_->SendFrameBuffer(frameSpec) == RC_OK) {
        CAMERA_LOGI("sendframebuffer success bufferpool id = %llu", frameSpec->bufferPoolId_);
        return RC_OK;
    }
    return RC_ERROR;
}
REGISTERNODE(V4L2SourceNode, {"v4l2_source"})
} // namespace OHOS::Camera
