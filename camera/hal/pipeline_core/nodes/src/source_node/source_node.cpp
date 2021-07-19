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

#include "source_node.h"
#include <unistd.h>

namespace OHOS::Camera{
SourceNode::SourceNode(const std::string& name, const std::string& type, const int streamId)
    :NodeBase(name, type, streamId)
{
    CAMERA_LOGI("%s enter, type(%s), stream id = %d\n", name_.c_str(), type_.c_str(), streamId);
}

RetCode SourceNode::GetDeviceController()
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

RetCode SourceNode::Start()
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
        CAMERA_LOGI("SourceNode streamrunning = false");
        streamRunning_ = true;
        CollectBuffers();
        DistributeBuffers();
    }
    return RC_OK;
}

SourceNode::~SourceNode()
{
    NodeBase::Stop();
    CAMERA_LOGI("~source Node exit.");
}

RetCode SourceNode::Stop()
{
    RetCode rc = RC_OK;
    rc = sensorController_->Stop();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("stopvi failed!");
        return RC_ERROR;
    }
    return NodeBase::Stop();
}
RetCode SourceNode::Configure(std::shared_ptr<CameraStandard::CameraMetadata> meta)
{
    RetCode rc = RC_OK;
    IS_NULLPTR(meta)
    rc = sensorController_->Configure(meta);
    IS_ERROR(rc)
    return rc;
}

void SourceNode::DistributeBuffers()
{
    CAMERA_LOGI("source node distribute buffers enter");
    for (auto& it : streamVec_) {
        CAMERA_LOGI("source node distribute thread bufferpool id = %llu", it.bufferPoolId_);
        it.deliverThread_ = new std::thread([this, it] {
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
                            bufferNum_--;
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

void SourceNode::AchieveBuffer(std::shared_ptr<FrameSpec> frameSpec)
{
    NodeBase::AchieveBuffer(frameSpec);
}

void SourceNode::SendCallBack()
{
    sensorController_->SetNodeCallBack([&](std::shared_ptr<FrameSpec> frameSpec) {
        AchieveBuffer(frameSpec);
    });
    return;
}

RetCode SourceNode::ProvideBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    CAMERA_LOGI("provide buffers enter.");
    if (sensorController_->SendFrameBuffer(frameSpec) == RC_OK) {
        CAMERA_LOGI("sendframebuffer success bufferpool id = %llu", frameSpec->bufferPoolId_);
        return RC_OK;
    }
    return RC_ERROR;
}
REGISTERNODE(SourceNode, {"source"})
} // namespace OHOS::Camera
