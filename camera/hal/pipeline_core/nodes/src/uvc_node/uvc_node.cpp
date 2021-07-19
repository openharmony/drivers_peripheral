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

#include "uvc_node.h"
#include <unistd.h>

namespace OHOS::Camera {
UvcNode::UvcNode(const std::string& name, const std::string& type, const int streamId)
        :NodeBase(name, type, streamId)
{
    CAMERA_LOGI("%s enter, type(%s), stream id = %d\n", name_.c_str(), type_.c_str(), streamId);
}

UvcNode::~UvcNode()
{
    NodeBase::Stop();
    CAMERA_LOGI("~uvc Node exit.");
}


RetCode UvcNode::GetDeviceController()
{
    CameraId cameraId = CAMERA_THIRD;
    sleep(2);
    sensorController_ = std::static_pointer_cast<SensorController>
        (deviceManager_->GetController(cameraId, DM_M_SENSOR, DM_C_SENSOR));
    if (sensorController_ == nullptr) {
        CAMERA_LOGE("get device controller failed");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode UvcNode::StartCheck(int64_t &bufferPoolId)
{
    GetDeviceManager();
    if (GetDeviceController() == RC_ERROR) {
        CAMERA_LOGE("GetDeviceController failed.");
        return RC_ERROR;
    }

    BufferManager* manager = Camera::BufferManager::GetInstance();
    if (manager == nullptr) {
        CAMERA_LOGE("buffer manager is null");
    }
    bufferPoolId = manager->GenerateBufferPoolId();
    if (bufferPoolId == 0) {
        CAMERA_LOGE("bufferpool id is 0");
    }
    bufferPool_ = manager->GetBufferPool(bufferPoolId);
    if (bufferPool_ == nullptr) {
        CAMERA_LOGE("bufferpool is null ");
    }
    GetOutPorts();
    return RC_OK;
}

RetCode UvcNode::Start()
{
    int64_t bufferPoolId;
    if (StartCheck(bufferPoolId) == RC_ERROR) {
        return RC_ERROR;
    }
    for (auto& iter : outPutPorts_) {
        RetCode ret = bufferPool_->Init(iter->format_.w_,
            iter->format_.h_,
            iter->format_.usage_,
            iter->format_.format_,
            iter->format_.bufferCount_,
            CAMERA_BUFFER_SOURCE_TYPE_HEAP);
        if (ret == RC_ERROR) {
            CAMERA_LOGE("bufferpool init failed");
            break;
        }
        iter->format_.bufferPoolId_ = bufferPoolId;

        DeviceFormat format;
        format.fmtdesc.pixelformat = V4L2_PIX_FMT_YUYV;
        format.fmtdesc.width = iter->format_.w_;
        format.fmtdesc.height = iter->format_.h_;
        int bufCnt = iter->format_.bufferCount_;
        ret = sensorController_->Start(bufCnt, format);
        if (ret == RC_ERROR) {
            CAMERA_LOGE("start failed.");
            return RC_ERROR;
        }
    }
    GetFrameInfo();
    SendCallBack();
    if (streamRunning_ == false) {
        CAMERA_LOGI("streamrunning = false");
        streamRunning_ = true;
        CollectBuffers();
        DistributeBuffers();
    }
    return RC_OK;
}

RetCode UvcNode::Stop()
{
    RetCode rc = RC_OK;
    rc = sensorController_->Stop();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("stopvi failed!");
        return RC_ERROR;
    }
    return NodeBase::Stop();
}

RetCode UvcNode::Configure(std::shared_ptr<CameraStandard::CameraMetadata> meta)
{
    RetCode rc = RC_OK;
    IS_NULLPTR(meta)
    rc = sensorController_->Configure(meta);
    IS_ERROR(rc)
    return rc;
}

void UvcNode::DistributeBuffers()
{
    CAMERA_LOGI("uvc node distribute buffers enter");
    for (auto& it : streamVec_) {
        CAMERA_LOGI("uvc node distribute thread bufferpool id = %{public}llu", it.bufferPoolId_);
        it.deliverThread_ = new std::thread([this, it] {
            std::shared_ptr<FrameSpec> frame = nullptr;
            while (streamRunning_ == true) {
            {
                std::lock_guard<std::mutex> l(streamLock_);
                if (frameVec_.size() > 0) {
                    auto frameSpec = std::find_if(frameVec_.begin(), frameVec_.end(),
                    [it](std::shared_ptr<FrameSpec> fs) {
                        return it.bufferPoolId_ == fs->bufferPoolId_;
                    });
                    if (frameSpec != frameVec_.end()) {
                        frame = *frameSpec;
                        frameVec_.erase(frameSpec);
                        bufferNum_--;
                    }
                }
            }
                if (frame != nullptr) {
                    DeliverBuffers(frame);
                    frame = nullptr;
                    continue;
                }
                usleep(10);
            }
            CAMERA_LOGI("uvc node distribute buffer thread %llu  closed", it.bufferPoolId_);
            return;
        });
    }
    return;
}

void UvcNode::AchieveBuffer(std::shared_ptr<FrameSpec> frameSpec)
{
    NodeBase::AchieveBuffer(frameSpec);
}

void UvcNode::SendCallBack()
{
    sensorController_->SetNodeCallBack([&](std::shared_ptr<FrameSpec> frameSpec) {
            AchieveBuffer(frameSpec);
            });
    return;
}

RetCode UvcNode::ProvideBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    CAMERA_LOGI("provide buffers enter.");
    if (sensorController_->SendFrameBuffer(frameSpec) == RC_OK) {
        CAMERA_LOGD("sendframebuffer success bufferpool id = %{public}llu", frameSpec->bufferPoolId_);
        return RC_OK;
    }
    return RC_ERROR;
}
REGISTERNODE(UvcNode, {"uvc"})
} // namespace OHOS::Camera
