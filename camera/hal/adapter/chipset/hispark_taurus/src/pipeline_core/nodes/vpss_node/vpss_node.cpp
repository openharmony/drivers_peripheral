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

#include "vpss_node.h"
#include <unistd.h>

namespace OHOS::Camera{
VpssNode::VpssNode(const std::string& name, const std::string& type, const int streamId)
        :MpiNode(name, type, streamId)
{
    CAMERA_LOGI("%s enter, type(%s), stream id = %d\n", name_.c_str(), type_.c_str(), streamId);
}

VpssNode::~VpssNode()
{
    NodeBase::Stop();
    CAMERA_LOGI("~Vpss Node exit.");
}

RetCode VpssNode::GetDeviceController()
{
    GetMpiDeviceManager();
    vpssController_ = std::static_pointer_cast<VpssController>
        ((std::static_pointer_cast<VpssManager>(deviceManager_->GetManager(DM_M_VPSS)))->GetController(DM_C_VPSS));
    if (vpssController_ == nullptr) {
        CAMERA_LOGE("get device controller failed");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode VpssNode::Start()
{
    RetCode rc = RC_OK;
    rc = GetDeviceController();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("GetDeviceController failed.");
        return RC_ERROR;
    }
    rc = vpssController_->ConfigVpss();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("configvpss failed.");
        return RC_ERROR;
    }
    rc = vpssController_->StartVpss();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("startvpss failed.");
        return RC_ERROR;
    }
    CAMERA_LOGI("%s, beign to connect", __FUNCTION__);
    rc = ConnectMpi();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("startvpss failed.");
        return RC_ERROR;
    }
    SendCallBack();
    GetFrameInfo();
    if (streamRunning_ == false) {
        CAMERA_LOGI("streamrunning = false");
        streamRunning_ = true;
        CollectBuffers();
        DistributeBuffers();
    }
    return RC_OK;
}

RetCode VpssNode::Stop()
{
    RetCode rc = RC_OK;
    if (streamRunning_ == false) {
        CAMERA_LOGI("vpss node : streamrunning is already false");
        return RC_OK;
    }
    streamRunning_ = false;
    rc = DisConnectMpi();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("DisConnectMpi failed!");
        return RC_ERROR;
    }
    rc = vpssController_->StopVpss();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("stopvpss failed!");
        return RC_ERROR;
    }

    BufferManager* bufferManager = Camera::BufferManager::GetInstance();
    for (auto it : bufferPoolIdVec_) {
        std::shared_ptr<IBufferPool> bufferPool = bufferManager->GetBufferPool(it);
        bufferPool->NotifyStop(true);
    }
    cv_.notify_all();

    for (auto& itr : streamVec_) {
        if (itr.collectThread_ != nullptr) {
            CAMERA_LOGI("VpssNode::Stop collectThread need join");
            itr.collectThread_->join();
            delete itr.collectThread_;
            itr.collectThread_ = nullptr;
        }
        if (itr.deliverThread_ != nullptr) {
            CAMERA_LOGI("deliver thread need join");
            itr.deliverThread_->join();
            delete itr.deliverThread_;
            itr.deliverThread_ = nullptr;
        }
    }

    return RC_OK;
}

void VpssNode::DistributeBuffers()
{
    CAMERA_LOGI("distribute buffers enter");
    for (auto& it : streamVec_) {
        it.deliverThread_ = new std::thread([this, it] {
        prctl(PR_SET_NAME, "distribute_buff");
            std::shared_ptr<FrameSpec> fms = nullptr;
            while (streamRunning_ == true) {
                {
                    std::lock_guard<std::mutex> l(streamLock_);
                    if (buffer_.count(it.bufferPoolId_) > 0) {
                        CAMERA_LOGI("distribute buffer Num = %d", frameVec_.size());
                        for (auto& frameSpec : buffer_[it.bufferPoolId_]) {
                            fms = frameSpec;
                            buffer_[it.bufferPoolId_].pop_front();
                            break;
                        }
                    }
                }
                if (fms != nullptr) {
                    CAMERA_LOGI("vpss node distribute buffer: bufferPool Id = %llu",it.bufferPoolId_);
                    DeliverBuffers(fms);
                    fms = nullptr;
                } else {
                    std::unique_lock <std::mutex> lck(mtx_);
                    cv_.wait(lck);
                }
            }
            CAMERA_LOGI("distribute buffer thread %llu  closed", it.bufferPoolId_);
            return;
        });
    }
    return;
}

void VpssNode::AchieveBuffer(std::shared_ptr<FrameSpec> frameSpec)
{
    if (frameSpec == nullptr) {
        CAMERA_LOGE("frame Spec is null");
        return;
    }
    {
        std::lock_guard<std::mutex> l(streamLock_);
        buffer_[frameSpec->bufferPoolId_].push_back(frameSpec);
        CAMERA_LOGI("AchieveBuffer : bufferpool id = %llu", frameSpec->bufferPoolId_);
    }
    std::unique_lock <std::mutex> lck(mtx_);
    cv_.notify_all();
}

void VpssNode::SendCallBack()
{
    deviceManager_->SetNodeCallBack([&](std::shared_ptr<FrameSpec> frameSpec) {
            AchieveBuffer(frameSpec);
            });
    return;
}

RetCode VpssNode::ProvideBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    std::shared_ptr<IDeviceManager> deviceManager = IDeviceManager::GetInstance();
    CAMERA_LOGI("%s, ready to send frame buffer, bufferpool id = %llu", __FUNCTION__, frameSpec->bufferPoolId_);
    if (deviceManager->SendFrameBuffer(frameSpec) == RC_OK) {
        CAMERA_LOGI("%s, send frame buffer success, bufferpool id = %llu", __FUNCTION__, frameSpec->bufferPoolId_);
        return RC_OK;
    }
    CAMERA_LOGE("provide buffer failed.");
    return RC_ERROR;
}

REGISTERNODE(VpssNode, {"vpss"})
} // namespace OHOS::Camera
