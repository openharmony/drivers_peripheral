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
ForkNode::ForkNode(const std::string& name, const std::string& type, const int streamId)
        :NodeBase(name, type, streamId)
{
    CAMERA_LOGI("%s enter, type(%s), stream id = %d\n", name_.c_str(), type_.c_str(), streamId);
}

ForkNode::~ForkNode()
{
    streamRunning_ = false;
    cv_.notify_all();
    if (forkThread_ != nullptr) {
        CAMERA_LOGI("forkThread need join");
        forkThread_->join();
        forkThread_ = nullptr;
    }
    CAMERA_LOGI("fork Node exit.");
}

RetCode ForkNode::Start()
{
    inPutPorts_ = GetInPorts();
    GetOutPorts();
    GetFrameInfo();
    if (streamRunning_ == false) {
        CAMERA_LOGI("streamrunning = false");
        streamRunning_ = true;
        ForkBuffers();
    }
    return RC_OK;
}

RetCode ForkNode::Stop()
{
    streamRunning_ = false;
    cv_.notify_all();
    if (forkThread_ != nullptr) {
        CAMERA_LOGI("forkThread need join");
        forkThread_->join();
        forkThread_ = nullptr;
    }
    return RC_OK;
}

void ForkNode::DeliverBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    if (frameSpec == nullptr) {
        CAMERA_LOGE("frameSpec is null");
        return;
    }
    std::unique_lock <std::mutex> lck(mtx_);
    forkSpec_ = frameSpec;
    cv_.notify_one();
    for (auto& it : outPutPorts_) {
        if (it->format_.bufferPoolId_ == frameSpec->bufferPoolId_) {
            it->DeliverBuffer(frameSpec);
            CAMERA_LOGI("fork node deliver bufferpoolid = %llu",it->format_.bufferPoolId_);
            return;
         }
    }
}

void ForkNode::ForkBuffers()
{
    int64_t bufferPoolId = 0;
    for (auto& in : inPutPorts_) {
        for (auto& out : outPutPorts_) {
            if (out->format_.bufferPoolId_ != in->format_.bufferPoolId_) {
                bufferPoolId = out->format_.bufferPoolId_;
                CAMERA_LOGI("fork buffer get bufferpoolid = %llu",out->format_.bufferPoolId_);
            }
        }
    }
    forkThread_ = std::make_shared<std::thread>([this, bufferPoolId] {
        prctl(PR_SET_NAME, "fork_buffers");
        BufferManager* bufferManager = Camera::BufferManager::GetInstance();
        std::shared_ptr<FrameSpec> frameSpec = std::make_shared<FrameSpec>();
        while (streamRunning_ == true) {
            std::unique_lock <std::mutex> lck(mtx_);
            cv_.wait(lck);
            std::shared_ptr<IBufferPool> bufferPool = bufferManager->GetBufferPool(bufferPoolId);
            if (bufferPool == nullptr) {
                CAMERA_LOGE("get bufferpool failed");
                return RC_ERROR;
            }
            CAMERA_LOGI("fork node acquirebuffer enter");
            std::shared_ptr<IBuffer> buffer = bufferPool->AcquireBuffer();
            CAMERA_LOGI("fork node acquirebuffer exit");
            if (buffer == nullptr) {
                CAMERA_LOGE("acquire buffer failed.");
                continue;
            }
            memcpy_s(buffer->GetVirAddress(), buffer->GetSize(), forkSpec_->buffer_->GetVirAddress(),
                    forkSpec_->buffer_->GetSize());
            frameSpec->bufferPoolId_ = bufferPoolId;
            frameSpec->buffer_ = buffer;
            for (auto& it : outPutPorts_) {
                if (it->format_.bufferPoolId_ == frameSpec->bufferPoolId_) {
                    CAMERA_LOGI("fork node deliver bufferpoolid = %llu",it->format_.bufferPoolId_);
                    it->DeliverBuffer(frameSpec);
                    break;
                }
            }
        }
        CAMERA_LOGI("fork thread closed");
        return RC_OK;
    });
    return;
}
REGISTERNODE(ForkNode, {"fork"})
} // namespace OHOS::Camera
