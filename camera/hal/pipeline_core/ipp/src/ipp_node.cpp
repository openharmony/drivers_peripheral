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

#include "ipp_node.h"

namespace OHOS::Camera {
IppNode::IppNode(const std::string& name, const std::string& type, const int streamId)
        :NodeBase(name, type, streamId) {}
IppNode::~IppNode() {}
RetCode IppNode::Init()
{
    // initialize algo plugin
    if (offlineMode_.load()) {
        return RC_OK;
    }
    algoPluginManager_ = std::make_shared<AlgoPluginManager>();
    if (algoPluginManager_ == nullptr) {
        CAMERA_LOGE("create AlgoPluginManager failed");
        return RC_ERROR;
    }
    RetCode ret = algoPluginManager_->LoadPlugin();
    if (ret != RC_OK) {
        CAMERA_LOGE("load plugin failed.");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode IppNode::Start()
{
    // start offline stream process thread
    if (offlineMode_.load()) {
        return RC_OK;
    }
    algoPlugin_ = algoPluginManager_->GetAlgoPlugin(IPP_ALGO_MODE_NORMAL);
    NodeBase::Start();
    StartProcess();
    streamRunning_ = true;
    return RC_OK;
}

RetCode IppNode::Stop()
{
    // stop offline stream process thread
    if (offlineMode_.load()) {
        return RC_OK;
    }
    if (streamRunning_ == false) {
        return RC_OK;
    }
    streamRunning_ = false;
    algoPlugin_->Flush();
    algoPlugin_->Stop();

    StopProcess();
    NodeBase::Stop();
    return RC_OK;
}

RetCode IppNode::Configure(std::shared_ptr<CameraStandard::CameraMetadata> meta)
{
    // configure algo
    // NodeBase::Configure
    if (offlineMode_.load()) {
        return RC_OK;
    }

    return RC_OK;
}

void IppNode::DeliverBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    std::vector<std::shared_ptr<IBuffer>> cache;
    cache.emplace_back(frameSpec->buffer_);

    ReceiveCache(cache);
    return;
}

void IppNode::DeliverBuffers(std::vector<std::shared_ptr<FrameSpec>> buffers)
{
    std::vector<std::shared_ptr<IBuffer>> cache;
    for (auto it : buffers) {
        cache.emplace_back(it->buffer_);
    }

    ReceiveCache(cache);
    return;
}

void IppNode::ProcessCache(std::vector<std::shared_ptr<IBuffer>>& buffers)
{
    // process buffers with algorithm
    std::shared_ptr<IBuffer> outBuffer = nullptr;
    RetCode ret = GetOutputBuffer(buffers, outBuffer);
    if (ret != RC_OK) {
        CAMERA_LOGE("fatal error, can't get output buffer, ipp will do nothing.");
        return;
    }
    std::shared_ptr<CameraStandard::CameraMetadata> meta = nullptr;
    if (algoPlugin_ != nullptr) {
        CAMERA_LOGV("process buffers with algo, input buffer count = %u.", buffers.size());
        algoPlugin_->Process(outBuffer, buffers, meta);
    }

    std::shared_ptr<IBuffer> algoProduct = nullptr;
    std::vector<std::shared_ptr<IBuffer> > recycleBuffers {
    };
    ClassifyOutputBuffer(outBuffer, buffers, algoProduct, recycleBuffers);

    DeliverAlgoProductBuffer(algoProduct);
    DeliverCache(recycleBuffers);
    CAMERA_LOGV("process algo completed.");
    return;
}

void IppNode::DeliverCache(std::vector<std::shared_ptr<IBuffer>>& buffers)
{
    OfflinePipeline::DeliverCacheCheck(buffers);
}

void IppNode::DeliverCancelCache(std::vector<std::shared_ptr<IBuffer>>& buffers)
{
    std::shared_ptr<IBuffer> outBuffer = nullptr;
    RetCode ret = GetOutputBuffer(buffers, outBuffer);
    if (ret != RC_OK) {
        CAMERA_LOGE("fatal error, can't return buffer.");
        return;
    }

    std::shared_ptr<IBuffer> algoProduct = nullptr;
    std::vector<std::shared_ptr<IBuffer> > recycleBuffers {
    };
    ClassifyOutputBuffer(outBuffer, buffers, algoProduct, recycleBuffers);
    if (algoProduct == nullptr) {
        return;
    }
    algoProduct->SetValidFlag(false);
    DeliverAlgoProductBuffer(algoProduct);
    DeliverCache(recycleBuffers);

    return;
}

RetCode IppNode::GetOutputBuffer(std::vector<std::shared_ptr<IBuffer>>& buffers, std::shared_ptr<IBuffer>& outBuffer)
{
    auto outPort = GetOutPortById(0);
    if (outPort == nullptr) {
        CAMERA_LOGE("fatal error, can't get out port.");
        return RC_ERROR;
    }

    PortFormat format {
    };
    outPort->GetFormat(format);
    auto id = format.bufferPoolId_;
    for (auto it : buffers) {
        if (id == it->GetPoolId()) {
            outBuffer = nullptr;
            return RC_OK;
        }
    }

    auto bufferManager = BufferManager::GetInstance();
    if (bufferManager == nullptr) {
        CAMERA_LOGE("fatal error, can't get buffer manager.");
        return RC_ERROR;
    }
    auto bufferPool = bufferManager->GetBufferPool(id);
    if (bufferPool == nullptr) {
        CAMERA_LOGE("fatal error, can't get buffer pool.");
        return RC_ERROR;
    }

    outBuffer = bufferPool->AcquireBuffer(-1);

    return RC_OK;
}

void IppNode::DeliverAlgoProductBuffer(std::shared_ptr<IBuffer>& result)
{
    if (offlineMode_.load()) {
        CAMERA_LOGV("deliver buffer to offline stream");
        DeliverOfflineBuffer(result);
    } else {
        std::shared_ptr<IPort> outPort = GetOutPortById(0);
        if (outPort == nullptr) {
            CAMERA_LOGE("can't find out port, deliver algo product failed.");
            return;
        }
        std::shared_ptr<FrameSpec> spec = std::make_shared<FrameSpec>();
        spec->bufferPoolId_ = result->GetPoolId();
        spec->buffer_ = result;
        outPort->DeliverBuffer(spec);
    }

    return;
}

void IppNode::ClassifyOutputBuffer(std::shared_ptr<IBuffer>& outBuffer,
                                   std::vector<std::shared_ptr<IBuffer>>& inBuffers,
                                   std::shared_ptr<IBuffer>& product,
                                   std::vector<std::shared_ptr<IBuffer>>& recycleBuffers)
{
    if (outBuffer != nullptr) {
        product = outBuffer;
        recycleBuffers = inBuffers;
        return;
    }
    auto outPort = GetOutPortById(0);
    if (outPort == nullptr) {
        CAMERA_LOGE("fatal error, can't get out port.");
        return;
    }

    PortFormat format {
    };
    outPort->GetFormat(format);
    auto id = format.bufferPoolId_;
    auto it = std::find_if(inBuffers.begin(), inBuffers.end(),
                           [&id](const std::shared_ptr<IBuffer>& buffer) { return buffer->GetPoolId() == id; });
    if (it == inBuffers.end()) {
        CAMERA_LOGE("fatal error, outBuffer should be null.");
        return;
    }
    product = *it;
    inBuffers.erase(it);
    recycleBuffers = inBuffers;
    return;
}
REGISTERNODE(IppNode, {"ipp"});
} // namespace OHOS::Camera
