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

#include "stream_pipeline_dispatcher.h"

namespace OHOS::Camera {

std::unique_ptr<StreamPipelineDispatcher> StreamPipelineDispatcher::Create()
{
    return std::make_unique<StreamPipelineDispatcher>();
}

void StreamPipelineDispatcher::GenerateNodeSeq(std::vector<std::shared_ptr<INode>>& nodeVec,
    const std::shared_ptr<INode>& node)
{
    if (node != nullptr) {
        nodeVec.push_back(node);
    } else {
        return;
    }

    if (node->GetNumberOfInPorts() == 0) {
        return;
    }

    for (const auto& it : node->GetInPorts()) {
        GenerateNodeSeq(nodeVec, it->Peer()->GetNode());
    }
}

RetCode StreamPipelineDispatcher::Update(const std::shared_ptr<Pipeline>& p)
{
    std::vector<std::shared_ptr<INode>> sink;
    for (auto it = p->nodes_.rbegin(); it < p->nodes_.rend(); it++) {
        if ((*it)->GetNumberOfInPorts() == 1 && (*it)->GetNumberOfOutPorts() == 0) {
            sink.push_back(*it);
        }
    }

    std::unordered_map<int, std::vector<std::shared_ptr<INode>>> seqNode;
    for (const auto& it : sink) {
        auto inPorts = it->GetInPorts();
        if (!inPorts.empty()) {
            // sink node has only one port, and it is a in-port
            GenerateNodeSeq(seqNode[inPorts[0]->GetStreamId()], it);
        }
    }

    for (auto& [id, pipe] : seqNode) {
        CutUselessBranch(id, pipe);
    }

    std::swap(seqNode_, seqNode);
    CAMERA_LOGI("------------------------Node Seq(UpStream) Dump Begin-------------\n");
    for (auto [ss, vv] : seqNode_) {
        CAMERA_LOGI("sink stream id:%{public}d \n", ss);
        for (auto it : vv) {
            it->wide_ = static_cast<int32_t>(p->maxWidth_);
            it->high_ = static_cast<int32_t>(p->maxHeight_);
            CAMERA_LOGI("seq node name:%{public}s, %{public}d * %{public}d\n",
                it->GetName().c_str(), it->wide_, it->high_);
        }
    }
    CAMERA_LOGI("------------------------Node Seq(UpStream) Dump End-------------\n");

    SetDispatcherCallback();

    return RC_OK;
}

RetCode StreamPipelineDispatcher::SetDispatcherCallback()
{
    RetCode ret = RC_OK;
    for (auto iter = seqNode_.begin(); iter != seqNode_.end(); iter++) {
        for (auto it = iter->second.rbegin(); it != iter->second.rend(); it++) {
            ret = (*it)->SetCallback() | ret;
        }
    }
    return ret;
}

void StreamPipelineDispatcher::CutUselessBranch(int32_t streamId, std::vector<std::shared_ptr<INode>>& branch)
{
    auto it = std::find_if(branch.begin(), branch.end(), [streamId](const std::shared_ptr<INode> node) {
        auto ports = node->GetOutPorts();
        bool isSameBranch = true;
        for (auto port : ports) {
            if (port->GetStreamId() == streamId) {
                return false;
            }
            isSameBranch = false;
        }
        return !isSameBranch;
    });
    if (it == branch.end()) {
        return;
    }
    branch.erase(it, branch.end());

    return;
}

RetCode StreamPipelineDispatcher::Prepare(const int32_t streamId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_ERROR;
    }

    RetCode ret = RC_OK;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        CAMERA_LOGV("init node %{public}s begin", (*it)->GetName().c_str());
        ret = (*it)->Init(streamId) | ret;
        CAMERA_LOGV("init node %{public}s end", (*it)->GetName().c_str());
    }
    return ret;
}

RetCode StreamPipelineDispatcher::Start(const int32_t streamId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_ERROR;
    }

    RetCode ret = RC_OK;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        CAMERA_LOGV("start node %{public}s begin", (*it)->GetName().c_str());
        ret = (*it)->Start(streamId) | ret;
        CAMERA_LOGV("start node %{public}s end", (*it)->GetName().c_str());
    }
    return ret;
}

RetCode StreamPipelineDispatcher::Config(const int32_t streamId, const CaptureMeta& meta)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_ERROR;
    }

    RetCode ret = RC_OK;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        ret = (*it)->Config(streamId, meta) | ret;
    }
    return ret;
}

RetCode StreamPipelineDispatcher::Flush(const int32_t streamId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_ERROR;
    }

    RetCode ret = RC_OK;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        CAMERA_LOGV("flush node %{public}s begin", (*it)->GetName().c_str());
        ret = (*it)->Flush(streamId) | ret;
        CAMERA_LOGV("flush node %{public}s end", (*it)->GetName().c_str());
    }
    return ret;
}

void StreamPipelineDispatcher::SetCallback(const MetaDataCb cb)
{
    CAMERA_LOGI("StreamPipelineDispatcher line: %{public}d", __LINE__);
    metaDataCb_ = cb;
}

RetCode StreamPipelineDispatcher::Stop(const int32_t streamId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_OK;
    }

    RetCode ret = RC_OK;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        CAMERA_LOGV("stop node %{public}s begin", (*it)->GetName().c_str());
        ret = (*it)->Stop(streamId) | ret;
        CAMERA_LOGV("stop node %{public}s end", (*it)->GetName().c_str());
    }
    return ret;
}

RetCode StreamPipelineDispatcher::Capture(const int32_t streamId, const int32_t captureId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_ERROR;
    }

    RetCode ret = RC_OK;
    for (auto it = seqNode_[streamId].begin(); it != seqNode_[streamId].end(); it++) {
        ret = (*it)->Capture(streamId, captureId) | ret;
    }

    return ret;
}

RetCode StreamPipelineDispatcher::CancelCapture(const int32_t streamId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_ERROR;
    }

    RetCode ret = RC_OK;
    for (auto it = seqNode_[streamId].begin(); it != seqNode_[streamId].end(); it++) {
        ret = (*it)->CancelCapture(streamId) | ret;
    }

    return ret;
}

RetCode StreamPipelineDispatcher::Destroy(const int32_t streamId)
{
    auto it = seqNode_.find(streamId);
    if (it == seqNode_.end()) {
        CAMERA_LOGV("pipeline for stream [id:%{public}d] doesn't exists, no need to destroy.", streamId);
        return RC_OK;
    }
    seqNode_.erase(streamId);

    return RC_OK;
}

std::shared_ptr<INode> StreamPipelineDispatcher::GetNode(const int32_t streamId, const std::string name)
{
    if (seqNode_.count(streamId) == 0) {
        return nullptr;
    }

    std::shared_ptr<INode> node = nullptr;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        if (name == (*it)->GetName().substr(0, 3)) {  // 3:Copy length
            node = *it;
        }
    }
    return node;
}
}
