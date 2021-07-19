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
        GenerateNodeSeq(seqNode[it->GetStreamId()], it);
    }

    std::swap(seqNode_, seqNode);
    CAMERA_LOGI("------------------------Node Seq(UpStream) Dump Begin-------------\n");
    for (auto [ss, vv] : seqNode_) {
        CAMERA_LOGI("sink stream id:%d \n", ss);
        for (auto it : vv) {
            CAMERA_LOGI("seq node name:%s\n", it->GetName().c_str());
        }
    }
    CAMERA_LOGI("------------------------Node Seq(UpStream) Dump End-------------\n");
    return RC_OK;
}

RetCode StreamPipelineDispatcher::Start(const int& streamId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_ERROR;
    }

    RetCode re = RC_OK;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        CAMERA_LOGV("start node %{public}s begin",(*it)->GetName().c_str());
        re = (*it)->Init() | re;
        re = (*it)->Start() | re;
        CAMERA_LOGV("start node %{public}s end", (*it)->GetName().c_str());
    }
    streamNum_++;
    return re;
}

RetCode StreamPipelineDispatcher::Config(const int& streamId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_ERROR;
    }

    RetCode re = RC_OK;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        re = (*it)->Config() | re;
    }
    return re;
}

RetCode StreamPipelineDispatcher::Stop(const int& streamId)
{
    if (seqNode_.count(streamId) == 0) {
        return RC_OK;
    }

    RetCode re = RC_OK;
    for (auto it = seqNode_[streamId].begin(); it != seqNode_[streamId].end(); it++) {
        CAMERA_LOGV("stop node %{public}s begin",(*it)->GetName().c_str());
        if ((*it)->GetNumberOfOutPorts() > 1 && streamNum_ != 1) {
            CAMERA_LOGI("node %{public}s can't be stoped, stream num = %d",
                (*it)->GetName().c_str(), streamNum_);
            break;
        }
        re = (*it)->Stop() | re;
        CAMERA_LOGV("stop node %s end", (*it)->GetName().c_str());
    }
    streamNum_--;
    return re;
}

RetCode StreamPipelineDispatcher::Destroy(const int& streamId)
{
    if (streamNum_ == 0){
        seqNode_.clear(); // fixme
    }
    return RC_OK;
}

std::shared_ptr<INode> StreamPipelineDispatcher::GetNode(const int32_t streamId, const std::string name)
{
    if (seqNode_.count(streamId) == 0) {
        return nullptr;
    }

    std::shared_ptr<INode> node = nullptr;
    for (auto it = seqNode_[streamId].rbegin(); it != seqNode_[streamId].rend(); it++) {
        if (name == (*it)->GetName().substr(0, 3)) { // 0:复制字符串的起始位 3:复制字符串的长度 从指定位置得到名字
            node = *it;
        }
    }
    return node;
}

RetCode StreamPipelineDispatcher::Capture(const std::vector<int32_t>& streamIds,
    const int32_t id, const int32_t captureId)
{
    if (seqNode_.count(id) == 0) {
        return RC_ERROR;
    }

    for (auto it = seqNode_[id].rbegin(); it != seqNode_[id].rend(); it++) {
        (*it)->Capture(streamIds, captureId);
    }

    return RC_OK;
}
}
