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

#include "stream_pipeline_core.h"
#include "ipp_node.h"
namespace OHOS::Camera {
RetCode StreamPipelineCore::Init()
{
    strategy_ = StreamPipelineStrategy::Create(context_->streamMgr_);
    builder_ = StreamPipelineBuilder::Create(context_->streamMgr_);
    dispatcher_ = StreamPipelineDispatcher::Create();
    return RC_OK;
}

RetCode StreamPipelineCore::CreatePipeline(const int32_t& mode)
{
    std::lock_guard<std::mutex> l(mutex_);
    std::shared_ptr<PipelineSpec> spec_ = strategy_->GeneratePipelineSpec(mode);
    if (spec_ == nullptr) {
        return RC_ERROR;
    }

    std::shared_ptr<Pipeline> pipeline = builder_->Build(spec_);
    if (pipeline == nullptr) {
        return RC_ERROR;
    }

    return dispatcher_->Update(pipeline);
}

RetCode StreamPipelineCore::DestroyPipeline(const std::vector<int>& streamIds)
{
    std::lock_guard<std::mutex> l(mutex_);
    RetCode re = RC_OK;
    for (const auto& it : streamIds) {
        re = dispatcher_->Destroy(it) | re;
        re = builder_->Destroy(it) | re;
        re = strategy_->Destroy(it) | re;
    }
    return re;
}

RetCode StreamPipelineCore::Start(const std::vector<int>& streamIds)
{
    std::lock_guard<std::mutex> l(mutex_);
    RetCode re = RC_OK;
    for (const auto& it : streamIds) {
        re = dispatcher_->Start(it) | re;
    }
    return re;
}

RetCode StreamPipelineCore::Stop(const std::vector<int>& streamIds)
{
    std::lock_guard<std::mutex> l(mutex_);
    RetCode re = RC_OK;
    for (const auto& it : streamIds) {
        CAMERA_LOGV("stop stream %{public}d begin",it);
        re = dispatcher_->Stop(it) | re;
        CAMERA_LOGV("stop stream %{public}d end", it);
    }
    return re;
}

RetCode StreamPipelineCore::Config(const std::vector<int>& streamIds)
{
    std::lock_guard<std::mutex> l(mutex_);
    RetCode re = RC_OK;
    for (const auto& it : streamIds) {
        re = dispatcher_->Config(it) | re;
    }
    return re;
}

std::shared_ptr<OfflinePipeline> StreamPipelineCore::GetOfflinePipeline(const int32_t id)
{
    std::lock_guard<std::mutex> l(mutex_);
    std::shared_ptr<INode> node = dispatcher_->GetNode(id, "ipp");
    return std::static_pointer_cast<IppNode>(node);
}

RetCode StreamPipelineCore::Capture(const std::vector<int32_t>& streamIds,
    const std::vector<int32_t>& ids, int32_t captureId)
{
    std::lock_guard<std::mutex> l(mutex_);
    for (const auto& it : ids) {
        dispatcher_->Capture(streamIds, it, captureId);
    }
    return RC_OK;
}

std::shared_ptr<IStreamPipelineCore> IStreamPipelineCore::Create(const std::shared_ptr<NodeContext>& c)
{
    return std::make_shared<StreamPipelineCore>(c);
}
}
