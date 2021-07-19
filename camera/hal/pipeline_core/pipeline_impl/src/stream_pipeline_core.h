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

#ifndef STREAM_PIPELINE_CORE_H
#define STREAM_PIPELINE_CORE_H

#include "istream_pipeline_core.h"
#include <mutex>
#include "stream_pipeline_strategy.h"
#include "stream_pipeline_builder.h"
#include "stream_pipeline_dispatcher.h"
#include "camera_metadata_info.h"
#include "idevice_manager.h"

namespace OHOS::Camera {
class StreamPipelineCore : public IStreamPipelineCore {
public:
    RetCode Init() override;
    RetCode CreatePipeline(const int32_t& mode) override;
    RetCode DestroyPipeline(const std::vector<int32_t>& types) override;
    RetCode Start(const std::vector<int32_t>& types) override;
    RetCode Stop(const std::vector<int32_t>& types) override;
    RetCode Config(const std::vector<int32_t>& types) override;
    StreamPipelineCore(const std::shared_ptr<NodeContext>& c) : context_(c)
    {
    }
    ~StreamPipelineCore() override = default;
    virtual std::shared_ptr<OfflinePipeline> GetOfflinePipeline(const int32_t id) override;
    virtual RetCode Capture(const std::vector<int32_t>& streamIds,
        const std::vector<int32_t>& ids, int32_t captureId) override;

protected:
    std::mutex mutex_;
    std::shared_ptr<NodeContext> context_ = nullptr;
    std::unique_ptr<StreamPipelineStrategy> strategy_ = nullptr;
    std::unique_ptr<StreamPipelineBuilder>  builder_ = nullptr;
    std::unique_ptr<StreamPipelineDispatcher> dispatcher_ = nullptr;
};
}
#endif
