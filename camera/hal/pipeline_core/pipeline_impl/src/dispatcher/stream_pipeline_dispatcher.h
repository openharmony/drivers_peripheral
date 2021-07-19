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

#ifndef STREAM_PIPELINE_DISPATCHER_H
#define STREAM_PIPELINE_DISPATCHER_H
#include <unordered_map>
#include "stream_pipeline_data_structure.h"
#include "inode.h"
#include "config_parser.h"
#include "no_copyable.h"

namespace OHOS::Camera {

class StreamPipelineDispatcher : public NoCopyable, private ConfigParser {
public:
    static std::unique_ptr<StreamPipelineDispatcher> Create();
    virtual RetCode Update(const std::shared_ptr<Pipeline>& p);
    virtual RetCode Start(const int& streamId = -1);
    virtual RetCode Config(const int& streamId = -1);
    virtual RetCode Stop(const int& streamId = -1);
    virtual RetCode Destroy(const int& streamId = -1);
    StreamPipelineDispatcher() = default;
    virtual ~StreamPipelineDispatcher() = default;
    virtual std::shared_ptr<INode> GetNode(const int32_t streamId, const std::string name);
    virtual RetCode Capture(const std::vector<int32_t>& steamIds, const int32_t id, const int32_t captureId);
protected:
    void GenerateNodeSeq(std::vector<std::shared_ptr<INode>>& nodeVec,
                const std::shared_ptr<INode>& node);
protected:
    std::unordered_map<int, std::vector<std::shared_ptr<INode>>> seqNode_;
    uint8_t             streamNum_ = 0;
};
}
#endif
