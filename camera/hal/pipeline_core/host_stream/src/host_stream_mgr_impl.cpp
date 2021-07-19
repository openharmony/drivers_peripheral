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

#include "host_stream_mgr.h"
#include "host_stream.h"

namespace OHOS::Camera {
class HostStreamMgrImpl : public HostStreamMgr {
public:
    RetCode CreateHostStream(const HostStreamInfo& info, BufferCb c) override;
    RetCode DestroyHostStream(const std::vector<int>& types) override;
    void GetStreamTypes(std::vector<int32_t>& s) const override;
    HostStreamInfo GetStreamInfo(const int32_t& id) const override;
    HostStreamInfo GetStreamInfoFromRight(const int32_t& id) const override;
    BufferCb GetBufferCb(const int32_t& type) const override;
    HostStreamMgrImpl() = default;
    ~HostStreamMgrImpl() override = default;
protected:
    std::vector<std::unique_ptr<HostStream>> streams_;
};

RetCode HostStreamMgrImpl::CreateHostStream(const HostStreamInfo& info, BufferCb c)
{
    auto it = std::find_if(streams_.begin(), streams_.end(), [info](const std::unique_ptr<HostStream>& s) {
                return s->GetStreamId() == info.streamId_;
                });
    if (it != streams_.end()) {
        CAMERA_LOGE("fail to CreateHostStream cause streamid %d error",info.streamId_);
        return RC_ERROR;
    }
    CAMERA_LOGI("bufferpool id = %llu , stream id = %d,stream type = %d",
        info.bufferPoolId_, info.streamId_, info.type_);
    streams_.push_back(HostStream::Create(info, c));
    return RC_OK;
}

RetCode HostStreamMgrImpl::DestroyHostStream(const std::vector<int>& streamIds)
{
    if (streamIds.empty()) {
        return RC_OK;
    }

    for (auto& streamId : streamIds) {
        auto it = std::find_if(streams_.begin(), streams_.end(), [streamId](const std::unique_ptr<HostStream>& s) {
            return s->GetStreamId() == streamId;
            });
        if (it != streams_.end()) {
            streams_.erase(it);
        } else {
            CAMERA_LOGE("stream id not found. [stream id = %{public}d]", streamId);
        }
    }
    return RC_OK;
}

void HostStreamMgrImpl::GetStreamTypes(std::vector<int32_t>& s) const
{
    for (const auto& it : streams_) {
        s.push_back(static_cast<std::underlying_type<StreamIntent>::type>(it->GetStreamType()));
    }
    std::sort(s.begin(), s.end(), [](const int32_t& f, const int32_t& n) {
                    return f < n;
                });
}

HostStreamInfo HostStreamMgrImpl::GetStreamInfo(const int32_t& id) const
{
    auto it = std::find_if(streams_.begin(), streams_.end(), [id](const std::unique_ptr<HostStream>& s) {
                return static_cast<std::underlying_type<StreamIntent>::type>(s->GetStreamType()) == id;
                });
    if (it != streams_.end()) {
        return (*it)->GetStreamInfo();
    }
    return {};
}

HostStreamInfo HostStreamMgrImpl::GetStreamInfoFromRight(const int32_t& id) const
{
    auto it = std::find_if(streams_.rbegin(), streams_.rend(), [id](const std::unique_ptr<HostStream>& s) {
                return static_cast<std::underlying_type<StreamIntent>::type>(s->GetStreamType()) == id;
                });
    if (it != streams_.rend()) {
        return (*it)->GetStreamInfo();
    }
    return {};
}

BufferCb HostStreamMgrImpl::GetBufferCb(const int& streamId) const
{
    auto it = std::find_if(streams_.begin(), streams_.end(), [streamId](const std::unique_ptr<HostStream>& s) {
                return s->GetStreamId() == streamId;
                });
    if (it != streams_.end()) {
        return (*it)->GetBufferCb();
    }
    return nullptr;
}

std::shared_ptr<HostStreamMgr> HostStreamMgr::Create()
{
    return std::make_shared<HostStreamMgrImpl>();
}
}
