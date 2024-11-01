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

#ifndef STREAM_OPERATOR_STREAM_BASE_H
#define STREAM_OPERATOR_STREAM_BASE_H

#include "ibuffer.h"
#include "ibuffer_pool.h"
#include "istream.h"
#include "capture_request.h"
#include <atomic>

namespace OHOS::Camera {
class StreamBase : public IStream, public std::enable_shared_from_this<StreamBase> {
public:
    StreamBase(const int32_t id,
               const VdiStreamIntent type,
               std::shared_ptr<IPipelineCore>& p,
               std::shared_ptr<CaptureMessageOperator>& m);
    virtual ~StreamBase();
    StreamBase(const StreamBase& other) = delete;
    StreamBase(StreamBase&& other) = delete;
    StreamBase& operator=(const StreamBase& other) = delete;
    StreamBase& operator=(StreamBase&& other) = delete;

public:
    RetCode ConfigStream(StreamConfiguration& config) override;
    RetCode CommitStream() override;
    RetCode StartStream() override;
    RetCode StopStream() override;
    RetCode AddRequest(std::shared_ptr<CaptureRequest>& request) override;
    RetCode CancelRequest(const std::shared_ptr<CaptureRequest>& request) override;
    RetCode AttachStreamTunnel(std::shared_ptr<StreamTunnel>& tunnel) override;
    RetCode DetachStreamTunnel() override;
    RetCode ChangeToOfflineStream(std::shared_ptr<OfflineStream> offlineStream) override;
    bool GetTunnelMode() const override;
    StreamConfiguration GetStreamAttribute() const override;
    int32_t GetStreamId() const override;
    RetCode Capture(const std::shared_ptr<CaptureRequest>& request) override;
    RetCode OnFrame(const std::shared_ptr<CaptureRequest>& request) override;
    bool IsRunning() const override;
    void DumpStatsInfo() const override;
    void ReleaseStreamBufferPool() override;

    virtual void HandleRequest();
    virtual uint64_t GetUsage();
    virtual uint32_t GetBufferCount();
    virtual void HandleResult(std::shared_ptr<IBuffer>& buffer);
    virtual RetCode DeliverStreamBuffer();
    virtual RetCode ReceiveBuffer(std::shared_ptr<IBuffer>& buffer);
    virtual uint64_t GetFrameCount() const;

    enum StreamState {
        STREAM_STATE_IDLE = 0,
        STREAM_STATE_ACTIVE,
        STREAM_STATE_BUSY,
        STREAM_STATE_OFFLINE,
    };

protected:
    int32_t streamId_ = -1;
    int32_t streamType_ = -1;
    bool isFirstRequest = true;
    uint64_t frameCount = 0;
    std::shared_ptr<IPipelineCore> pipelineCore_ = nullptr;
    std::shared_ptr<IStreamPipelineCore> pipeline_ = nullptr;
    std::shared_ptr<HostStreamMgr> hostStreamMgr_ = nullptr;
    std::shared_ptr<CaptureMessageOperator> messenger_ = nullptr;
    StreamConfiguration streamConfig_ = {};
    std::atomic<StreamState> state_ = STREAM_STATE_IDLE;
    std::shared_ptr<StreamTunnel> tunnel_ = nullptr;
    std::shared_ptr<IBufferPool> bufferPool_ = nullptr;
    uint64_t poolId_ = 0;

    std::mutex wtLock_ = {};
    std::list<std::shared_ptr<CaptureRequest>> waitingList_ = {};
    std::condition_variable cv_ = {};

    std::mutex tsLock_ = {};
    std::list<std::shared_ptr<CaptureRequest>> inTransitList_ = {};

    std::mutex smLock_ = {};

    std::unique_ptr<std::thread> handler_ = nullptr;
    std::shared_ptr<CaptureRequest> lastRequest_ = nullptr;

    std::atomic<int> calltimes_;
};
} // end namespace OHOS::Camera
#endif // STREAM_OPERATOR_STREAM_BASE_H
