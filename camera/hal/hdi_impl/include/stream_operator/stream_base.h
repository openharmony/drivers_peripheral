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

#include <string>
#include <functional>
#include <atomic>
#include <chrono>
#include <map>
#include "utils.h"
#include <surface.h>
#include "ibuffer_pool.h"
#include "object_factory.h"
#include "offline_stream_context.h"

namespace OHOS::Camera {
using ResultBufferCallback = std::function<void (int32_t captureId, int32_t streamId)>;
class StreamBase {
public:
    StreamBase();
    virtual ~StreamBase();
    StreamBase(const StreamBase &other) = delete;
    StreamBase(StreamBase &&other) = delete;
    StreamBase& operator=(const StreamBase &other) = delete;
    StreamBase& operator=(StreamBase &&other) = delete;

public:
    virtual RetCode Init(const std::shared_ptr<StreamInfo> &streamInfo);
    virtual RetCode AttachBufferQueue(const OHOS::sptr<OHOS::IBufferProducer> &producer);
    virtual RetCode DetachBufferQueue();
    virtual RetCode GetStreamAttribute(std::shared_ptr<StreamAttribute> &attribute) const;
    virtual std::shared_ptr<StreamInfo>& GetStreamInfo();
    virtual RetCode Request();
    virtual RetCode Result(const std::shared_ptr<IBuffer> &buffer, OperationType optType);
    virtual RetCode Release();
    virtual uint64_t GetBufferPoolId() const;
    virtual void Stop();
    virtual RetCode HandleOverStaticContext(const std::shared_ptr<OfflineStreamContext>& context);
    virtual RetCode HandleOverDynamicContext(const std::shared_ptr<OfflineStreamContext>& context);
    virtual RetCode SwitchToOffline();
    virtual int32_t GetQueueSize() const;
    virtual RetCode RequestCheck();

protected:
    virtual RetCode CreateBufferPool();
    virtual uint64_t GetCurrentLocalTimeStamp();

protected:
    std::shared_ptr<StreamInfo> streamInfo_ = nullptr;
    std::shared_ptr<StreamAttribute> attribute_ = nullptr;
    uint64_t bufferPoolId_ = 0;
    std::mutex                          bmLock_;
    std::shared_ptr<IBufferPool> bufferPool_ = nullptr;
    std::map<std::shared_ptr<IBuffer>, OHOS::sptr<OHOS::SurfaceBuffer>> bufferMap_ = {};
    std::list<std::shared_ptr<IBuffer>> pipeBuffer_ = {};
    uint64_t frameCount_ = 0;
    std::mutex frameLock_;
    OHOS::sptr<OHOS::Surface> producer_ = nullptr;
    std::atomic<bool> isOnline = true;
    std::atomic<bool> requestFlag_ = true;
    int32_t bufferIndex = -1;
};

using StreamFactory = RegisterFactoty<StreamBase>;
#define REGISTERSTREAM(cls, ...) \
namespace { \
static std::string g_##cls = StreamFactory::Instance().DoRegister<cls>(__VA_ARGS__, \
    []() { return std::make_shared<cls>(); }); \
}
} // end namespace OHOS::Camera
#endif // STREAM_OPERATOR_STREAM_BASE_H
