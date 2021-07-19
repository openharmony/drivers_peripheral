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

#ifndef NODE_BASE_H
#define NODE_BASE_H

#include <atomic>
#include "inode.h"
#include "buffer_manager.h"
#include "idevice_manager.h"

namespace OHOS::Camera {
#define IS_NULLPTR(value) \
    do { \
        if (value == nullptr) { \
            CAMERA_LOGE(#value" is null"); \
            return RC_ERROR; \
        } \
    } while (0);
#define IS_ERROR(value) \
    do { \
        if (value == RC_ERROR) { \
        CAMERA_LOGE(#value" sensor configure failed"); \
        return value; \
        } \
    } while (0);
struct StreamSpec {
    int64_t         bufferPoolId_;
    std::thread*    deliverThread_ = nullptr;
};
using StreamSpec = struct StreamSpec;

class PortBase : public IPort {
public:
    PortBase(const std::string& name, const std::weak_ptr<INode>& n):
        name_(name),
        owner_(n)
    {
    }
    ~PortBase() override = default;
    std::string GetName() const override;
    RetCode SetFormat(const PortFormat& format) override;
    RetCode GetFormat(PortFormat& format) const override;
    RetCode Connect(const std::shared_ptr<IPort>& peer) override;
    RetCode DisConnect() override;
    int32_t Direction() const override;
    std::shared_ptr<INode> GetNode() const override;
    std::shared_ptr<IPort> Peer() const override;
    void DeliverBuffer(std::shared_ptr<FrameSpec> frameSpec) override;
    void SetCaptureId(const int32_t captureId) override;
    int32_t GetCaptureId() const override;
    void DeliverBuffers(std::vector<std::shared_ptr<FrameSpec>> mergeVec) override;
protected:
    std::string name_;
    std::shared_ptr<IPort> peer_ = nullptr;
    std::weak_ptr<INode> owner_;
    std::atomic<int32_t> captureId_ = -1;
};

class NodeBase : public INode, public std::enable_shared_from_this<NodeBase> {
public:
    NodeBase(const std::string& name, const std::string& type, const int streamId)
        : name_(name)
        , type_(type)
        , streamId_(streamId)
    {
    }
    ~NodeBase() override
    {
        for (const auto& it : portVec_) {
            it->DisConnect();
        }
        portVec_.clear();
    }

    std::string GetName() const override;
    std::string GetType() const override;
    int GetStreamId() const override;
    std::shared_ptr<IPort> GetPort(const std::string& name) override;
    RetCode Init() override;
    RetCode Start() override;
    RetCode Stop() override;
    RetCode Config() override;
    virtual void AchieveBuffer(std::shared_ptr<FrameSpec> frameSpec);
    RetCode Capture(const std::vector<int32_t>& streamIds, const int32_t captureId) override;
    RetCode GetDeviceManager();
    int32_t GetNumberOfInPorts() const override;
    int32_t GetNumberOfOutPorts() const override;
    std::vector<std::shared_ptr<IPort>> GetInPorts() const override;
    std::vector<std::shared_ptr<IPort>> GetOutPorts() override;
    std::shared_ptr<IPort> GetOutPortById(const int32_t id) override;
    void GetFrameInfo() override;
    RetCode SetMetadata(std::shared_ptr<CameraStandard::CameraMetadata> meta) override;
    RetCode CollectBuffers() override;
    void DeliverBuffers(std::shared_ptr<FrameSpec> frameSpec) override;
    void DeliverBuffers(std::vector<std::shared_ptr<FrameSpec>> mergeVec) override {};
    RetCode ProvideBuffers(std::shared_ptr<FrameSpec> frameSpec) override;
    void SetCallBack(BufferCb c) override
    {
        cb_ = c;
    }

protected:
    RetCode UpdateCaptureId(const std::shared_ptr<IBuffer>& buffer);
protected:
    std::string name_;
    std::string type_;
    int streamId_;
    BufferCb  cb_;
    std::shared_ptr<IDeviceManager>     deviceManager_ = nullptr;
    std::vector<std::shared_ptr<IPort>> portVec_;
    std::atomic_bool                    streamRunning_ = false;
    std::mutex                          streamLock_;
    std::vector<int64_t>                bufferPoolIdVec_;
    std::vector<std::shared_ptr<IPort>> outPutPorts_;
    std::shared_ptr<std::thread>        collectThread_ = nullptr;
    std::shared_ptr<CameraStandard::CameraMetadata>     meta_ = nullptr;
    std::vector<std::shared_ptr<FrameSpec>>         frameVec_;
    std::vector<StreamSpec>    streamVec_;
    int32_t captureId_ = -1;
};
}
#endif

