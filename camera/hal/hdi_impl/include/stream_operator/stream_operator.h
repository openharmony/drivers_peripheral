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

#ifndef STREAM_OPERATOR_STREAM_OPERATOR_H
#define STREAM_OPERATOR_STREAM_OPERATOR_H

#include <set>
#include "v1_0/icamera_device.h"
#include "capture_message.h"
#include "istream.h"
#include "v1_0/istream_operator.h"
#include "offline_stream_operator.h"
#include "offline_stream.h"
#include "surface.h"
#include "v1_0/types.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
class StreamOperator : public IStreamOperator {
public:
    int32_t IsStreamsSupported(OperationMode mode, const std::vector<uint8_t>& modeSetting,
                               const std::vector<StreamInfo>& infos, StreamSupportType& type) override;
    int32_t CreateStreams(const std::vector<StreamInfo>& streamInfos) override;
    int32_t ReleaseStreams(const std::vector<int32_t>& streamIds) override;
    int32_t CommitStreams(OperationMode mode, const std::vector<uint8_t>& modeSetting) override;
    int32_t GetStreamAttributes(std::vector<StreamAttribute>& attributes) override;
    int32_t AttachBufferQueue(int32_t streamId, const sptr<BufferProducerSequenceable>& bufferProducer);
    int32_t DetachBufferQueue(int32_t streamId) override;
    int32_t Capture(int32_t captureId, const CaptureInfo& info, bool isStreaming) override;
    int32_t CancelCapture(int32_t captureId) override;
    int32_t ChangeToOfflineStream(const std::vector<int32_t>& streamIds,
        const sptr<IStreamOperatorCallback>& callbackObj, sptr<IOfflineStreamOperator>& offlineOperator) override;

public:
    StreamOperator() = default;
    StreamOperator(const OHOS::sptr<IStreamOperatorCallback>& callback, const std::weak_ptr<ICameraDevice>& device);
    virtual ~StreamOperator();
    StreamOperator(const StreamOperator& other) = delete;
    StreamOperator(StreamOperator&& other) = delete;
    StreamOperator& operator=(const StreamOperator& other) = delete;
    StreamOperator& operator=(StreamOperator&& other) = delete;

    RetCode Init();
    RetCode ReleaseStreams();

private:
    void HandleCallbackMessage(MessageGroup& message);
    void OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds);
    void OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos);
    void OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos);
    void OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp);
    bool CheckStreamInfo(const StreamInfo streamInfo);
    DynamicStreamSwitchMode CheckStreamsSupported(OperationMode mode,
                                                  const std::shared_ptr<CameraMetadata>& modeSetting,
                                                  const std::vector<StreamInfo>& infos);
    void StreamInfoToStreamConfiguration(StreamConfiguration &scg, const StreamInfo info);
    void GetStreamSupportType(std::set<int32_t> inputIDSet,
                              DynamicStreamSwitchMode method,
                              StreamSupportType& type);
private:
    OHOS::sptr<IStreamOperatorCallback> callback_ = nullptr;
    std::weak_ptr<ICameraDevice> device_;
    std::shared_ptr<IPipelineCore> pipelineCore_ = nullptr;
    std::shared_ptr<IStreamPipelineCore> streamPipeline_ = nullptr;
    std::shared_ptr<CaptureMessageOperator> messenger_ = nullptr;

    std::mutex streamLock_ = {};
    std::unordered_map<int32_t, std::shared_ptr<IStream>> streamMap_ = {};

    std::mutex requestLock_ = {};
    std::unordered_map<int32_t, std::shared_ptr<CaptureRequest>> requestMap_ = {};
    OHOS::sptr<OfflineStreamOperator> oflstor_ = nullptr;
    std::function<void()> requestTimeoutCB_ = nullptr;
};
} // end namespace OHOS::Camera
#endif // STREAM_OPERATOR_STREAM_OPERATOR_H
