/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef STREAM_OPERATOR_STREAM_OPERATOR_VDI_IMPL_H
#define STREAM_OPERATOR_STREAM_OPERATOR_VDI_IMPL_H

#include <set>
#include "v1_0/icamera_device_vdi.h"
#include "v1_0/istream_operator_vdi.h"
#include "capture_message.h"
#include "istream.h"
#include "offline_stream_operator_vdi_impl.h"
#include "offline_stream.h"
#include "surface.h"

namespace OHOS::Camera {
using namespace OHOS::VDI::Camera::V1_0;
class StreamOperatorVdiImpl : public IStreamOperatorVdi {
public:
    int32_t IsStreamsSupported(VdiOperationMode mode, const std::vector<uint8_t> &modeSetting,
                               const std::vector<VdiStreamInfo> &infos, VdiStreamSupportType &type) override;
    int32_t CreateStreams(const std::vector<VdiStreamInfo> &streamInfos) override;
    int32_t ReleaseStreams(const std::vector<int32_t> &streamIds) override;
    int32_t CommitStreams(VdiOperationMode mode, const std::vector<uint8_t> &modeSetting) override;
    int32_t GetStreamAttributes(std::vector<VdiStreamAttribute> &attributes) override;
    int32_t AttachBufferQueue(int32_t streamId, const sptr<BufferProducerSequenceable> &bufferProducer);
    int32_t DetachBufferQueue(int32_t streamId) override;
    int32_t Capture(int32_t captureId, const VdiCaptureInfo &info, bool isStreaming) override;
    int32_t CancelCapture(int32_t captureId) override;
    int32_t ChangeToOfflineStream(const std::vector<int32_t> &streamIds,
        const sptr<IStreamOperatorVdiCallback> &callbackObj, sptr<IOfflineStreamOperatorVdi> &offlineOperator) override;

public:
    StreamOperatorVdiImpl() = default;
    StreamOperatorVdiImpl(const OHOS::sptr<IStreamOperatorVdiCallback> &callback,
        const std::weak_ptr<ICameraDeviceVdi> &device);
    virtual ~StreamOperatorVdiImpl();
    StreamOperatorVdiImpl(const StreamOperatorVdiImpl &other) = delete;
    StreamOperatorVdiImpl(StreamOperatorVdiImpl&& other) = delete;
    StreamOperatorVdiImpl &operator=(const StreamOperatorVdiImpl &other) = delete;
    StreamOperatorVdiImpl &operator=(StreamOperatorVdiImpl&& other) = delete;

    RetCode Init();
    RetCode ReleaseStreams();

private:
    void FillCaptureErrorInfo(std::vector<VdiCaptureErrorInfo> &info, MessageGroup message);
    void FillCaptureEndedInfo(std::vector<VdiCaptureEndedInfo> &info, MessageGroup message);
    void HandleCallbackMessage(MessageGroup &message);
    void OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamIds);
    void OnCaptureEnded(int32_t captureId, const std::vector<VdiCaptureEndedInfo> &infos);
    void OnCaptureError(int32_t captureId, const std::vector<VdiCaptureErrorInfo> &infos);
    void OnFrameShutter(int32_t captureId, const std::vector<int32_t> &streamIds, uint64_t timestamp);
    bool CheckStreamInfo(const VdiStreamInfo streamInfo);
    DynamicStreamSwitchMode CheckStreamsSupported(VdiOperationMode mode,
                                                  const std::shared_ptr<CameraMetadata> &modeSetting,
                                                  const std::vector<VdiStreamInfo> &infos);
    void StreamInfoToStreamConfiguration(StreamConfiguration &scg, const VdiStreamInfo info);
    void GetStreamSupportType(std::set<int32_t> inputIDSet,
                              DynamicStreamSwitchMode method,
                              VdiStreamSupportType &type);
private:
    OHOS::sptr<IStreamOperatorVdiCallback> callback_ = nullptr;
    std::weak_ptr<ICameraDeviceVdi> device_;
    std::shared_ptr<IPipelineCore> pipelineCore_ = nullptr;
    std::shared_ptr<IStreamPipelineCore> streamPipeline_ = nullptr;
    std::shared_ptr<CaptureMessageOperator> messenger_ = nullptr;

    std::mutex streamLock_ = {};
    std::unordered_map<int32_t, std::shared_ptr<IStream>> streamMap_ = {};

    std::mutex requestLock_ = {};
    std::unordered_map<int32_t, std::shared_ptr<CaptureRequest>> requestMap_ = {};
    OHOS::sptr<OfflineStreamOperatorVdiImpl> oflstor_ = nullptr;
    std::function<void()> requestTimeoutCB_ = nullptr;
};
} // end namespace OHOS::Camera
#endif // STREAM_OPERATOR_STREAM_OPERATOR_VDI_IMPL_H
