/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef STREAM_OPERATOR_SERVICE_H
#define STREAM_OPERATOR_SERVICE_H

#include <set>
#include "surface.h"
#include "offline_stream_operator_service.h"
#include "v1_0/icamera_device.h"
#include "v1_0/istream_operator.h"
#include "v1_0/ioffline_stream_operator.h"
#include "v1_0/types.h"
#include "v1_0/istream_operator_vdi.h"
#include "camera_hal_hicollie.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;

class StreamOperatorService : public IStreamOperator {
public:
    int32_t IsStreamsSupported(OperationMode mode, const std::vector<uint8_t> &modeSetting,
                               const std::vector<StreamInfo> &infos, StreamSupportType &type) override;
    int32_t CreateStreams(const std::vector<StreamInfo> &streamInfos) override;
    int32_t ReleaseStreams(const std::vector<int32_t> &streamIds) override;
    int32_t CommitStreams(OperationMode mode, const std::vector<uint8_t> &modeSetting) override;
    int32_t GetStreamAttributes(std::vector<StreamAttribute> &attributes) override;
    int32_t AttachBufferQueue(int32_t streamId, const sptr<BufferProducerSequenceable> &bufferProducer) override;
    int32_t DetachBufferQueue(int32_t streamId) override;
    int32_t Capture(int32_t captureId, const CaptureInfo &info, bool isStreaming) override;
    int32_t CancelCapture(int32_t captureId) override;
    int32_t ChangeToOfflineStream(const std::vector<int32_t> &streamIds,
        const sptr<IStreamOperatorCallback> &callbackObj, sptr<IOfflineStreamOperator> &offlineOperator) override;

public:
    StreamOperatorService() = delete;
    explicit StreamOperatorService(OHOS::sptr<IStreamOperatorVdi> streamOperatorVdi);
    virtual ~StreamOperatorService();
    StreamOperatorService(const StreamOperatorService &other) = delete;
    StreamOperatorService(StreamOperatorService &&other) = delete;
    StreamOperatorService &operator=(const StreamOperatorService &other) = delete;
    StreamOperatorService &operator=(StreamOperatorService &&other) = delete;

private:
    OHOS::sptr<IStreamOperatorVdi> streamOperatorVdi_;
};
} // end namespace OHOS::Camera
#endif // STREAM_OPERATOR_SERVICE_H
