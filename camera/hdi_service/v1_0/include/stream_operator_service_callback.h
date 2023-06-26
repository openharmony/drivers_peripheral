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

#ifndef STREAM_OPERATOR_SERVICE_CALLBACK
#define STREAM_OPERATOR_SERVICE_CALLBACK

#include "camera.h"
#include "v1_0/istream_operator_callback.h"
#include "v1_0/istream_operator_vdi_callback.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;

class StreamOperatorServiceCallback : public IStreamOperatorVdiCallback {
public:

    explicit StreamOperatorServiceCallback(OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback);

    StreamOperatorServiceCallback() = delete;

    virtual ~StreamOperatorServiceCallback() = default;

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamIds) override;

    int32_t OnCaptureEnded(int32_t captureId, const std::vector<VdiCaptureEndedInfo> &infos) override;

    int32_t OnCaptureError(int32_t captureId, const std::vector<VdiCaptureErrorInfo> &infos) override;

    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t> &streamIds, uint64_t timestamp) override;

private:
    OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback_;
};

} // end namespace OHOS::Camera
#endif // STREAM_OPERATOR_SERVICE_CALLBACK
