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

#include "stream_operator_service_callback.h"
#include "camera_service_type_converter.h"

namespace OHOS::Camera {
StreamOperatorServiceCallback::StreamOperatorServiceCallback(OHOS::sptr<IStreamOperatorCallback> streamOperatorCallback)
    : streamOperatorCallback_(streamOperatorCallback)
{
}

int32_t StreamOperatorServiceCallback::OnCaptureStarted(int32_t captureId, const std::vector<int32_t> &streamIds)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorCallback_->OnCaptureStarted(captureId, streamIds);
}

int32_t StreamOperatorServiceCallback::OnCaptureEnded(int32_t captureId, const std::vector<VdiCaptureEndedInfo> &infos)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<CaptureEndedInfo> hdiInfos;
    for (auto info : infos) {
        CaptureEndedInfo hdiInfo;
        ConvertCaptureEndedInfoVdiToHdi(info, hdiInfo);
        hdiInfos.push_back(hdiInfo);
    }
    return streamOperatorCallback_->OnCaptureEnded(captureId, hdiInfos);
}

int32_t StreamOperatorServiceCallback::OnCaptureError(int32_t captureId, const std::vector<VdiCaptureErrorInfo> &infos)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<CaptureErrorInfo> hdiInfos;
    for (auto info : infos) {
        CaptureErrorInfo hdiInfo;
        ConvertCaptureErrorInfoVdiToHdi(info, hdiInfo);
        hdiInfos.push_back(hdiInfo);
    }
    return streamOperatorCallback_->OnCaptureError(captureId, hdiInfos);
}

int32_t StreamOperatorServiceCallback::OnFrameShutter(int32_t captureId,
    const std::vector<int32_t> &streamIds, uint64_t timestamp)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorCallback_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorCallback_->OnFrameShutter(captureId, streamIds, timestamp);
}

} // end namespace OHOS::Camera
