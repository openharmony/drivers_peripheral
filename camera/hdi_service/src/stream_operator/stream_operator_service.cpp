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

#include <algorithm>
#include <iterator>
#include "stream_operator_service.h"

namespace OHOS::Camera {

StreamOperatorService::StreamOperatorService(OHOS::sptr<IStreamOperatorVdi> streamOperatorVdi)
    : streamOperatorVdi_(streamOperatorVdi)
{
    CAMERA_LOGD("ctor, instance");
}

StreamOperatorService::~StreamOperatorService()
{
    CAMERA_LOGD("dtor, instance");
}

int32_t StreamOperatorService::IsStreamsSupported(OperationMode mode, const std::vector<uint8_t> &modeSetting,
    const std::vector<StreamInfo> &infos, StreamSupportType &type)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->IsStreamsSupported(mode, modeSetting, infos, type);
}

int32_t StreamOperatorService::CreateStreams(const std::vector<StreamInfo> &streamInfos)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->CreateStreams(streamInfos);
}

int32_t StreamOperatorService::ReleaseStreams(const std::vector<int32_t> &streamIds)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->ReleaseStreams(streamIds);
}

int32_t StreamOperatorService::CommitStreams(OperationMode mode, const std::vector<uint8_t> &modeSetting)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->CommitStreams(mode, modeSetting);
}

int32_t StreamOperatorService::GetStreamAttributes(std::vector<StreamAttribute> &attributes)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->GetStreamAttributes(attributes);
}

int32_t StreamOperatorService::AttachBufferQueue(int32_t streamId,
    const sptr<BufferProducerSequenceable> &bufferProducer)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->AttachBufferQueue(streamId, bufferProducer);
}

int32_t StreamOperatorService::DetachBufferQueue(int32_t streamId)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->DetachBufferQueue(streamId);
}

int32_t StreamOperatorService::Capture(int32_t captureId, const CaptureInfo &info, bool isStreaming)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->Capture(captureId, info, isStreaming);
}

int32_t StreamOperatorService::CancelCapture(int32_t captureId)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->CancelCapture(captureId);
}

int32_t StreamOperatorService::ChangeToOfflineStream(const std::vector<int32_t> &streamIds,
    const sptr<IStreamOperatorCallback> &callbackObj, sptr<IOfflineStreamOperator> &offlineOperator)
{
    OHOS::sptr<IOfflineStreamOperatorVdi> offlineOperatorVdi = nullptr;
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    int32_t ret = streamOperatorVdi_->ChangeToOfflineStream(streamIds, callbackObj, offlineOperatorVdi);
    if (ret != OHOS::HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("Change to offline stream error, ret=%{public}d", ret);
        return ret;
    }
    if (offlineOperatorVdi == nullptr) {
        CAMERA_LOGE("Change to offline stream error, offlineOperatorVdi is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }
    offlineOperator = new OfflineStreamOperatorService(offlineOperatorVdi);
    if (offlineOperator == nullptr) {
        CAMERA_LOGE("Change to offline stream error, offlineOperator is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }

    return OHOS::HDI::Camera::V1_0::NO_ERROR;
}
} // end namespace OHOS::Camera
