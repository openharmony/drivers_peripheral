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
#include "stream_operator_service_callback.h"
#include "camera_service_type_converter.h"
#include "camera_hal_hisysevent.h"

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
    CameraHalHicollie cameraHalHicollie("CameraHost:IsStreamsSupported");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<VdiStreamInfo> vdiInfos;
    for (auto info : infos) {
        VdiStreamInfo vdiInfo;
        ConvertStreamInfoHdiToVdi(info, vdiInfo);
        vdiInfos.push_back(vdiInfo);
    }
    VdiStreamSupportType vdiType = static_cast<VdiStreamSupportType>(type);
    int32_t ret = streamOperatorVdi_->IsStreamsSupported(static_cast<VdiOperationMode>(mode),
        modeSetting, vdiInfos, vdiType);
    type = static_cast<StreamSupportType>(vdiType);
    return ret;
}

int32_t StreamOperatorService::CreateStreams(const std::vector<StreamInfo> &streamInfos)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:CreateStreams");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<VdiStreamInfo> vdiStreamInfos;
    for (auto info : streamInfos) {
        VdiStreamInfo vdiInfo;
        ConvertStreamInfoHdiToVdi(info, vdiInfo);
        vdiStreamInfos.push_back(vdiInfo);
    }
    return streamOperatorVdi_->CreateStreams(vdiStreamInfos);
}

int32_t StreamOperatorService::ReleaseStreams(const std::vector<int32_t> &streamIds)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:ReleaseStreams");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->ReleaseStreams(streamIds);
}

int32_t StreamOperatorService::CommitStreams(OperationMode mode, const std::vector<uint8_t> &modeSetting)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:CommitStreams");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->CommitStreams(static_cast<VdiOperationMode>(mode), modeSetting);
}

int32_t StreamOperatorService::GetStreamAttributes(std::vector<StreamAttribute> &attributes)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:GetStreamAttributes");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    std::vector<VdiStreamAttribute> vdiAttributes;
    for (auto attribute : attributes) {
        VdiStreamAttribute vdiAttribute;
        ConvertStreamAttributeHdiToVdi(attribute, vdiAttribute);
        vdiAttributes.push_back(vdiAttribute);
    }
    int32_t ret = streamOperatorVdi_->GetStreamAttributes(vdiAttributes);
    std::vector<StreamAttribute>().swap(attributes);
    for (auto attribute : vdiAttributes) {
        StreamAttribute hdiAttribute;
        ConvertStreamAttributeVdiToHdi(attribute, hdiAttribute);
        attributes.push_back(hdiAttribute);
    }
    return ret;
}

int32_t StreamOperatorService::AttachBufferQueue(int32_t streamId,
    const sptr<BufferProducerSequenceable> &bufferProducer)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:AttachBufferQueue");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->AttachBufferQueue(streamId, bufferProducer);
}

int32_t StreamOperatorService::DetachBufferQueue(int32_t streamId)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:DetachBufferQueue");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->DetachBufferQueue(streamId);
}

int32_t StreamOperatorService::Capture(int32_t captureId, const CaptureInfo &info, bool isStreaming)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:Capture");
    CAMERAHALPERFSYSEVENT(TIME_FOR_CAPTURE);
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    VdiCaptureInfo vdiInfo;
    ConvertCaptureInfoHdiToVdi(info, vdiInfo);
    return streamOperatorVdi_->Capture(captureId, vdiInfo, isStreaming);
}

int32_t StreamOperatorService::CancelCapture(int32_t captureId)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:CancelCapture");
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return streamOperatorVdi_->CancelCapture(captureId);
}

int32_t StreamOperatorService::ChangeToOfflineStream(const std::vector<int32_t> &streamIds,
    const sptr<IStreamOperatorCallback> &callbackObj, sptr<IOfflineStreamOperator> &offlineOperator)
{
    OHOS::sptr<IOfflineStreamOperatorVdi> offlineOperatorVdi = nullptr;
    CHECK_IF_PTR_NULL_RETURN_VALUE(streamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    OHOS::sptr<IStreamOperatorVdiCallback> vdiCallbackObj = new StreamOperatorServiceCallback(callbackObj);
    if (vdiCallbackObj == nullptr) {
        CAMERA_LOGE("Change to offline stream error, vdiCallbackObj is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }
    int32_t ret = streamOperatorVdi_->ChangeToOfflineStream(streamIds, vdiCallbackObj, offlineOperatorVdi);
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
