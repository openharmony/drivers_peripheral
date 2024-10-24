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

#include "camera_device_service.h"
#include "stream_operator_service_callback.h"

namespace OHOS::Camera {

CameraDeviceService::CameraDeviceService(OHOS::sptr<ICameraDeviceVdi> cameraDeviceServiceVdi)
    : cameraDeviceServiceVdi_(cameraDeviceServiceVdi)
{
    CAMERA_LOGD("ctor, instance");
}

int32_t CameraDeviceService::GetStreamOperator(const sptr<IStreamOperatorCallback> &callbackObj,
    sptr<IStreamOperator> &streamOperator)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:GetStreamOperator");
    OHOS::sptr<IStreamOperatorVdi> streamOperatorVdi = nullptr;
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceServiceVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    OHOS::sptr<IStreamOperatorVdiCallback> vdiCallbackObj = new StreamOperatorServiceCallback(callbackObj);
    if (vdiCallbackObj == nullptr) {
        CAMERA_LOGE("Get stream operator error, vdiCallbackObj is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }
    int32_t ret = cameraDeviceServiceVdi_->GetStreamOperator(vdiCallbackObj, streamOperatorVdi);
    if (ret != OHOS::HDI::Camera::V1_0::NO_ERROR) {
        CAMERA_LOGE("Get stream operator error, ret=%{public}d", ret);
        return ret;
    }
    if (streamOperatorVdi == nullptr) {
        CAMERA_LOGE("Get stream operator error, streamOperatorVdi is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }
    streamOperator = new StreamOperatorService(streamOperatorVdi);
    if (streamOperator == nullptr) {
        CAMERA_LOGE("Get stream operator error, streamOperator is nullptr");
        return OHOS::HDI::Camera::V1_0::INSUFFICIENT_RESOURCES;
    }

    return OHOS::HDI::Camera::V1_0::NO_ERROR;
}

int32_t CameraDeviceService::UpdateSettings(const std::vector<uint8_t> &settings)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:UpdateSettings");
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceServiceVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraDeviceServiceVdi_->UpdateSettings(settings);
}

int32_t CameraDeviceService::SetResultMode(ResultCallbackMode mode)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:SetResultMode");
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceServiceVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraDeviceServiceVdi_->SetResultMode(static_cast<VdiResultCallbackMode>(mode));
}

int32_t CameraDeviceService::GetEnabledResults(std::vector<int32_t> &results)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:GetEnabledResults");
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceServiceVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraDeviceServiceVdi_->GetEnabledResults(results);
}

int32_t CameraDeviceService::EnableResult(const std::vector<int32_t> &results)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:EnableResult");
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceServiceVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraDeviceServiceVdi_->EnableResult(results);
}

int32_t CameraDeviceService::DisableResult(const std::vector<int32_t> &results)
{
    CameraHalHicollie cameraHalHicollie("CameraHost:DisableResult");
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceServiceVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraDeviceServiceVdi_->DisableResult(results);
}

int32_t CameraDeviceService::Close()
{
    CameraHalHicollie cameraHalHicollie("CameraHost:Close");
    CHECK_IF_PTR_NULL_RETURN_VALUE(cameraDeviceServiceVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return cameraDeviceServiceVdi_->Close();
}
} // end namespace OHOS::Camera
