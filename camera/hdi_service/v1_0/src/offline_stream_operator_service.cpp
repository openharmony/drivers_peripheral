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

#include "offline_stream_operator_service.h"

namespace OHOS::Camera {

OfflineStreamOperatorService::OfflineStreamOperatorService(
    OHOS::sptr<IOfflineStreamOperatorVdi> offlineStreamOperatorVdi)
    : offlineStreamOperatorVdi_(offlineStreamOperatorVdi)
{
    CAMERA_LOGD("ctor, instance");
}

OfflineStreamOperatorService::~OfflineStreamOperatorService()
{
    CAMERA_LOGD("dtor, instance");
}

int32_t OfflineStreamOperatorService::CancelCapture(int32_t captureId)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(offlineStreamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return offlineStreamOperatorVdi_->CancelCapture(captureId);
}

int32_t OfflineStreamOperatorService::ReleaseStreams(const std::vector<int32_t> &streamIds)
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(offlineStreamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return offlineStreamOperatorVdi_->ReleaseStreams(streamIds);
}

int32_t OfflineStreamOperatorService::Release()
{
    CHECK_IF_PTR_NULL_RETURN_VALUE(offlineStreamOperatorVdi_, OHOS::HDI::Camera::V1_0::INVALID_ARGUMENT);
    return offlineStreamOperatorVdi_->Release();
}
} // end namespace OHOS::Camera
