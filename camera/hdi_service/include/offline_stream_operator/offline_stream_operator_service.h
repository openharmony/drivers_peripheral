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

#ifndef OFFLINE_STREAM_OPERATOR_SERVICE_H
#define OFFLINE_STREAM_OPERATOR_SERVICE_H

#include "camera.h"
#include "v1_0/ioffline_stream_operator.h"
#include "v1_0/ioffline_stream_operator_vdi.h"

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
using namespace OHOS::VDI::Camera::V1_0;

class OfflineStreamOperatorService : public IOfflineStreamOperator {
public:
    OfflineStreamOperatorService() = delete;
    explicit OfflineStreamOperatorService(OHOS::sptr<IOfflineStreamOperatorVdi> offlineStreamOperatorVdi);
    virtual ~OfflineStreamOperatorService();
    int32_t CancelCapture(int32_t captureId) override;
    int32_t ReleaseStreams(const std::vector<int32_t> &streamIds) override;
    int32_t Release() override;

private:
    OHOS::sptr<IOfflineStreamOperatorVdi> offlineStreamOperatorVdi_;
};
} // namespace OHOS::Camera
#endif // HOS_CAMERA_OFFLINE_STREAM_OPERATOR_SERVICE_H
