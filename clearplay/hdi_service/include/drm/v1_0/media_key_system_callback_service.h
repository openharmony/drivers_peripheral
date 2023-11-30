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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMCALLBACKSERVICE_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMCALLBACKSERVICE_H

#include "v1_0/imedia_key_system_callback.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
class MediaKeySystemCallbackService : public OHOS::HDI::Drm::V1_0::IMediaKeySystemCallback {
public:
    MediaKeySystemCallbackService(OHOS::sptr<IMediaKeySystemCallback> callback);

    virtual ~MediaKeySystemCallbackService() = default;

    int32_t SendEvent(EventType eventType, int32_t extra, const std::vector<uint8_t>& data) override;
private:
    OHOS::sptr<IMediaKeySystemCallback> keySystemCallback_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMCALLBACKSERVICE_H