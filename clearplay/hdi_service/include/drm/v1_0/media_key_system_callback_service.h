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

#include <mutex>
#include "v1_0/imedia_key_system_callback.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
class MediaKeySystemCallbackService : public OHOS::HDI::Drm::V1_0::IMediaKeySystemCallback {
public:
    MediaKeySystemCallbackService(OHOS::sptr<IMediaKeySystemCallback> callback);

    virtual ~MediaKeySystemCallbackService();

    int32_t SendEvent(EventType eventType, int32_t extra, const std::vector<uint8_t>& data) override;

    void OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object);

private:
    OHOS::sptr<IMediaKeySystemCallback> keySystemCallback_;
    OHOS::sptr<OHOS::IRemoteObject::DeathRecipient> deathRecipient_;
    std::mutex callbackMutex_;
};

class KeySystemCallbackDeathRecipient : public OHOS::IRemoteObject::DeathRecipient {
public:
    explicit KeySystemCallbackDeathRecipient(const OHOS::wptr<MediaKeySystemCallbackService> &callbackService)
        : callbackService_(callbackService)
    {}

    virtual ~KeySystemCallbackDeathRecipient() = default;

    void OnRemoteDied(const OHOS::wptr<OHOS::IRemoteObject> &object) override
    {
        OHOS::sptr<MediaKeySystemCallbackService> callbackService = callbackService_.promote();
        if (callbackService == nullptr) {
            return;
        }
        callbackService->OnRemoteDied(object);
    }

private:
    OHOS::wptr<MediaKeySystemCallbackService> callbackService_;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMCALLBACKSERVICE_H