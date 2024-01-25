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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONCALLBACKPROXY_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONCALLBACKPROXY_H

#include "v1_0/imedia_key_session_callback.h"
#include <iproxy_broker.h>

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

class MediaKeySessionCallbackProxy : public IProxyBroker<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback> {
public:
    explicit MediaKeySessionCallbackProxy(const sptr<IRemoteObject>& remote) : IProxyBroker<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback>(remote) {}

    virtual ~MediaKeySessionCallbackProxy() = default;

    inline bool IsProxy() override
    {
        return true;
    }

    int32_t SendEvent(OHOS::HDI::Drm::V1_0::EventType eventType, int32_t extra,
         const std::vector<uint8_t>& data) override;

    int32_t SendEventKeyChange(const std::map<std::vector<uint8_t>,
         OHOS::HDI::Drm::V1_0::MediaKeySessionKeyStatus>& keyStatus, bool newKeysAvailable) override;

    int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer) override;

    static int32_t SendEvent_(OHOS::HDI::Drm::V1_0::EventType eventType, int32_t extra,
         const std::vector<uint8_t>& data, const sptr<IRemoteObject> remote);

    static int32_t SendEventKeyChange_(const std::map<std::vector<uint8_t>,
         OHOS::HDI::Drm::V1_0::MediaKeySessionKeyStatus>& keyStatus, bool newKeysAvailable, const sptr<IRemoteObject> remote);

    static int32_t GetVersion_(uint32_t& majorVer, uint32_t& minorVer, const sptr<IRemoteObject> remote);

private:
    static inline BrokerDelegator<OHOS::HDI::Drm::V1_0::MediaKeySessionCallbackProxy> delegator_;
};

} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONCALLBACKPROXY_H