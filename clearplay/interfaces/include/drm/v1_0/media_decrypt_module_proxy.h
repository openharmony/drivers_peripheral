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

#ifndef OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULEPROXY_H
#define OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULEPROXY_H

#include "v1_0/imedia_decrypt_module.h"
#include <iproxy_broker.h>

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

class MediaDecryptModuleProxy : public IProxyBroker<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> {
public:
    explicit MediaDecryptModuleProxy(const sptr<IRemoteObject>& remote) : IProxyBroker<OHOS::HDI::Drm::V1_0::IMediaDecryptModule>(remote) {}

    virtual ~MediaDecryptModuleProxy() = default;

    inline bool IsProxy() override
    {
        return true;
    }

    int32_t DecryptMediaData(bool secure, const OHOS::HDI::Drm::V1_0::CryptoInfo& cryptoInfo,
         const OHOS::HDI::Drm::V1_0::DrmBuffer& srcBuffer, const OHOS::HDI::Drm::V1_0::DrmBuffer& destBuffer) override;

    int32_t Release() override;

    int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer) override;

    static int32_t DecryptMediaData_(bool secure, const OHOS::HDI::Drm::V1_0::CryptoInfo& cryptoInfo,
         const OHOS::HDI::Drm::V1_0::DrmBuffer& srcBuffer, const OHOS::HDI::Drm::V1_0::DrmBuffer& destBuffer, const sptr<IRemoteObject> remote);

    static int32_t Release_(const sptr<IRemoteObject> remote);

    static int32_t GetVersion_(uint32_t& majorVer, uint32_t& minorVer, const sptr<IRemoteObject> remote);

private:
    static inline BrokerDelegator<OHOS::HDI::Drm::V1_0::MediaDecryptModuleProxy> delegator_;
};

} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIADECRYPTMODULEPROXY_H