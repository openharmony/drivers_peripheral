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

#ifndef OHOS_HDI_DRM_V1_0_OEMCERTIFICATEPROXY_H
#define OHOS_HDI_DRM_V1_0_OEMCERTIFICATEPROXY_H

#include "v1_0/ioem_certificate.h"
#include <iproxy_broker.h>

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

class OemCertificateProxy : public IProxyBroker<OHOS::HDI::Drm::V1_0::IOemCertificate> {
public:
    explicit OemCertificateProxy(const sptr<IRemoteObject>& remote) : IProxyBroker<OHOS::HDI::Drm::V1_0::IOemCertificate>(remote) {}

    virtual ~OemCertificateProxy() = default;

    inline bool IsProxy() override
    {
        return true;
    }

    int32_t GenerateOemKeySystemRequest(std::string& defaultUrl, std::vector<uint8_t>& request) override;

    int32_t ProcessOemKeySystemResponse(const std::vector<uint8_t>& response) override;

    int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer) override;

    static int32_t GenerateOemKeySystemRequest_(std::string& defaultUrl, std::vector<uint8_t>& request,
         const sptr<IRemoteObject> remote);

    static int32_t ProcessOemKeySystemResponse_(const std::vector<uint8_t>& response, const sptr<IRemoteObject> remote);

    static int32_t GetVersion_(uint32_t& majorVer, uint32_t& minorVer, const sptr<IRemoteObject> remote);

private:
    static inline BrokerDelegator<OHOS::HDI::Drm::V1_0::OemCertificateProxy> delegator_;
};

} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_OEMCERTIFICATEPROXY_H