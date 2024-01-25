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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMPROXY_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMPROXY_H

#include "v1_0/imedia_key_system.h"
#include <iproxy_broker.h>

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

class MediaKeySystemProxy : public IProxyBroker<OHOS::HDI::Drm::V1_0::IMediaKeySystem> {
public:
    explicit MediaKeySystemProxy(const sptr<IRemoteObject>& remote) : IProxyBroker<OHOS::HDI::Drm::V1_0::IMediaKeySystem>(remote) {}

    virtual ~MediaKeySystemProxy() = default;

    inline bool IsProxy() override
    {
        return true;
    }

    int32_t GetConfigurationString(const std::string& name, std::string& value) override;

    int32_t SetConfigurationString(const std::string& name, const std::string& value) override;

    int32_t GetConfigurationByteArray(const std::string& name, std::vector<uint8_t>& value) override;

    int32_t SetConfigurationByteArray(const std::string& name, const std::vector<uint8_t>& value) override;

    int32_t GetStatistics(std::map<std::string, std::string>& statistics) override;

    int32_t GetMaxContentProtectionLevel(OHOS::HDI::Drm::V1_0::ContentProtectionLevel& level) override;

    int32_t GenerateKeySystemRequest(std::string& defaultUrl, std::vector<uint8_t>& request) override;

    int32_t ProcessKeySystemResponse(const std::vector<uint8_t>& response) override;

    int32_t GetOemCertificateStatus(OHOS::HDI::Drm::V1_0::CertificateStatus& status) override;

    int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemCallback>& systemCallback) override;

    int32_t CreateMediaKeySession(OHOS::HDI::Drm::V1_0::ContentProtectionLevel level,
         sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession>& keySession) override;

    int32_t GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>>& mediaKeyIds) override;

    int32_t GetOfflineMediaKeyStatus(const std::vector<uint8_t>& mediaKeyId,
         OHOS::HDI::Drm::V1_0::OfflineMediaKeyStatus& mediaKeyStatus) override;

    int32_t ClearOfflineMediaKeys(const std::vector<uint8_t>& mediaKeyId) override;

    int32_t GetOemCertificate(sptr<OHOS::HDI::Drm::V1_0::IOemCertificate>& oemCert) override;

    int32_t Destroy() override;

    int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer) override;

    static int32_t GetConfigurationString_(const std::string& name, std::string& value,
         const sptr<IRemoteObject> remote);

    static int32_t SetConfigurationString_(const std::string& name, const std::string& value,
         const sptr<IRemoteObject> remote);

    static int32_t GetConfigurationByteArray_(const std::string& name, std::vector<uint8_t>& value,
         const sptr<IRemoteObject> remote);

    static int32_t SetConfigurationByteArray_(const std::string& name, const std::vector<uint8_t>& value,
         const sptr<IRemoteObject> remote);

    static int32_t GetStatistics_(std::map<std::string, std::string>& statistics, const sptr<IRemoteObject> remote);

    static int32_t GetMaxContentProtectionLevel_(OHOS::HDI::Drm::V1_0::ContentProtectionLevel& level,
         const sptr<IRemoteObject> remote);

    static int32_t GenerateKeySystemRequest_(std::string& defaultUrl, std::vector<uint8_t>& request,
         const sptr<IRemoteObject> remote);

    static int32_t ProcessKeySystemResponse_(const std::vector<uint8_t>& response, const sptr<IRemoteObject> remote);

    static int32_t GetOemCertificateStatus_(OHOS::HDI::Drm::V1_0::CertificateStatus& status,
         const sptr<IRemoteObject> remote);

    static int32_t SetCallback_(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemCallback>& systemCallback,
         const sptr<IRemoteObject> remote);

    static int32_t CreateMediaKeySession_(OHOS::HDI::Drm::V1_0::ContentProtectionLevel level,
         sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession>& keySession, const sptr<IRemoteObject> remote);

    static int32_t GetOfflineMediaKeyIds_(std::vector<std::vector<uint8_t>>& mediaKeyIds,
         const sptr<IRemoteObject> remote);

    static int32_t GetOfflineMediaKeyStatus_(const std::vector<uint8_t>& mediaKeyId,
         OHOS::HDI::Drm::V1_0::OfflineMediaKeyStatus& mediaKeyStatus, const sptr<IRemoteObject> remote);

    static int32_t ClearOfflineMediaKeys_(const std::vector<uint8_t>& mediaKeyId, const sptr<IRemoteObject> remote);

    static int32_t GetOemCertificate_(sptr<OHOS::HDI::Drm::V1_0::IOemCertificate>& oemCert,
         const sptr<IRemoteObject> remote);

    static int32_t Destroy_(const sptr<IRemoteObject> remote);

    static int32_t GetVersion_(uint32_t& majorVer, uint32_t& minorVer, const sptr<IRemoteObject> remote);

private:
    static inline BrokerDelegator<OHOS::HDI::Drm::V1_0::MediaKeySystemProxy> delegator_;
};

} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMPROXY_H