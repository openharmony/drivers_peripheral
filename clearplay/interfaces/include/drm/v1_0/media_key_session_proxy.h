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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONPROXY_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONPROXY_H

#include "v1_0/imedia_key_session.h"
#include <iproxy_broker.h>

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

class MediaKeySessionProxy : public IProxyBroker<OHOS::HDI::Drm::V1_0::IMediaKeySession> {
public:
    explicit MediaKeySessionProxy(const sptr<IRemoteObject>& remote) : IProxyBroker<OHOS::HDI::Drm::V1_0::IMediaKeySession>(remote) {}

    virtual ~MediaKeySessionProxy() = default;

    inline bool IsProxy() override
    {
        return true;
    }

    int32_t GenerateLicenseRequest(const LicenseRequestInfo& licenseRequestInfo,
         LicenseRequest& licenseRequest) override;

    int32_t ProcessLicenseResponse(const std::vector<uint8_t>& licenseResponse,
         std::vector<uint8_t>& licenseId) override;

    int32_t CheckLicenseStatus(std::vector<LicenseStatusString>& licenseStatus) override;

    int32_t RemoveLicense() override;

    int32_t GetOfflineReleaseRequest(const std::vector<uint8_t>& licenseId,
         std::vector<uint8_t>& releaseRequest) override;

    int32_t ProcessOfflineReleaseResponse(const std::vector<uint8_t>& licenseId,
         const std::vector<uint8_t>& response) override;

    int32_t RestoreOfflineLicense(const std::vector<uint8_t>& licenseId) override;

    int32_t GetSecurityLevel(SecurityLevel& level) override;

    int32_t RequiresSecureDecoderModule(const std::string& mimeType, bool& required) override;

    int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback>& sessionCallback) override;

    int32_t GetMediaDecryptModule(sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule>& decryptModule) override;

    int32_t Destroy() override;

    int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer) override;

    static int32_t GenerateLicenseRequest_(const LicenseRequestInfo& licenseRequestInfo, LicenseRequest& licenseRequest,
         const sptr<IRemoteObject> remote);

    static int32_t ProcessLicenseResponse_(const std::vector<uint8_t>& licenseResponse, std::vector<uint8_t>& licenseId,
         const sptr<IRemoteObject> remote);

    static int32_t CheckLicenseStatus_(std::vector<LicenseStatusString>& licenseStatus,
         const sptr<IRemoteObject> remote);

    static int32_t RemoveLicense_(const sptr<IRemoteObject> remote);

    static int32_t GetOfflineReleaseRequest_(const std::vector<uint8_t>& licenseId,
         std::vector<uint8_t>& releaseRequest, const sptr<IRemoteObject> remote);

    static int32_t ProcessOfflineReleaseResponse_(const std::vector<uint8_t>& licenseId,
         const std::vector<uint8_t>& response, const sptr<IRemoteObject> remote);

    static int32_t RestoreOfflineLicense_(const std::vector<uint8_t>& licenseId, const sptr<IRemoteObject> remote);

    static int32_t GetSecurityLevel_(SecurityLevel& level, const sptr<IRemoteObject> remote);

    static int32_t RequiresSecureDecoderModule_(const std::string& mimeType, bool& required,
         const sptr<IRemoteObject> remote);

    static int32_t SetCallback_(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback>& sessionCallback,
         const sptr<IRemoteObject> remote);

    static int32_t GetMediaDecryptModule_(sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule>& decryptModule,
         const sptr<IRemoteObject> remote);

    static int32_t Destroy_(const sptr<IRemoteObject> remote);

    static int32_t GetVersion_(uint32_t& majorVer, uint32_t& minorVer, const sptr<IRemoteObject> remote);

private:
    static inline BrokerDelegator<OHOS::HDI::Drm::V1_0::MediaKeySessionProxy> delegator_;
};

} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONPROXY_H