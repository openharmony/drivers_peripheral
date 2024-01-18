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

    int32_t GenerateMediaKeyRequest(const OHOS::HDI::Drm::V1_0::MediaKeyRequestInfo& mediaKeyRequestInfo,
         OHOS::HDI::Drm::V1_0::MediaKeyRequest& mediaKeyRequest) override;

    int32_t ProcessMediaKeyResponse(const std::vector<uint8_t>& mediaKeyResponse,
         std::vector<uint8_t>& mediaKeyId) override;

    int32_t CheckMediaKeyStatus(std::map<std::string, std::string>& mediaKeyStatus) override;

    int32_t ClearMediaKeys() override;

    int32_t GetOfflineReleaseRequest(const std::vector<uint8_t>& mediaKeyId,
         std::vector<uint8_t>& releaseRequest) override;

    int32_t ProcessOfflineReleaseResponse(const std::vector<uint8_t>& mediaKeyId,
         const std::vector<uint8_t>& response) override;

    int32_t RestoreOfflineMediaKeys(const std::vector<uint8_t>& mediaKeyId) override;

    int32_t GetContentProtectionLevel(OHOS::HDI::Drm::V1_0::ContentProtectionLevel& level) override;

    int32_t RequiresSecureDecoderModule(const std::string& mimeType, bool& required) override;

    int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback>& sessionCallback) override;

    int32_t GetMediaDecryptModule(sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule>& decryptModule) override;

    int32_t Destroy() override;

    int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer) override;

    static int32_t GenerateMediaKeyRequest_(const OHOS::HDI::Drm::V1_0::MediaKeyRequestInfo& mediaKeyRequestInfo,
         OHOS::HDI::Drm::V1_0::MediaKeyRequest& mediaKeyRequest, const sptr<IRemoteObject> remote);

    static int32_t ProcessMediaKeyResponse_(const std::vector<uint8_t>& mediaKeyResponse,
         std::vector<uint8_t>& mediaKeyId, const sptr<IRemoteObject> remote);

    static int32_t CheckMediaKeyStatus_(std::map<std::string, std::string>& mediaKeyStatus,
         const sptr<IRemoteObject> remote);

    static int32_t ClearMediaKeys_(const sptr<IRemoteObject> remote);

    static int32_t GetOfflineReleaseRequest_(const std::vector<uint8_t>& mediaKeyId,
         std::vector<uint8_t>& releaseRequest, const sptr<IRemoteObject> remote);

    static int32_t ProcessOfflineReleaseResponse_(const std::vector<uint8_t>& mediaKeyId,
         const std::vector<uint8_t>& response, const sptr<IRemoteObject> remote);

    static int32_t RestoreOfflineMediaKeys_(const std::vector<uint8_t>& mediaKeyId, const sptr<IRemoteObject> remote);

    static int32_t GetContentProtectionLevel_(OHOS::HDI::Drm::V1_0::ContentProtectionLevel& level,
         const sptr<IRemoteObject> remote);

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