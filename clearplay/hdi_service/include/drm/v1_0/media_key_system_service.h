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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMSERVICE_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMSERVICE_H

#include "v1_0/imedia_key_system.h"
#include "v1_0/media_key_session_service.h"
#include "media_key_system_callback_service.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
class MediaKeySystemServiceCallback;
class MediaKeySystemService : public OHOS::HDI::Drm::V1_0::IMediaKeySystem, public KeySessionServiceCallback {
public:
    MediaKeySystemService() = default;
    virtual ~MediaKeySystemService();

    int32_t GetConfigurationString(const std::string& name, std::string& value) override;

    int32_t SetConfigurationString(const std::string& name, const std::string& value) override;

    int32_t GetConfigurationByteArray(const std::string& name, std::vector<uint8_t>& value) override;

    int32_t SetConfigurationByteArray(const std::string& name, const std::vector<uint8_t>& value) override;

    int32_t GetStatistics(std::map<std::string, std::string>& statistics) override;

    int32_t GetMaxContentProtectionLevel(ContentProtectionLevel& level) override;

    int32_t GenerateKeySystemRequest(std::string& defaultUrl, std::vector<uint8_t>& request) override;

    int32_t ProcessKeySystemResponse(const std::vector<uint8_t>& response) override;

    int32_t GetOemCertificateStatus(CertificateStatus& status) override;

    int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemCallback>& systemCallback) override;

    int32_t CreateMediaKeySession(ContentProtectionLevel level,
         sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession>& keySession) override;

    int32_t GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>>& mediaKeyIds) override;

    int32_t GetOfflineMediaKeyStatus(const std::vector<uint8_t>& mediaKeyId,
         OfflineMediaKeyStatus& mediaKeyStatus) override;

    int32_t ClearOfflineMediaKeys(const std::vector<uint8_t>& mediaKeyId) override;

    int32_t GetOemCertificate(sptr<OHOS::HDI::Drm::V1_0::IOemCertificate>& oemCert) override;

    int32_t Destroy() override;

    int32_t SetKeySystemServiceCallback(sptr<MediaKeySystemServiceCallback> callback);
    int32_t CloseKeySessionService(sptr<MediaKeySessionService> mediaKeySession) override;
    void GetDecryptTimeAsString(std::vector<std::vector<double>> &topThreeTimes,
        std::string &decryptTimes);

private:
    int32_t GetOfflineKeyFromFile();
    int32_t SetOfflineKeyToFile();
    static void GetDecryptMaxTimes(double time, std::vector<double> &topThreeTimes);
    std::map<std::string, std::vector<uint8_t>> configuration_;
    std::map<std::string, std::string> configurationString_;
    std::map<sptr<MediaKeySessionService>, bool> mediaKeySessionMap_;
    std::mutex mediaKeySessionMutex_;
    sptr<MediaKeySystemServiceCallback> systemCallback_;
    std::mutex offlineKeyMutex_;
    std::map<std::string, std::string> offlineKeyIdAndKeyValueBase64_;
    const char* offlineKeyFileName = "/data/local/traces/offline_key.txt";
    const int keyIdMaxLength = 255;
    const std::string currentSessionNumName = "currentSessionNum";
    const std::string versionName = "version";
    const std::string decryptNumberName = "decryptNumber";
    const std::string errorDecryptNumberName = "errorDecryptNumber";
    const std::string decryptTime = "maxDecryptTimes";
    OHOS::sptr<MediaKeySystemCallbackService> vdiCallbackObj;
};
class MediaKeySystemServiceCallback : public virtual RefBase {
public:
    MediaKeySystemServiceCallback() = default;
    virtual ~MediaKeySystemServiceCallback() = default;
    virtual int32_t CloseMediaKeySystemService(sptr<MediaKeySystemService> mediaKeySystem) = 0;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMSERVICE_H