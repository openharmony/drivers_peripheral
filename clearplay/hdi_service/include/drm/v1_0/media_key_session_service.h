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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONSERVICE_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONSERVICE_H

#include "v1_0/imedia_key_session.h"
#include "v1_0/media_decrypt_module_service.h"
#include "v1_0/media_key_session_callback_service.h"
#include "v1_0/media_key_system_types.h"
#include "media_key_session_callback_service.h"
#include "session.h"
#include <mutex>
#include <map>
#include <sys/stat.h>
#include <sys/types.h>

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
class KeySessionServiceCallback;
class MediaKeySessionService : public OHOS::HDI::Drm::V1_0::IMediaKeySession {
public:
    MediaKeySessionService();
    MediaKeySessionService(ContentProtectionLevel level);
    virtual ~MediaKeySessionService() = default;

    int32_t GenerateMediaKeyRequest(const MediaKeyRequestInfo& mediaKeyRequestInfo,
         MediaKeyRequest& mediaKeyRequest) override;

    int32_t ProcessMediaKeyResponse(const std::vector<uint8_t>& mediaKeyResponse,
         std::vector<uint8_t>& mediaKeyId) override;

    int32_t CheckMediaKeyStatus(std::map<std::string, std::string>& mediaKeyStatus) override;

    int32_t ClearMediaKeys() override;

    int32_t GetOfflineReleaseRequest(const std::vector<uint8_t>& mediaKeyId,
         std::vector<uint8_t>& releaseRequest) override;

    int32_t ProcessOfflineReleaseResponse(const std::vector<uint8_t>& mediaKeyId,
         const std::vector<uint8_t>& response) override;

    int32_t RestoreOfflineMediaKeys(const std::vector<uint8_t>& mediaKeyId) override;

    int32_t GetContentProtectionLevel(ContentProtectionLevel& level) override;

    int32_t RequiresSecureDecoderModule(const std::string& mimeType, bool& required) override;

    int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback>& sessionCallback) override;

    int32_t GetMediaDecryptModule(sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule>& decryptModule) override;

    int32_t Destroy() override;

    int32_t Init();
    int32_t GetDecryptNumber();
    int32_t GetErrorDecryptNumber();
    int32_t GetDecryptTimes(std::vector<double> &times);
    void GetDecryptMaxTimes(double time, std::vector<double> &topThreeTimes);
    int32_t SetKeySessionServiceCallback(sptr<KeySessionServiceCallback> callback);
    sptr<Session> session_;
private:
    int32_t GetOfflineKeyFromFile();
    int32_t SetOfflineKeyToFile();
    ContentProtectionLevel level_;
    sptr<OHOS::HDI::Drm::V1_0::MediaDecryptModuleService> decryptModule_;
    sptr<KeySessionServiceCallback> sessionCallback_;
    std::mutex offlineKeyMutex_;
    std::map<std::string, std::string> offlineKeyIdAndKeyValueBase64_;
    const char* offlineKeyFileName = "/data/local/traces/offline_key.txt";
    const int keyIdMaxLength = 255;
    OHOS::sptr<MediaKeySessionCallbackService> vdiCallbackObj;
    static const int32_t topThree = 3;
};
class KeySessionServiceCallback : public virtual RefBase {
public:
    KeySessionServiceCallback() = default;
    virtual ~KeySessionServiceCallback() = default;
    virtual int32_t CloseKeySessionService(sptr<MediaKeySessionService> mediaKeySession) = 0;
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSESSIONSERVICE_H