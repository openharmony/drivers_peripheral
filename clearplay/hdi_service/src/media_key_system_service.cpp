/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <hdf_base.h>
#include <hdf_log.h>
#include "v1_0/media_key_system_service.h"
#include "v1_0/media_key_session_service.h"
#include "base64_utils.h"
#include "data_parser.h"
#include "securec.h"

#define HDF_LOG_TAG media_key_system_service

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
MediaKeySystemService::~MediaKeySystemService()
{
    HDF_LOGI("%{public}s: start", __func__);
    mediaKeySessionMutex_.lock();
    while (mediaKeySessionMap_.size() > 0) {
        sptr<OHOS::HDI::Drm::V1_0::MediaKeySessionService> keySession = mediaKeySessionMap_.begin()->first;
        mediaKeySessionMutex_.unlock();
        CloseKeySessionService(keySession);
        mediaKeySessionMutex_.lock();
    }
    mediaKeySessionMutex_.unlock();
    HDF_LOGI("%{public}s: end", __func__);
}

int32_t MediaKeySystemService::GetConfigurationString(const std::string &name, std::string &value)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (configurationString_.find(name) == configurationString_.end()) {
        HDF_LOGE("%{public}s: do not find value, name: %{public}s", __func__, name.c_str());
        return HDF_ERR_INVALID_PARAM;
    }
    value = configurationString_[name];
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::SetConfigurationString(const std::string &name, const std::string &value)
{
    HDF_LOGI("%{public}s: start", __func__);
    configurationString_[name] = value;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::GetConfigurationByteArray(const std::string &name, std::vector<uint8_t> &value)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (configuration_.find(name) == configuration_.end()) {
        HDF_LOGE("%{public}s: do not find value, name: %{public}s", __func__, name.c_str());
        return HDF_ERR_INVALID_PARAM;
    }
    value = configuration_[name];
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::SetConfigurationByteArray(const std::string &name, const std::vector<uint8_t> &value)
{
    HDF_LOGI("%{public}s: start", __func__);
    configuration_[name] = value;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

void MediaKeySystemService::GetDecryptTimeAsString(std::vector<std::vector<double>> &topThreeTimes,
    std::string &decryptTimes)
{
    for (auto &time : topThreeTimes) {
        if (!decryptTimes.empty()) {
            decryptTimes.append(";");
        }
        for (auto it = time.begin(); it != time.end(); ++it) {
            if (it != time.begin()) {
                decryptTimes.append(",");
            }
            decryptTimes.append(std::to_string(*it));
        }
    }
}

int32_t MediaKeySystemService::GetStatistics(std::map<std::string, std::string> &statistics)
{
    HDF_LOGI("%{public}s: start", __func__);
    mediaKeySessionMutex_.lock();
    int sessionNum = mediaKeySessionMap_.size();
    int decryptNumber = 0;
    int errorDecryptNumber = 0;
    std::vector<std::vector<double>> topThreeTimes;
    std::string decryptTimes;
    for (auto &pair : mediaKeySessionMap_) {
        decryptNumber += pair.first->GetDecryptNumber();
        errorDecryptNumber += pair.first->GetErrorDecryptNumber();
        std::vector<double> topThreeTime;
        pair.first->GetDecryptTimes(topThreeTime);
        topThreeTimes.push_back(topThreeTime);
    }
    GetDecryptTimeAsString(topThreeTimes, decryptTimes);
    mediaKeySessionMutex_.unlock();

    statistics[versionName] = "clearplay";
    statistics[currentSessionNumName] = std::to_string(sessionNum);
    statistics[decryptNumberName] = std::to_string(decryptNumber);
    statistics[errorDecryptNumberName] = std::to_string(errorDecryptNumber);
    statistics[decryptTime] = decryptTimes;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::GetMaxContentProtectionLevel(ContentProtectionLevel &level)
{
    HDF_LOGI("%{public}s: start", __func__);

    level = OHOS::HDI::Drm::V1_0::ContentProtectionLevel::SW_SECURE_CRYPTO;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::GenerateKeySystemRequest(std::string &defaultUrl, std::vector<uint8_t> &request)
{
    HDF_LOGI("%{public}s: start", __func__);
    defaultUrl = "http://default.com";
    std::string requestData = "{\"signedRequest\":\"KEYREQUESTTYPE_DOWNLOADCERT\"}";
    size_t requestDataLen = requestData.size();
    request.assign(requestData.c_str(), requestData.c_str() + requestDataLen);
    if (vdiCallbackObj != nullptr) {
        std::string eventData = "PROVISIONRE QUIRED";
        std::vector<uint8_t> data(eventData.begin(), eventData.end());
        vdiCallbackObj->SendEvent(EVENTTYPE_PROVISIONREQUIRED, 0, data);
    }
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::ProcessKeySystemResponse(const std::vector<uint8_t> &response)
{
    HDF_LOGI("%{public}s: start", __func__);
    std::string responseData(response.begin(), response.end());
    HDF_LOGI("%{public}s: response: %{public}s", __func__, responseData.c_str());
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::CreateMediaKeySession(ContentProtectionLevel level,
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> &keySession)
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: start, level: %d", __func__, level);
    sptr<MediaKeySessionService> keySessionService = nullptr;
    keySessionService = new (std::nothrow) MediaKeySessionService(level);
    if (keySessionService == nullptr) {
        HDF_LOGE("MediaKeySystemService::CreateKeySession allocation failed");
        return HDF_ERR_MALLOC_FAIL;
    }
    if (keySessionService->Init() != HDF_SUCCESS) {
        HDF_LOGE("keySessionService::Init() failed");
        delete keySessionService;
        return HDF_ERR_MALLOC_FAIL;
    }
    keySessionService->SetKeySessionServiceCallback(this);
    mediaKeySessionMutex_.lock();
    mediaKeySessionMap_[keySessionService] = true;
    mediaKeySessionMutex_.unlock();
    keySession = keySessionService;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>> &licenseIds)
{
    HDF_LOGI("%{public}s: start", __func__);
    offlineKeyMutex_.lock();
    int32_t ret = GetOfflineKeyFromFile();
    if (ret != HDF_SUCCESS) {
        offlineKeyMutex_.unlock();
        return ret;
    }
    for (auto &keyIdValueBase64Pair : offlineKeyIdAndKeyValueBase64_) {
        std::string keyIdString = Decode(keyIdValueBase64Pair.first);
        std::vector<uint8_t> keyId(keyIdString.begin(), keyIdString.end());
        licenseIds.push_back(keyId);
    }
    offlineKeyIdAndKeyValueBase64_.clear();
    offlineKeyMutex_.unlock();
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::GetOfflineMediaKeyStatus(const std::vector<uint8_t> &licenseId,
    OfflineMediaKeyStatus &licenseStatus)
{
    HDF_LOGI("%{public}s: start", __func__);
    offlineKeyMutex_.lock();
    std::string keyIdString(licenseId.begin(), licenseId.end());
    std::string keyIdBase64 = Encode(keyIdString);
    int32_t ret = GetOfflineKeyFromFile();
    if (ret != HDF_SUCCESS) {
        offlineKeyMutex_.unlock();
        return HDF_FAILURE;
    }
    keyIdBase64.erase(std::remove(keyIdBase64.begin(), keyIdBase64.end(), '\0'), keyIdBase64.end());
    if (offlineKeyIdAndKeyValueBase64_.find(keyIdBase64) == offlineKeyIdAndKeyValueBase64_.end()) {
        offlineKeyMutex_.unlock();
        return HDF_FAILURE;
    }
    for (auto it = mediaKeySessionMap_.begin(); it != mediaKeySessionMap_.end(); ++it) {
        if (it->second == false) {
            continue;
        }
        licenseStatus = it->first->session_->keyIdStatusMap[licenseId];
    }
    offlineKeyMutex_.unlock();
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::ClearOfflineMediaKeys(const std::vector<uint8_t> &licenseId)
{
    HDF_LOGI("%{public}s: start", __func__);
    offlineKeyMutex_.lock();
    int32_t ret = GetOfflineKeyFromFile();
    if (ret != HDF_SUCCESS) {
        offlineKeyMutex_.unlock();
        return ret;
    }
    std::string keyIdString(licenseId.begin(), licenseId.end());
    std::string keyIdBase64 = Encode(keyIdString);
    auto it = offlineKeyIdAndKeyValueBase64_.find(keyIdBase64);
    if (it != offlineKeyIdAndKeyValueBase64_.end()) {
        offlineKeyIdAndKeyValueBase64_.erase(it);
        ret = SetOfflineKeyToFile();
        if (ret != HDF_SUCCESS) {
            offlineKeyMutex_.unlock();
            return ret;
        }
        for (auto it = mediaKeySessionMap_.begin(); it != mediaKeySessionMap_.end(); ++it) {
            if (it->second == false) {
                continue;
            }
            it->first->session_->keyIdStatusMap[licenseId] = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
        }
        offlineKeyMutex_.unlock();
        HDF_LOGI("%{public}s: end", __func__);
        return HDF_SUCCESS;
    }
    offlineKeyMutex_.unlock();
    HDF_LOGI("%{public}s: do not find offline license, keyId: %{public}s", __func__, licenseId.data());
    return HDF_FAILURE;
}

int32_t MediaKeySystemService::GetOemCertificate(sptr<OHOS::HDI::Drm::V1_0::IOemCertificate> &oemCert)
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::GetOemCertificateStatus(CertificateStatus &status)
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemCallback> &systemCallback)
{
    vdiCallbackObj = new (std::nothrow) MediaKeySystemCallbackService(systemCallback);
    if (vdiCallbackObj == nullptr) {
        HDF_LOGE("new MediaKeySystemCallbackService() failed");
        return HDF_ERR_MALLOC_FAIL;
    }
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::Destroy()
{
    HDF_LOGI("%{public}s: start", __func__);
    if (systemCallback_ != nullptr) {
        systemCallback_->CloseMediaKeySystemService(this);
    }
    systemCallback_ = nullptr;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::CloseKeySessionService(sptr<MediaKeySessionService> mediaKeySession)
{
    HDF_LOGI("%{public}s: start", __func__);
    mediaKeySessionMutex_.lock();
    auto it = mediaKeySessionMap_.find(mediaKeySession);
    if (it == mediaKeySessionMap_.end()) {
        mediaKeySessionMutex_.unlock();
        return HDF_FAILURE;
    }
    mediaKeySessionMap_.erase(it);
    mediaKeySessionMutex_.unlock();
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::SetKeySystemServiceCallback(sptr<MediaKeySystemServiceCallback> callback)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (callback == nullptr) {
        HDF_LOGE("MediaKeySystemServiceCallback callback is null");
        return HDF_ERR_INVALID_PARAM;
    }
    systemCallback_ = callback;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::GetOfflineKeyFromFile()
{
    HDF_LOGI("%{public}s: start", __func__);
    FILE *offlineKeyFile = fopen(offlineKeyFileName, "r+");
    if (offlineKeyFile == NULL) {
        HDF_LOGE("%{public}s: open: \"%{public}s\" failed", __func__, offlineKeyFileName);
        // file do not exist, is allright
        return HDF_SUCCESS;
    }
    char keyIdBase64Chars[keyIdMaxLength];
    char keyValueBase64Chars[keyIdMaxLength];
    while (fscanf_s(offlineKeyFile, "%s %s", keyIdBase64Chars, sizeof(keyIdBase64Chars), keyValueBase64Chars, sizeof(keyValueBase64Chars)) != EOF) {
        std::string tempKeyIdBase64 = keyIdBase64Chars;
        std::string tempKeyValueBase64 = keyValueBase64Chars;
        tempKeyIdBase64.erase(std::remove(tempKeyIdBase64.begin(), tempKeyIdBase64.end(), '\0'), tempKeyIdBase64.end());
        offlineKeyIdAndKeyValueBase64_[tempKeyIdBase64] = tempKeyValueBase64;
    }
    fclose(offlineKeyFile);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySystemService::SetOfflineKeyToFile()
{
    HDF_LOGI("%{public}s: start", __func__);
    FILE *offlineKeyFile = fopen(offlineKeyFileName, "w+");
    if (offlineKeyFile == NULL) {
        offlineKeyIdAndKeyValueBase64_.clear();
        HDF_LOGE("%{public}s: create failed, ret: %{public}s", __func__, strerror(errno));
        return HDF_FAILURE;
    }
    for (auto &keyIdValueBase64Pair : offlineKeyIdAndKeyValueBase64_) {
        fprintf(offlineKeyFile, "%s %s\n", keyIdValueBase64Pair.first.c_str(), keyIdValueBase64Pair.second.c_str());
    }
    offlineKeyIdAndKeyValueBase64_.clear();
    fclose(offlineKeyFile);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}
} // V1_0
} // Drm
} // HDI
} // OHOS
