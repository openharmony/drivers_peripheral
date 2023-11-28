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

#include "v1_0/media_key_session_service.h"
#include "v1_0/media_key_system_types.h"
#include "v1_0/media_decrypt_module_service.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include "base64_utils.h"
#include "data_parser.h"
#include "securec.h"

#define HDF_LOG_TAG media_key_session_service

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
MediaKeySessionService::MediaKeySessionService()
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
}

MediaKeySessionService::MediaKeySessionService(SecurityLevel level)
{
    HDF_LOGI("%{public}s: start", __func__);
    level_ = level;
    HDF_LOGI("%{public}s: end", __func__);
}

int32_t MediaKeySessionService::GenerateLicenseRequest(const LicenseRequestInfo &licenseRequestInfo,
    LicenseRequest &licenseRequest)
{
    HDF_LOGI("%{public}s: start", __func__);
    licenseRequest.requestType = REQUEST_TYPE_INITIAL;
    licenseRequest.mDefaultUrl = "http://default.com";
    HDF_LOGI("%{public}s: end", __func__);
    return session_->getKeyRequest(licenseRequestInfo.initData, licenseRequestInfo.mimeType,
        licenseRequestInfo.licenseType, licenseRequestInfo.optionalData, &licenseRequest.mData);
}

int32_t MediaKeySessionService::ProcessLicenseResponse(const std::vector<uint8_t> &licenseResponse,
    std::vector<uint8_t> &licenseId)
{
    HDF_LOGI("%{public}s: start", __func__);
    licenseId.clear();
    size_t commaPos = 0;
    std::vector<std::vector<uint8_t>> keyIdAndValuePairs;
    for (size_t i = 0; i < licenseResponse.size(); i++) {
        if (licenseResponse[i] == ',') {
            keyIdAndValuePairs.push_back(
                std::vector<uint8_t>(licenseResponse.begin() + commaPos, licenseResponse.begin() + i));
            commaPos = i + 1;
        }
    }
    keyIdAndValuePairs.push_back(std::vector<uint8_t>(licenseResponse.begin() + commaPos, licenseResponse.end()));
    for (auto &keyIdAndValuePair : keyIdAndValuePairs) {
        size_t colonPos = 0;
        LicenseType licenseType = LICENSE_TYPE_ONLINE;
        if (keyIdAndValuePair[0] == '0') {
            licenseType = LICENSE_TYPE_ONLINE;
        } else if (keyIdAndValuePair[0] == '1') {
            licenseType = LICENSE_TYPE_OFFLINE;
        } else {
            return HDF_ERR_INVALID_PARAM;
        }
        while (colonPos < keyIdAndValuePair.size() && keyIdAndValuePair[colonPos] != ':') {
            ++colonPos;
        }
        if (colonPos == keyIdAndValuePair.size()) {
            HDF_LOGE("%{public}s: without char ':'", __func__);
            return HDF_ERR_INVALID_PARAM;
        }
        std::string keyIdBase64(keyIdAndValuePair.begin() + 1, keyIdAndValuePair.begin() + colonPos);
        std::string keyValueBase64(keyIdAndValuePair.begin() + colonPos + 1, keyIdAndValuePair.end());
        std::string keyIdString = Decode(keyIdBase64);
        std::string keyValueString = Decode(keyValueBase64);

        std::vector<uint8_t> localKeyId(keyIdString.begin(), keyIdString.end());
        std::vector<uint8_t> value(keyValueString.begin(), keyValueString.end());

        int32_t ret = session_->setKeyIdAndKeyValue(localKeyId, value);
        if (ret != HDF_SUCCESS) {
            return ret;
        }
        if (licenseType == LICENSE_TYPE_OFFLINE) {
            offlineKeyMutex_.lock();
            ret = GetOfflineKeyFromFile();
            if (ret != HDF_SUCCESS) {
                offlineKeyMutex_.unlock();
                return ret;
            }
            offlineKeyIdAndKeyValueBase64_[keyIdBase64] = keyValueBase64;
            ret = SetOfflineKeyToFile();
            if (ret != HDF_SUCCESS) {
                offlineKeyMutex_.unlock();
                return ret;
            }
            offlineKeyMutex_.unlock();
        }
    }
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::CheckLicenseStatus(std::map<std::string, MediaKeySessionKeyStatus>& licenseStatus)
{
    HDF_LOGI("%{public}s: start", __func__);
    for (auto &keyValuePair : session_->keyIdAndKeyValue_) {
        std::string name = std::string(keyValuePair.first.begin(), keyValuePair.first.end());
        MediaKeySessionKeyStatus value = MEDIA_KEY_SESSION_KEY_STATUS_USABLE;
        licenseStatus.insert(std::make_pair(name, value));
    }
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::RemoveLicense()
{
    HDF_LOGI("%{public}s: start", __func__);
    session_->keyIdAndKeyValue_.clear();
    if (session_->keyIdAndKeyValue_.size() != 0) {
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::GetOfflineReleaseRequest(const std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &releaseRequest)
{
    HDF_LOGI("%{public}s: start", __func__);
    releaseRequest.clear();
    std::string requestJson;
    std::vector<std::vector<uint8_t>> keyIds;
    keyIds.push_back(licenseId);
    if (generateRequest(LICENSE_TYPE_OFFLINE, keyIds, &requestJson) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: generateRequest failed", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    releaseRequest = std::vector<uint8_t>(requestJson.begin(), requestJson.end());
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::ProcessOfflineReleaseResponse(const std::vector<uint8_t> &licenseId,
    const std::vector<uint8_t> &response)
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
        offlineKeyMutex_.unlock();
        HDF_LOGI("%{public}s: end", __func__);
        return HDF_SUCCESS;
    }
    offlineKeyMutex_.unlock();
    HDF_LOGI("%{public}s: do not find offline license, keyId: %{public}s", __func__, licenseId.data());
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_FAILURE;
}

int32_t MediaKeySessionService::RestoreOfflineLicense(const std::vector<uint8_t> &licenseId)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (session_ == nullptr) {
        return HDF_FAILURE;
    }
    offlineKeyMutex_.lock();
    int32_t ret = GetOfflineKeyFromFile();
    if (ret != HDF_SUCCESS) {
        offlineKeyMutex_.unlock();
        return ret;
    }
    std::string keyIdString(licenseId.begin(), licenseId.end());
    std::string keyIdBase64 = Encode(keyIdString);
    keyIdBase64.erase(std::remove(keyIdBase64.begin(), keyIdBase64.end(), '\0'), keyIdBase64.end());
    if (offlineKeyIdAndKeyValueBase64_.find(keyIdBase64) == offlineKeyIdAndKeyValueBase64_.end()) {
        offlineKeyMutex_.unlock();
        HDF_LOGE("%{public}s: do not find offline license, licenseId: %{public}s", __func__, licenseId.data());
        return HDF_FAILURE;
    }
    std::string keyValueString = Decode(offlineKeyIdAndKeyValueBase64_[keyIdBase64]);
    std::vector<uint8_t> value(keyValueString.begin(), keyValueString.end());
    offlineKeyIdAndKeyValueBase64_.clear();
    offlineKeyMutex_.unlock();
    HDF_LOGI("%{public}s: end", __func__);
    return session_->setKeyIdAndKeyValue(licenseId, value);
}

int32_t MediaKeySessionService::GetSecurityLevel(SecurityLevel &level)
{
    HDF_LOGI("%{public}s: start", __func__);
    level = level_;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::RequiresSecureDecoderModule(const std::string &mimeType, bool &required)
{
    HDF_LOGI("%{public}s: start", __func__);
    required = false;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback> &sessionCallback)
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::GetMediaDecryptModule(sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> &decryptModule)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (decryptModule_ == nullptr) {
        return HDF_FAILURE;
    }
    decryptModule = decryptModule_;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::Init()
{
    HDF_LOGI("%{public}s: start", __func__);
    session_ = new (std::nothrow) Session();
    if (session_ == nullptr) {
        return HDF_ERR_MALLOC_FAIL;
    }
    decryptModule_ = new (std::nothrow) MediaDecryptModuleService(session_);
    if (decryptModule_ == nullptr) {
        HDF_LOGE("new MediaDecryptModuleService() failed");
        return HDF_ERR_MALLOC_FAIL;
    }

    keySessionCallback_ = new (std::nothrow) MediaKeySessionCallbackService();
    if (keySessionCallback_ == nullptr) {
        HDF_LOGE("new MediaKeySessionCallbackService() failed");
        return HDF_ERR_MALLOC_FAIL;
    }
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::Destroy()
{
    HDF_LOGI("%{public}s: start", __func__);
    offlineKeyMutex_.lock();
    offlineKeyIdAndKeyValueBase64_.clear();
    offlineKeyMutex_.unlock();
    if (sessionCallback_ != nullptr) {
        sessionCallback_->CloseKeySessionService(this);
    }
    sessionCallback_ = nullptr;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::SetKeySessionServiceCallback(sptr<KeySessionServiceCallback> callback)
{
    HDF_LOGI("%{public}s: start", __func__);
    if (callback == nullptr) {
        HDF_LOGE("SetKeySessionServiceCallback callback is null");
        return HDF_ERR_INVALID_PARAM;
    }
    sessionCallback_ = callback;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::GetDecryptNumber()
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return decryptModule_->GetDecryptNumber();
}

int32_t MediaKeySessionService::GetErrorDecryptNumber()
{
    HDF_LOGI("%{public}s: start", __func__);
    HDF_LOGI("%{public}s: end", __func__);
    return decryptModule_->GetErrorDecryptNumber();
}

int32_t MediaKeySessionService::GetOfflineKeyFromFile()
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
    while (fscanf_s(offlineKeyFile, "%s %s", keyIdBase64Chars, sizeof(keyIdBase64Chars), keyValueBase64Chars,
        sizeof(keyValueBase64Chars)) != EOF) {
        std::string tempKeyIdBase64 = keyIdBase64Chars;
        std::string tempKeyValueBase64 = keyValueBase64Chars;
        tempKeyIdBase64.erase(std::remove(tempKeyIdBase64.begin(), tempKeyIdBase64.end(), '\0'), tempKeyIdBase64.end());
        offlineKeyIdAndKeyValueBase64_[tempKeyIdBase64] = tempKeyValueBase64;
    }
    fclose(offlineKeyFile);
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t MediaKeySessionService::SetOfflineKeyToFile()
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
