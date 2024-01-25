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

#include <hdf_log.h>
#include "session.h"
#include "openssl/aes.h"
#include "mime_type.h"
#include "data_parser.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
int32_t Session::getKeyRequest(const std::vector<uint8_t> &indexInfo, const std::string &mimeType, MediaKeyType keyType,
    std::map<std::string, std::string> optionalData, std::vector<uint8_t> *keyRequest)
{
    std::vector<std::vector<uint8_t>> keyIds;
    int32_t ret;
    if (mimeType == ISO_VIDEO_MIME_TYPE || mimeType == ISO_AUDIO_MIME_TYPE || mimeType == CENC_INIT_DATA_FORMAT) {
        ret = ParsePssh(indexInfo, keyIds);
        if (ret != HDF_SUCCESS) {
            return ret;
        }
    } else if (mimeType == WEBM_INIT_DATA_FORMAT || mimeType == WEBM_AUDIO_DATA_FORMAT || mimeType == WEBM_VIDEO_DATA_FORMAT) {
        if (indexInfo.size() != KEY_ID_SIZE) {
            return HDF_ERR_INVALID_PARAM;
        }
        keyIds.push_back(indexInfo);
    } else {
        return HDF_ERR_INVALID_PARAM;
    }

    std::string requestJson;
    if (generateRequest(keyType, keyIds, &requestJson) != HDF_SUCCESS) {
        return HDF_ERR_INVALID_PARAM;
    }
    for (auto optionalDataIt = optionalData.begin(); optionalDataIt != optionalData.end(); ++optionalDataIt) {
        HDF_LOGI("optionalData name: %{public}s, optionalData value: %{public}s", optionalDataIt->first.c_str(),
            optionalDataIt->second.c_str());
    }
    HDF_LOGI("requestJson: %{public}s", requestJson.c_str());
    keyRequest->clear();
    *keyRequest = std::vector<uint8_t>(requestJson.begin(), requestJson.end());
    return HDF_SUCCESS;
}

int32_t Session::setKeyIdAndKeyValue(const std::vector<uint8_t> &keyId, const std::vector<uint8_t> &keyValue)
{
    HDF_LOGI("%{public}s: start", __func__);
    keyIdAndKeyValue_.push_back(make_pair(keyId, keyValue));
    keyIdStatusMap[keyId] = OFFLINE_MEDIA_KEY_STATUS_USABLE;
    HDF_LOGI("%{public}s: end", __func__);
    return HDF_SUCCESS;
}

int32_t Session::getKeyValueByKeyId(const std::vector<uint8_t> &keyId, std::vector<uint8_t> &keyValue)
{
    for (auto &idValuePair : keyIdAndKeyValue_) {
        if (idValuePair.first == keyId && keyIdStatusMap[keyId] == OFFLINE_MEDIA_KEY_STATUS_USABLE) {
            keyValue = idValuePair.second;
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%{public}s: The key status is incorrect and cannot be use!", __func__);
    return HDF_FAILURE;
}
} // V1_0
} // Drm
} // HDI
} // OHOS