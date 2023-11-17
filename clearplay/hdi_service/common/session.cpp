#include <hdf_log.h>
#include "session.h"
#include "openssl/aes.h"
#include "mime_type.h"
#include "data_parser.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

int32_t Session::getKeyRequest(const std::vector<uint8_t>& indexInfo,
    const std::string& mimeType, LicenseType keyType, std::map<std::string, std::string> optionalData, std::vector<uint8_t>* keyRequest) {
    std::vector<std::vector<uint8_t>> keyIds;
    int32_t ret;
    if (mimeType == isoVideoMimeType ||
        mimeType == isoAudioMimeType ||
        mimeType == cencInitDataFormat) {
        ret = ParsePssh(indexInfo, keyIds);
        if (ret != HDF_SUCCESS) {
            return ret;
        }
    } else if (mimeType == webmInitDataFormat ||
        mimeType == webmAudioDataFormat ||
        mimeType == webmVideoDataFormat) {
        if (indexInfo.size() != keyIdSize) {
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
        HDF_LOGI("optionalData name: %{public}s, optionalData value: %{public}s", optionalDataIt->first.c_str(), optionalDataIt->second.c_str());
    }
    HDF_LOGI("requestJson: %{public}s", requestJson.c_str());
    keyRequest->clear();
    *keyRequest = std::vector<uint8_t>(requestJson.begin(), requestJson.end());
    return HDF_SUCCESS;
}

int32_t Session::setKeyIdAndKeyValue(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& keyValue) {
    HDF_LOGE("%{public}s: start", __func__);
    for (auto &idValuePair:keyIdAndKeyValue_) {
        if (idValuePair.first == keyId) {
            idValuePair.second = keyValue;
            return HDF_SUCCESS;
        }
    }
    keyIdAndKeyValue_.push_back(make_pair(keyId, keyValue));
    return HDF_SUCCESS;
}

int32_t Session::getKeyValueByKeyId(const std::vector<uint8_t>& keyId, std::vector<uint8_t>& keyValue) {
    for (auto &idValuePair:keyIdAndKeyValue_) {
        if (idValuePair.first == keyId) {
            keyValue = idValuePair.second;
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("%{public}s: do not find keyId license", __func__);
    return HDF_FAILURE;
}

} // V1_0
} // Drm
} // HDI
} // OHOS