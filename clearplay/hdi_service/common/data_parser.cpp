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

#include <arpa/inet.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <string>
#include "clearplay_uuid.h"
#include "mime_type.h"
#include "base64_utils.h"
#include "data_parser.h"
#include "cJSON.h"
#include "securec.h"

#define HDF_LOG_TAG data_parse

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
int32_t ParsePssh(const std::vector<uint8_t> &initData, std::vector<std::vector<uint8_t>> &keyIds)
{
    HDF_LOGD("%{public}s: start", __func__);
    size_t readPosition = 0;

    // Validate size field
    uint32_t expectedSize = initData.size();
    expectedSize = htonl(expectedSize);
    if (memcmp(&initData[readPosition], &expectedSize, sizeof(expectedSize)) != 0) {
        HDF_LOGD("%{public}s: memcmp(&initData[readPosition], &expectedSize, sizeof(expectedSize)) != 0", __func__);
    }
    readPosition += sizeof(expectedSize);

    // Validate PSSH box identifier
    const char psshIdentifier[4] = {'p', 's', 's', 'h'};
    if (memcmp(&initData[readPosition], psshIdentifier, sizeof(psshIdentifier)) != 0) {
        HDF_LOGD("%{public}s: without \"pssh\"", __func__);
    }
    readPosition += sizeof(psshIdentifier);

    // Validate EME version number
    const uint8_t psshVersion1[4] = {1, 0, 0, 0};
    const uint8_t psshVersion0[4] = {0, 0, 0, 0};
    int psshVersionId = 0;
    if (memcmp(&initData[readPosition], psshVersion0, sizeof(psshVersion0)) != 0) {
        if (memcmp(&initData[readPosition], psshVersion1, sizeof(psshVersion1)) != 0) {
            HDF_LOGD("%{public}s: psshVersion error", __func__);
        }
        psshVersionId = 1;
    }
    readPosition += sizeof(psshVersion1);

    // Validate system ID
    std::string uuid((reinterpret_cast<const char*>(initData.data())) + readPosition, CLEARPLAY_NAME.size());
    if (IsClearPlayUuid(uuid)) {
        HDF_LOGD("%{public}s: uuid error", __func__);
    }
    readPosition += SYSTEM_ID_SIZE;

    if (psshVersionId == 0) {
        std::vector<uint8_t> keyIdString = { 'k', 'i', 'd', 's' };
        int32_t keyIdPos = findSubVector(initData, keyIdString);
        if (keyIdPos == -1) {
            HDF_LOGD("%{public}s: without \"kids\"", __func__);
        }
        while (keyIdPos < initData.size() && initData[keyIdPos] != '[') {
            ++keyIdPos;
        }
        std::string keyIdBase64 = "";
        bool isLeft = false;
        while (keyIdPos < initData.size() && initData[keyIdPos] != ']') {
            if (initData[keyIdPos] == '"') {
                isLeft = !isLeft;
                if (!isLeft) {
                    std::string keyIdString = Decode(keyIdBase64);
                    keyIdBase64 = "";
                    std::vector<uint8_t> keyId(keyIdString.begin(), keyIdString.end());
                    keyIds.push_back(keyId);
                }
            } else if (isLeft) {
                keyIdBase64 += initData[keyIdPos];
            }
            ++keyIdPos;
        }
        if (keyIdPos == initData.size()) {
            HDF_LOGD("%{public}s: kids parse error", __func__);
        }
    } else if (psshVersionId == 1) {
        // Read key ID count
        uint32_t keyIdCount;
        int32_t ret = HDF_FAILURE;
        ret = memcpy_s(&keyIdCount, sizeof(keyIdCount), &initData[readPosition], sizeof(keyIdCount));
        if(ret != 0) {
            HDF_LOGE("%{public}s: memcpy_s faild", __func__);
            return HDF_ERR_INVALID_PARAM;
        }
        keyIdCount = ntohl(keyIdCount);
        readPosition += sizeof(keyIdCount);

        // Calculate the key ID offsets
        for (uint32_t i = 0; i < keyIdCount; ++i) {
            std::vector<uint8_t> keyId;
            for (size_t j = 0; i < KEY_ID_SIZE; ++j) {
                keyId.push_back(initData[readPosition + i * KEY_ID_SIZE + j]);
            }
            keyIds.push_back(keyId);
        }
    }
    return HDF_SUCCESS;
}

int32_t generateRequest(const MediaKeyType keyType, const std::vector<std::vector<uint8_t>> &keyIds,
    std::string *request)
{
    // begin
    *request = "{\"kids\":[";
    std::string encodedKeyId;
    for (size_t i = 0; i < keyIds.size(); ++i) {
        encodedKeyId.clear();
        std::string keyId(keyIds[i].begin(), keyIds[i].end());
        encodedKeyId = Encode(keyId);
        if (i != 0) {
            request->append(",");
        }
        request->append("\"");
        request->append(encodedKeyId);
        request->append("\"");
    }
    if (keyType == MEDIA_KEY_TYPE_ONLINE) {
        request->append("],\"type\":\"temporary\"}");
    } else if (keyType == MEDIA_KEY_TYPE_OFFLINE) {
        request->append("],\"type\":\"persistent-license\"}");
    } else {
        return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

int32_t findSubVector(const std::vector<uint8_t> &main, const std::vector<uint8_t> &sub)
{
    for (size_t i = 0; i < main.size(); ++i) {
        size_t j = 0;
        for (j = 0; j < sub.size() && main[i + j] == sub[j]; ++j) {
        }
        // for j end
        if (j == sub.size()) {
            return i;
        }
    }
    return -1;
}
} // V1_0
} // Drm
} // HDI
} // OHOS