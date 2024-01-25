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

#ifndef CLEARPLAY_SESSION_H
#define CLEARPLAY_SESSION_H

#include <hdf_base.h>
#include <hdi_base.h>
#include <vector>
#include "v1_0/media_key_system_types.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {
class Session : public RefBase {
public:
    explicit Session() {}
    virtual ~Session() {}
    int32_t getKeyRequest(const std::vector<uint8_t> &indexInfo, const std::string &mimeType, MediaKeyType keyType,
        std::map<std::string, std::string> optionalData, std::vector<uint8_t> *keyRequest);
    int32_t setKeyIdAndKeyValue(const std::vector<uint8_t> &keyId, const std::vector<uint8_t> &keyValue);
    int32_t getKeyValueByKeyId(const std::vector<uint8_t> &keyId, std::vector<uint8_t> &keyValue);
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> keyIdAndKeyValue_;
    std::map<std::vector<uint8_t>, OfflineMediaKeyStatus> keyIdStatusMap;
};
} // V1_0
} // Drm
} // HDI
} // OHOS
#endif // CLEARPLAY_SESSION_H