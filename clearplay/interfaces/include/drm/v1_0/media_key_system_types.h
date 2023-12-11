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

#ifndef OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMTYPES_H
#define OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMTYPES_H

#include <cstdbool>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#ifndef HDI_BUFF_MAX_SIZE
#define HDI_BUFF_MAX_SIZE (1024 * 200)
#endif

#ifndef HDI_CHECK_VALUE_RETURN
#define HDI_CHECK_VALUE_RETURN(lv, compare, rv, ret) do { \
    if ((lv) compare (rv)) { \
        return ret; \
    } \
} while (false)
#endif

#ifndef HDI_CHECK_VALUE_RET_GOTO
#define HDI_CHECK_VALUE_RET_GOTO(lv, compare, rv, ret, value, table) do { \
    if ((lv) compare (rv)) { \
        ret = value; \
        goto table; \
    } \
} while (false)
#endif

namespace OHOS {
class MessageParcel;
}

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

using namespace OHOS;

enum SecurityLevel : int32_t {
    SECURE_UNKNOWN = 0,
    SW_SECURE_CRYPTO,
    SW_SECURE_DECODE,
    HW_SECURE_CRYPTO,
    HW_SECURE_DECODE,
    HW_SECURE_ALL,
};

enum RequestType : int32_t {
    REQUESTTYPE_UNKNOWN = 0,
    REQUEST_TYPE_INITIAL,
    REQUEST_TYPE_RENEWAL,
    REQUEST_TYPE_RELEASE,
    REQUEST_TYPE_NONE,
    REQUEST_TYPE_UPDATE,
};

enum EventType : int32_t {
    EVENTTYPE_PROVISIONREQUIRED = 0,
    EVENTTYPE_KEYNEEDED,
    EVENTTYPE_KEYEXPIRED,
    EVENTTYPE_VENDOR_DEFINED,
    EVENTTYPE_EXPIRATIONUPDATE,
    EVENTTYPE_KEYCHANGE,
    EVENTTYPE_KEYSESSION_LOST,
};

enum CryptoAlgorithmType : int32_t {
    ALGTYPE_UNENCRYPTED = 0,
    ALGTYPE_AES_CTR,
    ALGTYPE_AES_WV,
    ALGTYPE_AES_CBC,
    ALGTYPE_SM4_CBC,
    ALGTYPE_SM4_CTR,
};

enum OfflineLicenseStatus : int32_t {
    OFFLINELICENSE_STATUS_UNKNOWN = 0,
    OFFLINELICENSE_STATUS_USABLE,
    OFFLINELICENSE_STATUS_INACTIVE,
};

enum LicenseType : int32_t {
    LICENSE_TYPE_ONLINE = 0,
    LICENSE_TYPE_OFFLINE,
};

enum CertificateStatus : int32_t {
    CERT_STATUS_PROVISIONED = 0,
    CERT_STATUS_NOT_PROVISIONED,
    CERT_STATUS_EXPIRED,
    CERT_STATUS_INVALID,
    CERT_STATUS_GET_FAILED,
};

enum MediaKeySessionKeyStatus : int32_t {
    MEDIA_KEY_SESSION_KEY_STATUS_USABLE = 0,
    MEDIA_KEY_SESSION_KEY_STATUS_EXPIRED,
    MEDIA_KEY_SESSION_KEY_STATUS_OUTPUT_NOT_ALLOWED,
    MEDIA_KEY_SESSION_KEY_STATUS_PENDING,
    MEDIA_KEY_SESSION_KEY_STATUS_INTERNAL_ERROR,
    MEDIA_KEY_SESSION_KEY_STATUS_USABLE_IN_FUTURE,
};

struct LicenseRequestInfo {
    OHOS::HDI::Drm::V1_0::LicenseType licenseType;
    std::string mimeType;
    std::vector<uint8_t> initData;
    std::map<std::string, std::string> optionalData;
};

struct LicenseRequest {
    OHOS::HDI::Drm::V1_0::RequestType requestType;
    std::vector<uint8_t> mData;
    std::string mDefaultUrl;
};

struct Pattern {
    uint32_t encryptBlocks;
    uint32_t skipBlocks;
} __attribute__ ((aligned(8)));

struct SubSample {
    uint32_t clearHeaderLen;
    uint32_t payLoadLen;
} __attribute__ ((aligned(8)));

struct CryptoInfo {
    OHOS::HDI::Drm::V1_0::CryptoAlgorithmType type;
    std::vector<uint8_t> keyId;
    std::vector<uint8_t> iv;
    OHOS::HDI::Drm::V1_0::Pattern pattern;
    std::vector<OHOS::HDI::Drm::V1_0::SubSample> subSamples;
};

struct DrmBuffer {
    uint32_t bufferType;
    int fd;
    uint32_t bufferLen;
};

bool LicenseRequestInfoBlockMarshalling(OHOS::MessageParcel &data, const OHOS::HDI::Drm::V1_0::LicenseRequestInfo& dataBlock);

bool LicenseRequestInfoBlockUnmarshalling(OHOS::MessageParcel &data, OHOS::HDI::Drm::V1_0::LicenseRequestInfo& dataBlock);

bool LicenseRequestBlockMarshalling(OHOS::MessageParcel &data, const OHOS::HDI::Drm::V1_0::LicenseRequest& dataBlock);

bool LicenseRequestBlockUnmarshalling(OHOS::MessageParcel &data, OHOS::HDI::Drm::V1_0::LicenseRequest& dataBlock);

bool PatternBlockMarshalling(OHOS::MessageParcel &data, const OHOS::HDI::Drm::V1_0::Pattern& dataBlock);

bool PatternBlockUnmarshalling(OHOS::MessageParcel &data, OHOS::HDI::Drm::V1_0::Pattern& dataBlock);

bool SubSampleBlockMarshalling(OHOS::MessageParcel &data, const OHOS::HDI::Drm::V1_0::SubSample& dataBlock);

bool SubSampleBlockUnmarshalling(OHOS::MessageParcel &data, OHOS::HDI::Drm::V1_0::SubSample& dataBlock);

bool CryptoInfoBlockMarshalling(OHOS::MessageParcel &data, const OHOS::HDI::Drm::V1_0::CryptoInfo& dataBlock);

bool CryptoInfoBlockUnmarshalling(OHOS::MessageParcel &data, OHOS::HDI::Drm::V1_0::CryptoInfo& dataBlock);

bool DrmBufferBlockMarshalling(OHOS::MessageParcel &data, const OHOS::HDI::Drm::V1_0::DrmBuffer& dataBlock);

bool DrmBufferBlockUnmarshalling(OHOS::MessageParcel &data, OHOS::HDI::Drm::V1_0::DrmBuffer& dataBlock);

} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMTYPES_H