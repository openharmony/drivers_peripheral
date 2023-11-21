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
    SW_SECURE_CRYPTO = 1,
    SW_SECURE_DECODE = 2,
    HW_SECURE_CRYPTO = 3,
    HW_SECURE_DECODE = 4,
    HW_SECURE_ALL = 5,
};

enum RequestType : int32_t {
    REQUESTTYPE_UNKNOWN = 0,
    REQUEST_TYPE_INITIAL = 1,
    REQUEST_TYPE_RENEWAL = 2,
    REQUEST_TYPE_RELEASE = 3,
    REQUEST_TYPE_NONE = 4,
    REQUEST_TYPE_UPDATE = 5,
};

enum EventType : int32_t {
    EVENTTYPE_PROVISIONREQUIRED = 1,
    EVENTTYPE_KEYNEEDED = 2,
    EVENTTYPE_KEYEXPIRED = 3,
    EVENTTYPE_VENDOR_DEFINED = 4,
    EVENTTYPE_KEYSESSION_RECLAIMED = 5,
    EVENTTYPE_EXPIRATIONUPDATE = 6,
    EVENTTYPE_KEYCHANGE = 7,
    EVENTTYPE_KEYSESSION_LOST = 8,
};

enum CryptoAlgorithmType : int32_t {
    ALGTYPE_UNENCRYPTED = 0,
    ALGTYPE_AES_CTR = 1,
    ALGTYPE_AES_WV = 2,
    ALGTYPE_AES_CBC = 3,
    ALGTYPE_SM4_CBC = 4,
    ALGTYPE_SM4_CTR = 5,
};

enum OfflineLicenseStatus : int32_t {
    OFFLINELICENSE_STATUS_UNKNOWN = 0,
    OFFLINELICENSE_STATUS_USABLE = 1,
    OFFLINELICENSE_STATUS_INACTIVE = 2,
};

enum LicenseType : int32_t {
    LICENSE_TYPE_ONLINE = 1,
    LICENSE_TYPE_OFFLINE = 2,
};

enum CertificateStatus : int32_t {
    CERT_STATUS_PROVISIONED = 0,
    CERT_STATUS_NOT_PROVISIONED = 1,
    CERT_STATUS_EXPIRED = 2,
    CERT_STATUS_INVALID = 3,
    CERT_STATUS_GET_FAILED = 4,
};

enum MediaKeySessionLicenseStatus : int32_t {
    MEDIA_KEY_SESSION_LICENSE_STATUS_USABLE = 0,
    MEDIA_KEY_SESSION_LICENSE_STATUS_EXPIRED = 1,
    MEDIA_KEY_SESSION_LICENSE_STATUS_OUTPUT_NOT_ALLOWED = 2,
    MEDIA_KEY_SESSION_LICENSE_STATUS_PENDING = 3,
    MEDIA_KEY_SESSION_LICENSE_STATUS_INTERNAL_ERROR = 4,
    MEDIA_KEY_SESSION_LICENSE_STATUS_USABLE_IN_FUTURE = 5,
};

struct LicenseStatusString {
    std::string name;
    std::string value;
};

struct LicenseRequestInfo {
    LicenseType licenseType;
    std::string mimeType;
    std::vector<uint8_t> initData;
    std::map<std::string, std::string> optionalData;
};

struct LicenseRequest {
    RequestType requestType;
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
    CryptoAlgorithmType type;
    std::vector<uint8_t> keyId;
    std::vector<uint8_t> iv;
    Pattern pattern;
    std::vector<SubSample> subSamples;
};

struct DrmBuffer {
    uint32_t bufferType;
    uint32_t bufferLen;
    int fd;
};

bool LicenseStatusStringBlockMarshalling(OHOS::MessageParcel &data, const LicenseStatusString& dataBlock);

bool LicenseStatusStringBlockUnmarshalling(OHOS::MessageParcel &data, LicenseStatusString& dataBlock);

bool LicenseRequestInfoBlockMarshalling(OHOS::MessageParcel &data, const LicenseRequestInfo& dataBlock);

bool LicenseRequestInfoBlockUnmarshalling(OHOS::MessageParcel &data, LicenseRequestInfo& dataBlock);

bool LicenseRequestBlockMarshalling(OHOS::MessageParcel &data, const LicenseRequest& dataBlock);

bool LicenseRequestBlockUnmarshalling(OHOS::MessageParcel &data, LicenseRequest& dataBlock);

bool PatternBlockMarshalling(OHOS::MessageParcel &data, const Pattern& dataBlock);

bool PatternBlockUnmarshalling(OHOS::MessageParcel &data, Pattern& dataBlock);

bool SubSampleBlockMarshalling(OHOS::MessageParcel &data, const SubSample& dataBlock);

bool SubSampleBlockUnmarshalling(OHOS::MessageParcel &data, SubSample& dataBlock);

bool CryptoInfoBlockMarshalling(OHOS::MessageParcel &data, const CryptoInfo& dataBlock);

bool CryptoInfoBlockUnmarshalling(OHOS::MessageParcel &data, CryptoInfo& dataBlock);

bool DrmBufferBlockMarshalling(OHOS::MessageParcel &data, const DrmBuffer& dataBlock);

bool DrmBufferBlockUnmarshalling(OHOS::MessageParcel &data, DrmBuffer& dataBlock);

} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_MEDIAKEYSYSTEMTYPES_H