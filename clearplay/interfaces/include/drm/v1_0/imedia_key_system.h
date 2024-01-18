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

#ifndef OHOS_HDI_DRM_V1_0_IMEDIAKEYSYSTEM_H
#define OHOS_HDI_DRM_V1_0_IMEDIAKEYSYSTEM_H

#include <stdint.h>
#include <map>
#include <string>
#include <vector>
#include <hdf_base.h>
#include <hdi_base.h>
#include "drm/v1_0/imedia_key_session.h"
#include "drm/v1_0/imedia_key_system_callback.h"
#include "drm/v1_0/ioem_certificate.h"
#include "drm/v1_0/media_key_system_types.h"

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
namespace HDI {
namespace Drm {
namespace V1_0 {
using namespace OHOS;
using namespace OHOS::HDI;

enum {
    CMD_MEDIA_KEY_SYSTEM_GET_VERSION = 0,
    CMD_MEDIA_KEY_SYSTEM_GET_CONFIGURATION_STRING = 1,
    CMD_MEDIA_KEY_SYSTEM_SET_CONFIGURATION_STRING = 2,
    CMD_MEDIA_KEY_SYSTEM_GET_CONFIGURATION_BYTE_ARRAY = 3,
    CMD_MEDIA_KEY_SYSTEM_SET_CONFIGURATION_BYTE_ARRAY = 4,
    CMD_MEDIA_KEY_SYSTEM_GET_STATISTICS = 5,
    CMD_MEDIA_KEY_SYSTEM_GET_MAX_CONTENT_PROTECTION_LEVEL = 6,
    CMD_MEDIA_KEY_SYSTEM_GENERATE_KEY_SYSTEM_REQUEST = 7,
    CMD_MEDIA_KEY_SYSTEM_PROCESS_KEY_SYSTEM_RESPONSE = 8,
    CMD_MEDIA_KEY_SYSTEM_GET_OEM_CERTIFICATE_STATUS = 9,
    CMD_MEDIA_KEY_SYSTEM_SET_CALLBACK = 10,
    CMD_MEDIA_KEY_SYSTEM_CREATE_MEDIA_KEY_SESSION = 11,
    CMD_MEDIA_KEY_SYSTEM_GET_OFFLINE_MEDIA_KEY_IDS = 12,
    CMD_MEDIA_KEY_SYSTEM_GET_OFFLINE_MEDIA_KEY_STATUS = 13,
    CMD_MEDIA_KEY_SYSTEM_CLEAR_OFFLINE_MEDIA_KEYS = 14,
    CMD_MEDIA_KEY_SYSTEM_GET_OEM_CERTIFICATE = 15,
    CMD_MEDIA_KEY_SYSTEM_DESTROY = 16,
};

class IMediaKeySystem : public HdiBase {
public:
    DECLARE_HDI_DESCRIPTOR(u"ohos.hdi.drm.v1_0.IMediaKeySystem");

    virtual ~IMediaKeySystem() = default;

    virtual int32_t GetConfigurationString(const std::string& name, std::string& value) = 0;

    virtual int32_t SetConfigurationString(const std::string& name, const std::string& value) = 0;

    virtual int32_t GetConfigurationByteArray(const std::string& name, std::vector<uint8_t>& value) = 0;

    virtual int32_t SetConfigurationByteArray(const std::string& name, const std::vector<uint8_t>& value) = 0;

    virtual int32_t GetStatistics(std::map<std::string, std::string>& statistics) = 0;

    virtual int32_t GetMaxContentProtectionLevel(OHOS::HDI::Drm::V1_0::ContentProtectionLevel& level) = 0;

    virtual int32_t GenerateKeySystemRequest(std::string& defaultUrl, std::vector<uint8_t>& request) = 0;

    virtual int32_t ProcessKeySystemResponse(const std::vector<uint8_t>& response) = 0;

    virtual int32_t GetOemCertificateStatus(OHOS::HDI::Drm::V1_0::CertificateStatus& status) = 0;

    virtual int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemCallback>& systemCallback) = 0;

    virtual int32_t CreateMediaKeySession(OHOS::HDI::Drm::V1_0::ContentProtectionLevel level,
         sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession>& keySession) = 0;

    virtual int32_t GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>>& mediaKeyIds) = 0;

    virtual int32_t GetOfflineMediaKeyStatus(const std::vector<uint8_t>& mediaKeyId,
         OHOS::HDI::Drm::V1_0::OfflineMediaKeyStatus& mediaKeyStatus) = 0;

    virtual int32_t ClearOfflineMediaKeys(const std::vector<uint8_t>& mediaKeyId) = 0;

    virtual int32_t GetOemCertificate(sptr<OHOS::HDI::Drm::V1_0::IOemCertificate>& oemCert) = 0;

    virtual int32_t Destroy() = 0;

    virtual int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer)
    {
        majorVer = 1;
        minorVer = 0;
        return HDF_SUCCESS;
    }

    virtual bool IsProxy()
    {
        return false;
    }

    virtual const std::u16string GetDesc()
    {
        return metaDescriptor_;
    }
};
} // V1_0
} // Drm
} // HDI
} // OHOS

#endif // OHOS_HDI_DRM_V1_0_IMEDIAKEYSYSTEM_H