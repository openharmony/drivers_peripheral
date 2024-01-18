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

#ifndef OHOS_HDI_DRM_V1_0_IMEDIAKEYSESSION_H
#define OHOS_HDI_DRM_V1_0_IMEDIAKEYSESSION_H

#include <stdint.h>
#include <map>
#include <string>
#include <vector>
#include <hdf_base.h>
#include <hdi_base.h>
#include "drm/v1_0/imedia_decrypt_module.h"
#include "drm/v1_0/imedia_key_session_callback.h"
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
    CMD_MEDIA_KEY_SESSION_GET_VERSION = 0,
    CMD_MEDIA_KEY_SESSION_GENERATE_MEDIA_KEY_REQUEST = 1,
    CMD_MEDIA_KEY_SESSION_PROCESS_MEDIA_KEY_RESPONSE = 2,
    CMD_MEDIA_KEY_SESSION_CHECK_MEDIA_KEY_STATUS = 3,
    CMD_MEDIA_KEY_SESSION_CLEAR_MEDIA_KEYS = 4,
    CMD_MEDIA_KEY_SESSION_GET_OFFLINE_RELEASE_REQUEST = 5,
    CMD_MEDIA_KEY_SESSION_PROCESS_OFFLINE_RELEASE_RESPONSE = 6,
    CMD_MEDIA_KEY_SESSION_RESTORE_OFFLINE_MEDIA_KEYS = 7,
    CMD_MEDIA_KEY_SESSION_GET_CONTENT_PROTECTION_LEVEL = 8,
    CMD_MEDIA_KEY_SESSION_REQUIRES_SECURE_DECODER_MODULE = 9,
    CMD_MEDIA_KEY_SESSION_SET_CALLBACK = 10,
    CMD_MEDIA_KEY_SESSION_GET_MEDIA_DECRYPT_MODULE = 11,
    CMD_MEDIA_KEY_SESSION_DESTROY = 12,
};

class IMediaKeySession : public HdiBase {
public:
    DECLARE_HDI_DESCRIPTOR(u"ohos.hdi.drm.v1_0.IMediaKeySession");

    virtual ~IMediaKeySession() = default;

    virtual int32_t GenerateMediaKeyRequest(const OHOS::HDI::Drm::V1_0::MediaKeyRequestInfo& mediaKeyRequestInfo,
         OHOS::HDI::Drm::V1_0::MediaKeyRequest& mediaKeyRequest) = 0;

    virtual int32_t ProcessMediaKeyResponse(const std::vector<uint8_t>& mediaKeyResponse,
         std::vector<uint8_t>& mediaKeyId) = 0;

    virtual int32_t CheckMediaKeyStatus(std::map<std::string, std::string>& mediaKeyStatus) = 0;

    virtual int32_t ClearMediaKeys() = 0;

    virtual int32_t GetOfflineReleaseRequest(const std::vector<uint8_t>& mediaKeyId,
         std::vector<uint8_t>& releaseRequest) = 0;

    virtual int32_t ProcessOfflineReleaseResponse(const std::vector<uint8_t>& mediaKeyId,
         const std::vector<uint8_t>& response) = 0;

    virtual int32_t RestoreOfflineMediaKeys(const std::vector<uint8_t>& mediaKeyId) = 0;

    virtual int32_t GetContentProtectionLevel(OHOS::HDI::Drm::V1_0::ContentProtectionLevel& level) = 0;

    virtual int32_t RequiresSecureDecoderModule(const std::string& mimeType, bool& required) = 0;

    virtual int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback>& sessionCallback) = 0;

    virtual int32_t GetMediaDecryptModule(sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule>& decryptModule) = 0;

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

#endif // OHOS_HDI_DRM_V1_0_IMEDIAKEYSESSION_H