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

#ifndef OHOS_HDI_DRM_V1_0_IMEDIAKEYSYSTEMFACTORY_H
#define OHOS_HDI_DRM_V1_0_IMEDIAKEYSYSTEMFACTORY_H

#include <stdint.h>
#include <string>
#include <hdf_base.h>
#include <hdi_base.h>
#include "drm/v1_0/imedia_key_system.h"
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
    CMD_MEDIA_KEY_SYSTEM_FACTORY_GET_VERSION = 0,
    CMD_MEDIA_KEY_SYSTEM_FACTORY_IS_MEDIA_KEY_SYSTEM_SUPPORTED = 1,
    CMD_MEDIA_KEY_SYSTEM_FACTORY_CREATE_MEDIA_KEY_SYSTEM = 2,
    CMD_MEDIA_KEY_SYSTEM_FACTORY_GET_MEDIA_KEY_SYSTEM_NAME = 3,
};

class IMediaKeySystemFactory : public HdiBase {
public:
    DECLARE_HDI_DESCRIPTOR(u"ohos.hdi.drm.v1_0.IMediaKeySystemFactory");

    virtual ~IMediaKeySystemFactory() = default;

    static sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> Get(bool isStub = false);
    static sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> Get(const std::string &serviceName, bool isStub = false);

    virtual int32_t IsMediaKeySystemSupported(const std::string& name, const std::string& mimeType,
         OHOS::HDI::Drm::V1_0::ContentProtectionLevel level, bool& isSupported) = 0;

    virtual int32_t CreateMediaKeySystem(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem>& mediaKeySystem) = 0;

    virtual int32_t GetMediaKeySystemDescription(std::string& name, std::string& uuid) = 0;

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

#endif // OHOS_HDI_DRM_V1_0_IMEDIAKEYSYSTEMFACTORY_H