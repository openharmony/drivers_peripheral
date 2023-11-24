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

#ifndef OHOS_HDI_DRM_V1_0_IMEDIADECRYPTMODULE_H
#define OHOS_HDI_DRM_V1_0_IMEDIADECRYPTMODULE_H

#include <stdint.h>
#include <hdf_base.h>
#include <hdi_base.h>
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
    CMD_MEDIA_DECRYPT_MODULE_GET_VERSION = 0,
    CMD_MEDIA_DECRYPT_MODULE_DECRYPT_MEDIA_DATA = 1,
    CMD_MEDIA_DECRYPT_MODULE_RELEASE = 2,
};

class IMediaDecryptModule : public HdiBase {
public:
    DECLARE_HDI_DESCRIPTOR(u"ohos.hdi.drm.v1_0.IMediaDecryptModule");

    virtual ~IMediaDecryptModule() = default;

    virtual int32_t DecryptMediaData(bool secure, const OHOS::HDI::Drm::V1_0::CryptoInfo& cryptoInfo,
         const OHOS::HDI::Drm::V1_0::DrmBuffer& srcBuffer, const OHOS::HDI::Drm::V1_0::DrmBuffer& destBuffer) = 0;

    virtual int32_t Release() = 0;

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

#endif // OHOS_HDI_DRM_V1_0_IMEDIADECRYPTMODULE_H