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

#include "codeccomponenttunnelrequest_fuzzer.h"
#include "codeccommon_fuzzer.h"

#include <securec.h>

namespace {
    struct AllParameters {
        uint32_t port;
        int32_t tunneledComp;
        uint32_t tunneledPort;
        struct OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE *tunnelSetup;
    };
}

namespace OHOS {
namespace Codec {
    bool CodecComponentTunnelRequest(const uint8_t *data, size_t size)
    {
        struct AllParameters params;
        if (data == nullptr) {
            return false;
        }

        uint8_t *rawData = const_cast<uint8_t *>(data);
        if (size > sizeof(uint32_t) + sizeof(int32_t) + sizeof(uint32_t) +
                sizeof(OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE *)) {
            params.port = Convert2Uint32(rawData);
            rawData = rawData + sizeof(uint32_t);
            params.tunneledComp = static_cast<int32_t>(Convert2Uint32(rawData));
            rawData = rawData + sizeof(int32_t);
            params.tunneledPort = Convert2Uint32(rawData);
            rawData = rawData + sizeof(uint32_t);
            params.tunnelSetup = reinterpret_cast<OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE *>(rawData);
        } else {
            params.tunneledComp = static_cast<int32_t>(Convert2Uint32(rawData));
            params.port = Convert2Uint32(rawData);
            params.tunneledPort = Convert2Uint32(rawData);
            params.tunnelSetup = reinterpret_cast<OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE *>(rawData);
        }

        bool result = Preconditions();
        if (!result) {
            HDF_LOGE("%{public}s: Preconditions failed\n", __func__);
            return false;
        }

        const struct OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE inTunnelSetup = *(params.tunnelSetup);
        struct  OHOS::HDI::Codec::V1_0::OMX_TUNNELSETUPTYPE outTunnelSetup = inTunnelSetup;

        int32_t ret = g_component->ComponentTunnelRequest(params.port, params.tunneledComp,
            params.tunneledPort, inTunnelSetup, outTunnelSetup);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: ComponentTunnelRequest failed, ret is [%{public}x]\n", __func__, ret);
        }

        result = Destroy();
        if (!result) {
            HDF_LOGE("%{public}s: Destroy failed\n", __func__);
            return false;
        }

        return true;
    }
} // namespace codec
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::CodecComponentTunnelRequest(data, size);
    return 0;
}