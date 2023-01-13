/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "codecsendcommand_fuzzer.h"
#include "codeccommon_fuzzer.h"

#include <securec.h>

namespace {
    struct AllParameters {
        enum OMX_COMMANDTYPE cmd;
        uint32_t param;
        int8_t *cmdData;
        uint32_t cmdDataLen;
    };
}

namespace OHOS {
namespace Codec {
    bool CodecSendCommand(const uint8_t *data, size_t size)
    {
        struct AllParameters params;
        if (data == nullptr) {
            return false;
        }

        uint8_t *rawData = const_cast<uint8_t *>(data);
        params.param = Convert2Uint32(rawData);
        if (size > sizeof(OMX_COMMANDTYPE) + sizeof(uint32_t) + sizeof(int8_t *)) {
            rawData = rawData + sizeof(uint32_t);
            size = size - sizeof(uint32_t);
            params.cmdData = reinterpret_cast<int8_t *>(rawData);
            params.cmdDataLen = size;
            rawData = rawData + sizeof(int8_t *);
            params.cmd = static_cast<OMX_COMMANDTYPE>(*rawData);
        } else {
            params.cmdData = reinterpret_cast<int8_t *>(rawData);
            params.cmdDataLen = size;
            params.cmd = static_cast<OMX_COMMANDTYPE>(*rawData);
        }

        bool result = Preconditions();
        if (!result) {
            HDF_LOGE("%{public}s: Preconditions failed\n", __func__);
            return false;
        }

        int32_t ret = g_component->SendCommand(g_component, params.cmd, params.param, params.cmdData,
            params.cmdDataLen);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: SendCommand failed, ret is [%{public}x]\n", __func__, ret);
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
    OHOS::Codec::CodecSendCommand(data, size);
    return 0;
}