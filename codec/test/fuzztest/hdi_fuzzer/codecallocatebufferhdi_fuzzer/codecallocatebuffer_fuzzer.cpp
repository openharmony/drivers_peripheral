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

#include "codecallocatebuffer_fuzzer.h"
#include "codeccommon_fuzzer.h"

namespace OHOS {
namespace Codec {

    static const uint32_t OMX_MAX_PORT_INDEX = 2;

    bool CodecAllocateBuffer(const uint8_t *data, size_t size)
    {
        if (data == nullptr) {
            return false;
        }

        bool result = Preconditions();
        if (!result) {
            HDF_LOGE("%{public}s: Preconditions failed\n", __func__);
            return false;
        }

        struct OmxCodecBuffer inbuffer, outBuffer;
        FillDataOmxCodecBuffer(&inbuffer);
        int32_t ret = g_component->SendCommand(HDI::Codec::V4_0::CODEC_COMMAND_STATE_SET,
                                               HDI::Codec::V4_0::CODEC_STATE_IDLE, {});
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: Set LOADED failed, ret is [%{public}x]\n", __func__, ret);
        }
        ret = g_component->AllocateBuffer(static_cast<uint32_t>((*(const_cast<uint8_t *>(data)) % OMX_MAX_PORT_INDEX)),
            inbuffer, outBuffer);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: AllocateBuffer failed, ret is [%{public}x]\n", __func__, ret);
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
    OHOS::Codec::CodecAllocateBuffer(data, size);
    return 0;
}
