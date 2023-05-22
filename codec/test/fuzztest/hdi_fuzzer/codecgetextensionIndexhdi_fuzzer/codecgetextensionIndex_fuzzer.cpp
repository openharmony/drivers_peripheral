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

#include "codecgetextensionIndex_fuzzer.h"
#include "codeccommon_fuzzer.h"

#include <securec.h>

namespace OHOS {
namespace Codec {
    bool CodecGetExtensionIndex(const uint8_t *data, size_t size)
    {
        if (data == nullptr) {
            return false;
        }
        
        uint8_t *rawData = const_cast<uint8_t *>(data);
        uint32_t indexType = *(reinterpret_cast<uint32_t *>(rawData));
        std::string paramName("OMX.Topaz.index.param.extended_test");

        bool result = Preconditions();
        if (!result) {
            HDF_LOGE("%{public}s: Preconditions failed\n", __func__);
            return false;
        }

        int32_t ret = g_component->GetExtensionIndex(paramName, indexType);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: GetExtensionIndex failed, ret is [%{public}x]\n", __func__, ret);
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
    OHOS::Codec::CodecGetExtensionIndex(data, size);
    return 0;
}
