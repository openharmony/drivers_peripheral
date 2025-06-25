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

#include "codecgetextensionIndex_fuzzer.h"
#include "codeccommon_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

namespace OHOS {
namespace Codec {
    bool CodecGetExtensionIndex(const uint8_t *data, size_t size)
    {
        FuzzedDataProvider fdp(const_cast<uint8_t *>(data), size);
        uint32_t* indexType = nullptr;
        std::string paramName = fdp.ConsumeRandomLengthString();
        bool result = Preconditions();
        if (!result) {
            HDF_LOGE("%{public}s: Preconditions failed\n", __func__);
            return false;
        }

        int32_t ret = g_component->GetExtensionIndex(g_component, paramName.c_str(), indexType);
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