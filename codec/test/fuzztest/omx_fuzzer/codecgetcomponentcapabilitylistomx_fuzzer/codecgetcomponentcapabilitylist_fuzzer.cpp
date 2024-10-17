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

#include "codecgetcomponentcapabilitylist_fuzzer.h"
#include "codec_callback_type_stub.h"
#include "codec_component_type.h"
#include "codec_component_manager.h"

#include <osal_mem.h>
#include <hdf_log.h>

extern "C" __attribute__((visibility("default"))) int dlclose(void* handle)
{
    return 0;
}

namespace OHOS {
namespace Codec {
    bool CodecGetComponentCapabilityList(const uint8_t* data, size_t size)
    {
        bool result = false;
        struct CodecComponentManager *manager = nullptr;

        manager = GetCodecComponentManager();
        if (manager == nullptr) {
            HDF_LOGE("%{public}s: GetCodecComponentManager failed\n", __func__);
            return false;
        }

        CodecCompCapability *capList = reinterpret_cast<CodecCompCapability *>(OsalMemAlloc(sizeof(CodecCompCapability)
            *static_cast<int32_t>(*data)));
        if (capList == nullptr) {
            HDF_LOGE("%{public}s: OsalMemAlloc CodecCompCapability failed\n", __func__);
            return false;
        }

        int32_t ret = manager->GetComponentCapabilityList(capList, static_cast<int32_t>(*data));
        if (ret == HDF_SUCCESS) {
            HDF_LOGI("%{public}s: GetComponentCapabilityList succeed\n", __func__);
            result = true;
        }
        OsalMemFree(capList);
        CodecComponentManagerRelease();

        return result;
    }
} // namespace codec
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Codec::CodecGetComponentCapabilityList(data, size);
    return 0;
}
