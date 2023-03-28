/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "codec_component_manager.h"
#include "codec_component_type.h"

#include <hdf_log.h>
#include <osal_mem.h>

namespace OHOS {
namespace Codec {
bool CodecGetComponentCapabilityList(const uint8_t *data, size_t size)
{
    struct CodecComponentManager *manager = nullptr;

    manager = GetCodecComponentManager();
    if (manager == nullptr) {
        HDF_LOGE("%{public}s: GetCodecComponentManager failed", __func__);
        return false;
    }

    int32_t componentCount = manager->GetComponentNum();
    if (componentCount <= 0) {
        HDF_LOGE("%{public}s: GetComponentNum failed", __func__);
        CodecComponentManagerRelease();
        return false;
    }

    CodecCompCapability *capList = new CodecCompCapability[componentCount];
    if (capList == nullptr) {
        HDF_LOGE("%{public}s: new CodecCompCapability failed", __func__);
        CodecComponentManagerRelease();
        return false;
    }

    int32_t ret =
        manager->GetComponentCapabilityList(capList, *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data))));
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: GetComponentCapabilityList failed", __func__);
    }
    delete[] capList;
    CodecComponentManagerRelease();

    return (ret == HDF_SUCCESS);
}
} // namespace Codec
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::CodecGetComponentCapabilityList(data, size);
    return 0;
}