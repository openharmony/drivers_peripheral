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

#include "codeccreatecomponent_fuzzer.h"
#include "codeccommon_fuzzer.h"

namespace OHOS {
namespace Codec {
bool CodecCreateComponent(const uint8_t *data, size_t size)
{
    bool result = true;
    struct CodecComponentManager *manager = nullptr;
    struct CodecComponentType *component = nullptr;
    uint32_t componentId;
    CodecCallbackType *callback = CodecCallbackTypeGet(nullptr);

    manager = GetCodecComponentManager();
    if (manager == nullptr) {
        HDF_LOGE("%{public}s: GetCodecComponentManager failed", __func__);
        return false;
    }

    int32_t ret =
        manager->CreateComponent(&component, &componentId, reinterpret_cast<char *>(const_cast<uint8_t *>(data)),
            *(reinterpret_cast<int64_t *>(const_cast<uint8_t *>(data))), callback);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: CreateComponent failed", __func__);
        result = false;
    }

    ret = manager->DestroyComponent(componentId);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: DestroyComponent failed", __func__);
        result = false;
    }
    CodecCallbackTypeRelease(callback);
    CodecComponentManagerRelease();

    return result;
}
} // namespace Codec
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::CodecCreateComponent(data, size);
    return 0;
}