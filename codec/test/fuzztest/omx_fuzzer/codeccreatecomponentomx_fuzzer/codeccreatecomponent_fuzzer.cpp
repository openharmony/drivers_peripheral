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

#include "codeccreatecomponent_fuzzer.h"
#include "codeccommon_fuzzer.h"

namespace OHOS {
namespace Codec {
    bool CodecCreateComponent(const uint8_t *data, size_t size)
    {
        struct CodecComponentManager *manager = nullptr;
        struct CodecComponentType *component = nullptr;
        CodecCallbackType* g_callback = CodecCallbackTypeStubGetInstance();

        manager = GetCodecComponentManager();
        if (manager == nullptr) {
            HDF_LOGE("%{public}s: GetCodecComponentManager failed\n", __func__);
            return false;
        }

        std::string compName("OMX.rk.video_encoder.avc");
        int32_t ret = manager->CreateComponent(&component, &g_componentId, compName.data(),
            static_cast<int64_t >(*data), g_callback);
        if (ret != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: UseEglImage failed, ret is [%{public}x]\n", __func__, ret);
        }

        int32_t result = manager->DestroyComponent(g_componentId);
        if (result != HDF_SUCCESS) {
            HDF_LOGE("%{public}s: DestroyComponent failed\n", __func__);
            return false;
        }
        CodecComponentTypeRelease(component);
        CodecComponentManagerRelease();

        return true;
    }
} // namespace codec
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Codec::CodecCreateComponent(data, size);
    return 0;
}