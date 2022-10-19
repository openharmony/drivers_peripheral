/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "audiolibaudiobindservicerender_fuzzer.h"
#include "audio_adm_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioLibAudioBindserviceRenderFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        struct DevHandle *(*BindServiceRender)(const char *) = nullptr;
        char resolvedPath[] = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_render");
        void *ptrHandle = dlopen(resolvedPath, RTLD_LAZY);
        if (ptrHandle == nullptr) {
            HDF_LOGE("%{public}s: dlopen failed \n", __func__);
            return false;
        }
        BindServiceRender = reinterpret_cast<struct DevHandle *(*)(const char *)>(dlsym(ptrHandle,
            "AudioBindServiceRender"));
        if (BindServiceRender == nullptr) {
            dlclose(ptrHandle);
            HDF_LOGE("%{public}s: dlsym AudioBindServiceRender failed \n", __func__);
            return false;
        }
        char *bindFuzz = reinterpret_cast<char *>(const_cast<uint8_t *>(data));
        struct DevHandle *handle = BindServiceRender(bindFuzz);
        if (handle != nullptr) {
            result = true;
        }
        dlclose(ptrHandle);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioLibAudioBindserviceRenderFuzzTest(data, size);
    return 0;
}