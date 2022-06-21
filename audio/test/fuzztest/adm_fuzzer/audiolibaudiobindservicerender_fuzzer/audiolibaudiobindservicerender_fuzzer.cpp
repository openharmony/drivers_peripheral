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
        void *PtrHandle = dlopen(resolvedPath, RTLD_LAZY);
        if (PtrHandle == nullptr) {
            HDF_LOGE("%{public}s: dlopen failed \n", __func__);
            return false;
        }
        BindServiceRender = (struct DevHandle *(*)(const char *))dlsym(PtrHandle, "AudioBindServiceRender");
        if (BindServiceRender == nullptr) {
            dlclose(PtrHandle);
            HDF_LOGE("%{public}s: dlsym AudioBindServiceRender failed \n", __func__);
            return false;
        }
        char *bindFuzz = (char *)data;
        struct DevHandle *handle = BindServiceRender(bindFuzz);
        if (handle != nullptr) {
            result = true;
        }
        dlclose(PtrHandle);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioLibAudioBindserviceRenderFuzzTest(data, size);
    return 0;
}