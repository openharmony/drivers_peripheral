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

#include "audiointerfaceliboutputcapturecmdid_fuzzer.h"
#include "audio_adm_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioInterfaceliboutputcaptureCmdidFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        char resolvedPath[] = HDF_LIBRARY_FULL_PATH("libhdi_audio_interface_lib_capture");
        void *PtrHandle = dlopen(resolvedPath, RTLD_LAZY);
        if (PtrHandle == nullptr) {
            return false;
        }
        struct DevHandle *(*BindServiceCapture)(const char *) = nullptr;
        int32_t (*InterfaceLibOutputCapture)(struct DevHandle *, int, struct AudioHwCaptureParam *) = nullptr;
        BindServiceCapture = (struct DevHandle* (*)(const char *))dlsym(PtrHandle, "AudioBindServiceCapture");
        if (BindServiceCapture == nullptr) {
            dlclose(PtrHandle);
            return false;
        }
        struct DevHandle *handle = nullptr;
        handle = BindServiceCapture(BIND_CONTROL.c_str());
        if (handle == nullptr) {
            dlclose(PtrHandle);
            return false;
        }
        InterfaceLibOutputCapture = (int32_t (*)(struct DevHandle *, int,
            struct AudioHwCaptureParam *))dlsym(PtrHandle, "AudioInterfaceLibOutputCapture");
        if (InterfaceLibOutputCapture == nullptr) {
            dlclose(PtrHandle);
            return false;
        }
        struct AudioHwCapture *hwCapture = nullptr;
        int32_t ret = BindServiceAndHwCapture(hwCapture);
        int32_t cmdId = *(int32_t *)(data);
        ret = InterfaceLibOutputCapture(handle, cmdId, &hwCapture->captureParam);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        free(hwCapture);
        void (*CloseService)(const struct DevHandle *) = nullptr;
        CloseService = (void (*)(const struct DevHandle *))dlsym(PtrHandle, "AudioCloseServiceCapture");
        if (CloseService == nullptr) {
            dlclose(PtrHandle);
            return false;
        }
        CloseService(handle);
        dlclose(PtrHandle);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioInterfaceliboutputcaptureCmdidFuzzTest(data, size);
    return 0;
}