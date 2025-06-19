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

#include "audiointerfacelibctlrendercmdid_fuzzer.h"
#include "audio_adm_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioInterfacelibctlrenderCmdidFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        char resolvedPath[] = HDF_LIBRARY_FULL_PATH("libaudio_render_adapter");
        void *ctlRenFuzzPtrHandle = dlopen(resolvedPath, RTLD_LAZY);
        if (ctlRenFuzzPtrHandle == nullptr) {
            HDF_LOGE("%{public}s: dlopen failed \n", __func__);
            return false;
        }
        struct DevHandle *(*BindServiceRender)(const char *) = nullptr;
        int32_t (*InterfaceLibCtlRender)(struct DevHandle *, int32_t, struct AudioHwRenderParam *) = nullptr;
        BindServiceRender = reinterpret_cast<struct DevHandle *(*)(const char *)>(dlsym(ctlRenFuzzPtrHandle,
            "AudioBindServiceRender"));
        if (BindServiceRender == nullptr) {
            HDF_LOGE("%{public}s: dlsym AudioBindServiceRender failed \n", __func__);
            dlclose(ctlRenFuzzPtrHandle);
            return false;
        }
        struct DevHandle *handle = BindServiceRender(BIND_CONTROL.c_str());
        if (handle == nullptr) {
            HDF_LOGE("%{public}s: BindServiceRender failed \n", __func__);
            dlclose(ctlRenFuzzPtrHandle);
            return false;
        }
        InterfaceLibCtlRender = reinterpret_cast<int32_t (*)(struct DevHandle *, int,
            struct AudioHwRenderParam *)>(dlsym(ctlRenFuzzPtrHandle, "AudioInterfaceLibCtlRender"));
        if (InterfaceLibCtlRender == nullptr) {
            HDF_LOGE("%{public}s: dlsym AudioInterfaceLibCtlRender failed \n", __func__);
            dlclose(ctlRenFuzzPtrHandle);
            return false;
        }
        struct AudioHwRender *hwRender = nullptr;
        (void)BindServiceAndHwRender(hwRender);
        hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
        if (size < sizeof(int32_t)) {
            return false;
        }
        int32_t cmdId = *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data)));
        int32_t ret = InterfaceLibCtlRender(handle, cmdId, &hwRender->renderParam);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        free(hwRender);
        void (*CloseService)(const struct DevHandle *) = nullptr;
        CloseService = reinterpret_cast<void (*)(const struct DevHandle *)>(dlsym(ctlRenFuzzPtrHandle,
            "AudioCloseServiceRender"));
        if (CloseService == nullptr) {
            HDF_LOGE("%{public}s:dlsym AudioCloseServiceRender failed \n", __func__);
            dlclose(ctlRenFuzzPtrHandle);
            return false;
        }
        CloseService(handle);
        dlclose(ctlRenFuzzPtrHandle);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioInterfacelibctlrenderCmdidFuzzTest(data, size);
    return 0;
}