/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "audio_adm_fuzzer_common.h"

using namespace HMOS::Audio;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char resolvedPath[] = "//system/lib/libhdi_audio_interface_lib_render.z.so";
    void *PtrHandle = dlopen(resolvedPath, RTLD_LAZY);
    if (PtrHandle == nullptr) {
        return HDF_FAILURE;
    }
    struct DevHandle *(*BindServiceRender)(const char *) = nullptr;
    int32_t (*InterfaceLibCtlRender)(struct DevHandle *, int, struct AudioHwRenderParam *) = nullptr;
    BindServiceRender = (struct DevHandle *(*)(const char *))dlsym(PtrHandle, "AudioBindServiceRender");
    if (BindServiceRender == nullptr) {
        dlclose(PtrHandle);
        return HDF_FAILURE;
    }
    struct DevHandle *handle = nullptr;
    handle = BindServiceRender(BIND_CONTROL.c_str());
    if (handle == nullptr) {
        dlclose(PtrHandle);
        return HDF_FAILURE;
    }
    InterfaceLibCtlRender = (int32_t (*)(struct DevHandle *, int,
        struct AudioHwRenderParam *))dlsym(PtrHandle, "AudioInterfaceLibCtlRender");
    if (InterfaceLibCtlRender == nullptr) {
        dlclose(PtrHandle);
        return HDF_FAILURE;
    }
    struct AudioHwRender *hwRender = nullptr;
    int32_t ret = BindServiceAndHwRender(hwRender);
    hwRender->renderParam.renderMode.hwInfo.card = AUDIO_SERVICE_IN;
    InterfaceLibCtlRender(handle, size, &hwRender->renderParam);
    free(hwRender);
    void (*CloseService)(const struct DevHandle *) = nullptr;
    CloseService = (void (*)(const struct DevHandle *))dlsym(PtrHandle, "AudioCloseServiceRender");
    if (CloseService == nullptr) {
        dlclose(PtrHandle);
        return HDF_FAILURE;
    }
    CloseService(handle);
    dlclose(PtrHandle);
    return ret;
}
