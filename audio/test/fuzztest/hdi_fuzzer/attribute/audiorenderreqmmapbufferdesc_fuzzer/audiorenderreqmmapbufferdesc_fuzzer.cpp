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

#include "audiorenderreqmmapbufferdesc_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioRenderReqmmapbufferDescFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *manager = nullptr;
        struct AudioAdapter *adapter = nullptr;
        struct AudioRender *render = nullptr;
        int32_t ret = AudioGetManagerCreateStartRender(manager, &adapter, &render);
        if (ret < 0 || adapter == nullptr || render == nullptr || manager == nullptr) {
            return false;
        }
        struct AudioMmapBufferDescripter descFuzz {
            .memoryAddress = (void *)data,
            .memoryFd = *(int32_t *)data,
            .totalBufferFrames = *(int32_t *)data,
            .transferFrameSize = *(int32_t *)data,
            .isShareable = *(int32_t *)data,
            .offset = *(uint32_t *)data,
        };

        ret = render->attr.ReqMmapBuffer((AudioHandle)render, size, &descFuzz);
        if (ret == HDF_SUCCESS) {
            (void)munmap(descFuzz.memoryAddress, size);
            result = true;
        }
        adapter->DestroyRender(adapter, render);
        manager->UnloadAdapter(manager, adapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioRenderReqmmapbufferDescFuzzTest(data, size);
    return 0;
}