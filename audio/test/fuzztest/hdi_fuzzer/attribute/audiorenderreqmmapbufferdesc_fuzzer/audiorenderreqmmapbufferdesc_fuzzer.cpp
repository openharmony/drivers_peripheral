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
#include "securec.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioRenderReqmmapbufferDescFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *renderReqManager = nullptr;
        struct AudioAdapter *adapter = nullptr;
        struct AudioRender *render = nullptr;
        int32_t ret = AudioGetManagerCreateStartRender(renderReqManager, &adapter, &render);
        if (ret < 0 || adapter == nullptr || render == nullptr || renderReqManager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
            return false;
        }
        uint8_t *temp = const_cast<uint8_t *>(data);
        struct AudioMmapBufferDescripter descFuzz {
            .memoryAddress = reinterpret_cast<void *>(temp),
            .memoryFd = *(reinterpret_cast<int32_t *>(temp)),
            .totalBufferFrames = *(reinterpret_cast<int32_t *>(temp)),
            .transferFrameSize = *(reinterpret_cast<int32_t *>(temp)),
            .isShareable = *(reinterpret_cast<int32_t *>(temp)),
            .offset = *reinterpret_cast<uint32_t *>(temp),
        };

        ret = render->attr.ReqMmapBuffer((AudioHandle)render, size, &descFuzz);
        if (ret == HDF_SUCCESS) {
            (void)munmap(descFuzz.memoryAddress, size);
            result = true;
        }
        adapter->DestroyRender(adapter, render);
        renderReqManager->UnloadAdapter(renderReqManager, adapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioRenderReqmmapbufferDescFuzzTest(data, size);
    return 0;
}