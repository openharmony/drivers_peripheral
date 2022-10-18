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

#include "audiorendergetmmappositionrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioRenderGetmmappositionRenderFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *getMmapPosManager = nullptr;
        struct AudioAdapter *adapter = nullptr;
        struct AudioRender *render = nullptr;
        int32_t ret = AudioGetManagerCreateRender(getMmapPosManager, &adapter, &render);
        if (ret < 0 || adapter == nullptr || render == nullptr || getMmapPosManager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateRender failed \n", __func__);
            return false;
        }
        uint64_t frames = 0;
        struct AudioTimeStamp time = {};
        struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
        ret = render->attr.GetMmapPosition(renderFuzz, &frames, &time);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        adapter->DestroyRender(adapter, render);
        getMmapPosManager->UnloadAdapter(getMmapPosManager, adapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioRenderGetmmappositionRenderFuzzTest(data, size);
    return 0;
}