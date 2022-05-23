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

#include "audioselectscenerender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioSelectSceneRenderFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        struct AudioSceneDescriptor scenes = {};
        scenes.scene.id = 0;
        TestAudioManager *manager = nullptr;
        struct AudioAdapter *adapter = nullptr;
        struct AudioRender *render = nullptr;
        int32_t ret = AudioGetManagerCreateRender(manager, &adapter, &render);
        if (ret < 0 || adapter == nullptr || render == nullptr || manager == nullptr) {
            return false;
        }

        struct AudioRender *handle = (struct AudioRender *)data;
        ret = render->scene.SelectScene(handle, &scenes);
        if (ret == HDF_SUCCESS) {
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
    OHOS::Audio::AudioSelectSceneRenderFuzzTest(data, size);
    return 0;
}