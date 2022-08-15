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

#include "audiocheckscenecapabilityrenderscene_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioCheckSceneCapabilityRenderSceneFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        bool supported = false;
        struct AudioSceneDescriptor scenes = {};
        scenes.scene.id = 0;
        TestAudioManager *checkSceFuzzManager = nullptr;
        struct AudioAdapter *checkSceFuzzAdapter = nullptr;
        struct AudioRender *checkSceFuzzRender = nullptr;
        int32_t ret = AudioGetManagerCreateRender(checkSceFuzzManager, &checkSceFuzzAdapter, &checkSceFuzzRender);
        if (ret < 0 || checkSceFuzzAdapter == nullptr ||
            checkSceFuzzRender == nullptr || checkSceFuzzManager == nullptr) {
            return false;
        }

        struct AudioSceneDescriptor sceneFuzz = {};
        int32_t copySize = sizeof(sceneFuzz) > size ? size : sizeof(sceneFuzz);
        if (memcpy_s((void *)&sceneFuzz, sizeof(sceneFuzz), data, copySize) != 0) {
            return false;
        }
        ret = checkSceFuzzRender->scene.CheckSceneCapability(checkSceFuzzRender, &sceneFuzz, &supported);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        checkSceFuzzAdapter->DestroyRender(checkSceFuzzAdapter, checkSceFuzzRender);
        checkSceFuzzManager->UnloadAdapter(checkSceFuzzManager, checkSceFuzzAdapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCheckSceneCapabilityRenderSceneFuzzTest(data, size);
    return 0;
}