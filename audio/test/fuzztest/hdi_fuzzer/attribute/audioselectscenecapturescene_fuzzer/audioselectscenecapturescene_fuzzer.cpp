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

#include "audioselectscenecapturescene_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioSelectSceneCaptureSceneFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *selSceneCapManager = nullptr;
        struct AudioAdapter *selSceneCapAdapter = nullptr;
        struct AudioCapture *selSceneCapCapture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(selSceneCapManager, &selSceneCapAdapter, &selSceneCapCapture);
        if (ret < 0 || selSceneCapAdapter == nullptr ||
            selSceneCapCapture == nullptr || selSceneCapManager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
            return false;
        }

        struct AudioSceneDescriptor sceneFuzzDesc = {};
        int32_t copySize = sizeof(sceneFuzzDesc) > size ? size : sizeof(sceneFuzzDesc);
        if (memcpy_s((void *)&sceneFuzzDesc, sizeof(sceneFuzzDesc), data, copySize) != 0) {
            return false;
        }
        ret = selSceneCapCapture->scene.SelectScene(selSceneCapCapture, &sceneFuzzDesc);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        selSceneCapAdapter->DestroyCapture(selSceneCapAdapter, selSceneCapCapture);
        selSceneCapManager->UnloadAdapter(selSceneCapManager, selSceneCapAdapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSelectSceneCaptureSceneFuzzTest(data, size);
    return 0;
}