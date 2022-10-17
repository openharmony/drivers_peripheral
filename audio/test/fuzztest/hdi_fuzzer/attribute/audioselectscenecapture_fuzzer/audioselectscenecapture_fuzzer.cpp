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

#include "audioselectscenecapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioSelectSceneCaptureFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        struct AudioSceneDescriptor scenes = {};
        scenes.scene.id = 0;
        TestAudioManager *selSceneManager = nullptr;
        struct AudioAdapter *selSceneAdapter = nullptr;
        struct AudioCapture *capture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(selSceneManager, &selSceneAdapter, &capture);
        if (ret < 0 || selSceneAdapter == nullptr || capture == nullptr || selSceneManager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
            return false;
        }

        struct AudioCapture *handle = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
        ret = capture->scene.SelectScene(handle, &scenes);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        selSceneAdapter->DestroyCapture(selSceneAdapter, capture);
        selSceneManager->UnloadAdapter(selSceneManager, selSceneAdapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSelectSceneCaptureFuzzTest(data, size);
    return 0;
}