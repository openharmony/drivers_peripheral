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

#include "audiocheckscenecapabilitycapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioCheckSceneCapabilityCaptureFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        bool supported = false;
        struct AudioSceneDescriptor scenes = {};
        scenes.scene.id = 0;
        TestAudioManager *checkSceneFuzzManager = nullptr;
        struct AudioAdapter *checkSceneFuzzAdapter = nullptr;
        struct AudioCapture *checkSceneFuzzCapture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(checkSceneFuzzManager,
            &checkSceneFuzzAdapter, &checkSceneFuzzCapture);
        if (ret < 0 || checkSceneFuzzAdapter == nullptr ||
            checkSceneFuzzCapture == nullptr || checkSceneFuzzManager == nullptr) {
            return false;
        }

        struct AudioCapture *handle = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
        ret = checkSceneFuzzCapture->scene.CheckSceneCapability(handle, &scenes, &supported);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        checkSceneFuzzAdapter->DestroyCapture(checkSceneFuzzAdapter, checkSceneFuzzCapture);
        checkSceneFuzzManager->UnloadAdapter(checkSceneFuzzManager, checkSceneFuzzAdapter);

        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCheckSceneCapabilityCaptureFuzzTest(data, size);
    return 0;
}