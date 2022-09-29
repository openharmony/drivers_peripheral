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

#include "audiosetvolumecapturevolume_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetvolumeCaptureVolumeFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *volCapManager = nullptr;
    struct AudioAdapter *volCapAdapter = nullptr;
    struct AudioCapture *volCapCapture = nullptr;
    int32_t ret = AudioGetManagerCreateCapture(volCapManager, &volCapAdapter, &volCapCapture);
    if (ret < 0 || volCapAdapter == nullptr || volCapCapture == nullptr || volCapManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
        return false;
    }
    int32_t volume = *(float *)data;
    ret = volCapCapture->volume.SetVolume(volCapCapture, volume);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    volCapAdapter->DestroyCapture(volCapAdapter, volCapCapture);
    volCapManager->UnloadAdapter(volCapManager, volCapAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetvolumeCaptureVolumeFuzzTest(data, size);
    return 0;
}