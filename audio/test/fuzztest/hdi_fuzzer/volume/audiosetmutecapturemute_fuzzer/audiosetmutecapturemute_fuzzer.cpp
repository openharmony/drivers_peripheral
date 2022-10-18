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

#include "audiosetmutecapturemute_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetmuteCaptureMuteFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *muteCapManager = nullptr;
    struct AudioAdapter *muteCapAdapter = nullptr;
    struct AudioCapture *muteCapCapture = nullptr;
    int32_t ret = AudioGetManagerCreateCapture(muteCapManager, &muteCapAdapter, &muteCapCapture);
    if (ret < 0 || muteCapAdapter == nullptr || muteCapCapture == nullptr || muteCapManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
        return false;
    }

    bool mute = *(reinterpret_cast<bool *>(const_cast<uint8_t *>(data)));
    ret = muteCapCapture->volume.SetVolume(muteCapCapture, mute);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    muteCapAdapter->DestroyCapture(muteCapAdapter, muteCapCapture);
    muteCapManager->UnloadAdapter(muteCapManager, muteCapAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetmuteCaptureMuteFuzzTest(data, size);
    return 0;
}