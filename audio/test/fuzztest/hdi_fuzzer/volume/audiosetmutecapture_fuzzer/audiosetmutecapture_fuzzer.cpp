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

#include "audiosetmutecapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetmuteCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    bool mute = false;
    TestAudioManager *setMuteCapManager = nullptr;
    struct AudioAdapter *setMuteCapAdapter = nullptr;
    struct AudioCapture *setMuteCapCapture = nullptr;
    int32_t ret = AudioGetManagerCreateCapture(setMuteCapManager, &setMuteCapAdapter, &setMuteCapCapture);
    if (ret < 0 || setMuteCapAdapter == nullptr || setMuteCapCapture == nullptr || setMuteCapManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
        return false;
    }

    struct AudioCapture *handle = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = setMuteCapCapture->volume.SetMute(handle, mute);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    setMuteCapAdapter->DestroyCapture(setMuteCapAdapter, setMuteCapCapture);
    setMuteCapManager->UnloadAdapter(setMuteCapManager, setMuteCapAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetmuteCaptureFuzzTest(data, size);
    return 0;
}