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

#include "audiogetgaincapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetgainCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    float gain = 0;
    TestAudioManager *getGainCapManager = nullptr;
    struct AudioAdapter *getGainCapAdapter = nullptr;
    struct AudioCapture *getGainCapCapture = nullptr;
    int32_t ret = AudioGetManagerCreateCapture(getGainCapManager, &getGainCapAdapter, &getGainCapCapture);
    if (ret < 0 || getGainCapAdapter == nullptr || getGainCapCapture == nullptr || getGainCapManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
        return false;
    }

    struct AudioCapture *handle = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = getGainCapCapture->volume.SetGain(handle, gain);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    getGainCapAdapter->DestroyCapture(getGainCapAdapter, getGainCapCapture);
    getGainCapManager->UnloadAdapter(getGainCapManager, getGainCapAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetgainCaptureFuzzTest(data, size);
    return 0;
}