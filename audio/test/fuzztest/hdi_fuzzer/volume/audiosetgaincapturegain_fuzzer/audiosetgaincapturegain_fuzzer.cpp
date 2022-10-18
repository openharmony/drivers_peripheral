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

#include "audiosetgaincapturegain_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetgainCaptureGainFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *gainCapFuzzManager = nullptr;
    struct AudioAdapter *gainCapFuzzAdapter = nullptr;
    struct AudioCapture *gainCapFuzzCapture = nullptr;
    int32_t ret = AudioGetManagerCreateCapture(gainCapFuzzManager, &gainCapFuzzAdapter, &gainCapFuzzCapture);
    if (ret < 0 || gainCapFuzzAdapter == nullptr || gainCapFuzzCapture == nullptr || gainCapFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
        return false;
    }
    int32_t gain = *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data)));
    ret = gainCapFuzzCapture->volume.SetGain(gainCapFuzzCapture, gain);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    gainCapFuzzAdapter->DestroyCapture(gainCapFuzzAdapter, gainCapFuzzCapture);
    gainCapFuzzManager->UnloadAdapter(gainCapFuzzManager, gainCapFuzzAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetgainCaptureGainFuzzTest(data, size);
    return 0;
}