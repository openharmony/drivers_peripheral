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

#include "audiogetgainthresholdrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetgainthresholdRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    float min = 0;
    float max = 0;
    TestAudioManager *geGainRenManager = nullptr;
    struct AudioAdapter *geGainRenAdapter = nullptr;
    struct AudioRender *geGainRenRender = nullptr;
    int32_t ret = AudioGetManagerCreateRender(geGainRenManager, &geGainRenAdapter, &geGainRenRender);
    if (ret < 0 || geGainRenAdapter == nullptr || geGainRenRender == nullptr || geGainRenManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateRender failed \n", __func__);
        return false;
    }

    struct AudioRender *handle = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = geGainRenRender->volume.GetGainThreshold(handle, &min, &max);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    geGainRenAdapter->DestroyRender(geGainRenAdapter, geGainRenRender);
    geGainRenManager->UnloadAdapter(geGainRenManager, geGainRenAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetgainthresholdRenderFuzzTest(data, size);
    return 0;
}