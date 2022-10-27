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

#include "audiosetgainrendergain_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetgainRenderGainFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *gainRenManager = nullptr;
    struct AudioAdapter *gainRenAdapter = nullptr;
    struct AudioRender *gainRenRender = nullptr;
    int32_t ret = AudioGetManagerCreateRender(gainRenManager, &gainRenAdapter, &gainRenRender);
    if (ret < 0 || gainRenAdapter == nullptr || gainRenRender == nullptr || gainRenManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateRender failed \n", __func__);
        return false;
    }
    int32_t gain = *(reinterpret_cast<int32_t *>(const_cast<uint8_t *>(data)));
    ret = gainRenRender->volume.SetGain(gainRenRender, gain);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    gainRenAdapter->DestroyRender(gainRenAdapter, gainRenRender);
    gainRenManager->UnloadAdapter(gainRenManager, gainRenAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetgainRenderGainFuzzTest(data, size);
    return 0;
}