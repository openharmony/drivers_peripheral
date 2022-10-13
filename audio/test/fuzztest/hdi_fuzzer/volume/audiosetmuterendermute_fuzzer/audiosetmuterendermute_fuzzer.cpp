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

#include "audiosetmuterendermute_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetmuteRenderMuteFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *muteRenManager = nullptr;
    struct AudioAdapter *muteRenAdapter = nullptr;
    struct AudioRender *muteRenRender = nullptr;
    int32_t ret = AudioGetManagerCreateRender(muteRenManager, &muteRenAdapter, &muteRenRender);
    if (ret < 0 || muteRenAdapter == nullptr || muteRenRender == nullptr || muteRenManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateRender failed \n", __func__);
        return false;
    }

    bool mute = *(reinterpret_cast<bool *>(const_cast<uint8_t *>(data)));
    ret = muteRenRender->volume.SetVolume(muteRenRender, mute);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    muteRenAdapter->DestroyRender(muteRenAdapter, muteRenRender);
    muteRenManager->UnloadAdapter(muteRenManager, muteRenAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetmuteRenderMuteFuzzTest(data, size);
    return 0;
}