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

#include "audiogetchannelmoderender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetchannelmodeRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *getChannelFuzzManager = nullptr;
    struct AudioAdapter *getChannelFuzzAdapter = nullptr;
    struct AudioRender *getChannelFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(getChannelFuzzManager,
        &getChannelFuzzAdapter, &getChannelFuzzRender);
    if (ret < 0 || getChannelFuzzAdapter == nullptr ||
        getChannelFuzzRender == nullptr || getChannelFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    AudioChannelMode mode = AUDIO_CHANNEL_NORMAL;

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = getChannelFuzzRender->GetChannelMode(renderFuzz, &mode);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    getChannelFuzzRender->control.Stop((AudioHandle)getChannelFuzzRender);
    getChannelFuzzAdapter->DestroyRender(getChannelFuzzAdapter, getChannelFuzzRender);
    getChannelFuzzManager->UnloadAdapter(getChannelFuzzManager, getChannelFuzzAdapter);
    getChannelFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetchannelmodeRenderFuzzTest(data, size);
    return 0;
}