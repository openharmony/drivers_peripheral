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

#include "audioresumerender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioResumeRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *resumeFuzzManager = nullptr;
    struct AudioAdapter *resumeFuzzAdapter = nullptr;
    struct AudioRender *resumeFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(resumeFuzzManager, &resumeFuzzAdapter, &resumeFuzzRender);
    if (ret < 0 || resumeFuzzAdapter == nullptr || resumeFuzzRender == nullptr || resumeFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    ret = resumeFuzzRender->control.Pause((AudioHandle)resumeFuzzRender);
    if (ret < 0) {
        resumeFuzzAdapter->DestroyRender(resumeFuzzAdapter, resumeFuzzRender);
        resumeFuzzManager->UnloadAdapter(resumeFuzzManager, resumeFuzzAdapter);
        resumeFuzzRender = nullptr;
        HDF_LOGE("%{public}s: Pause failed \n", __func__);
        return false;
    }

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = resumeFuzzRender->control.Resume((AudioHandle)renderFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    resumeFuzzRender->control.Stop((AudioHandle)resumeFuzzRender);
    resumeFuzzAdapter->DestroyRender(resumeFuzzAdapter, resumeFuzzRender);
    resumeFuzzManager->UnloadAdapter(resumeFuzzManager, resumeFuzzAdapter);
    resumeFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioResumeRenderFuzzTest(data, size);
    return 0;
}