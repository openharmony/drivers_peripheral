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

#include "audiogetrenderpositionrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetrenderpositionRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *getRenPosFuzzManager = nullptr;
    struct AudioAdapter *getRenPosFuzzAdapter = nullptr;
    struct AudioRender *getRenPosFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(getRenPosFuzzManager, &getRenPosFuzzAdapter, &getRenPosFuzzRender);
    if (ret < 0 || getRenPosFuzzAdapter == nullptr ||
        getRenPosFuzzRender == nullptr || getRenPosFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    uint64_t frames = 0;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = getRenPosFuzzRender->GetRenderPosition(renderFuzz, &frames, &time);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    getRenPosFuzzRender->control.Stop((AudioHandle)getRenPosFuzzRender);
    getRenPosFuzzAdapter->DestroyRender(getRenPosFuzzAdapter, getRenPosFuzzRender);
    getRenPosFuzzManager->UnloadAdapter(getRenPosFuzzManager, getRenPosFuzzAdapter);
    getRenPosFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetrenderpositionRenderFuzzTest(data, size);
    return 0;
}

