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
#include "audio_hdi_fuzzer_common.h"
#include "audiodestroyrenderadapter_fuzzer.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioDestroyrenderAdapterFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *destroyFuzzManager = nullptr;
    struct AudioAdapter *destroyFuzzAdapter = nullptr;
    struct AudioRender *destroyFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateRender(destroyFuzzManager, &destroyFuzzAdapter, &destroyFuzzRender);
    if (ret < 0 || destroyFuzzAdapter == nullptr || destroyFuzzRender == nullptr || destroyFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateRender failed \n", __func__);
        return false;
    }

    struct AudioAdapter *adapterFuzz = (struct AudioAdapter *)data;
    ret = destroyFuzzAdapter->DestroyRender(adapterFuzz, destroyFuzzRender);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    destroyFuzzAdapter->DestroyRender(destroyFuzzAdapter, destroyFuzzRender);
    destroyFuzzManager->UnloadAdapter(destroyFuzzManager, destroyFuzzAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioDestroyrenderAdapterFuzzTest(data, size);
    return 0;
}