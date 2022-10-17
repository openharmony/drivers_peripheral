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
#include "audiodestroyrenderrender_fuzzer.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioDestroyrenderRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *destroyFuzzManager = nullptr;
    int32_t ret = GetManager(destroyFuzzManager);
    if (ret < 0 || destroyFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: GetManager failed \n", __func__);
        return false;
    }
    struct AudioAdapter *destroyFuzzAdapter = nullptr;
    struct AudioPort *renderPort = nullptr;
    ret = GetLoadAdapter(destroyFuzzManager, &destroyFuzzAdapter, renderPort);
    if (ret < 0 || destroyFuzzAdapter == nullptr) {
        HDF_LOGE("%{public}s: GetLoadAdapter failed \n", __func__);
        return false;
    }

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = destroyFuzzAdapter->DestroyRender(destroyFuzzAdapter, renderFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    destroyFuzzManager->UnloadAdapter(destroyFuzzManager, destroyFuzzAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioDestroyrenderRenderFuzzTest(data, size);
    return 0;
}