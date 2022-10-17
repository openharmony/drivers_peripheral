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

#include "audiogetlatencyrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetlatencyRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *getLatRenFuzzManager = nullptr;
    struct AudioAdapter *getLatRenFuzzAdapter = nullptr;
    struct AudioRender *getLatRenFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(getLatRenFuzzManager, &getLatRenFuzzAdapter, &getLatRenFuzzRender);
    if (ret < 0 || getLatRenFuzzAdapter == nullptr ||
        getLatRenFuzzRender == nullptr || getLatRenFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    uint32_t latencyTime = 0;

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = getLatRenFuzzRender->GetLatency(renderFuzz, &latencyTime);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    getLatRenFuzzRender->control.Stop((AudioHandle)getLatRenFuzzRender);
    getLatRenFuzzAdapter->DestroyRender(getLatRenFuzzAdapter, getLatRenFuzzRender);
    getLatRenFuzzManager->UnloadAdapter(getLatRenFuzzManager, getLatRenFuzzAdapter);
    getLatRenFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetlatencyRenderFuzzTest(data, size);
    return 0;
}

