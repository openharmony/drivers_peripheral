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

#include "audiosetrenderspeedrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetrenderspeedRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *setRenSpeedManager = nullptr;
    struct AudioAdapter *setRenSpeedAdapter = nullptr;
    struct AudioRender *setRenSpeedRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(setRenSpeedManager, &setRenSpeedAdapter, &setRenSpeedRender);
    if (ret < 0 || setRenSpeedAdapter == nullptr || setRenSpeedRender == nullptr || setRenSpeedManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    float speed = 100;

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = setRenSpeedRender->SetRenderSpeed(renderFuzz, speed);
    if (ret == HDF_ERR_NOT_SUPPORT) {
        result = true;
    }
    setRenSpeedRender->control.Stop((AudioHandle)setRenSpeedRender);
    setRenSpeedAdapter->DestroyRender(setRenSpeedAdapter, setRenSpeedRender);
    setRenSpeedManager->UnloadAdapter(setRenSpeedManager, setRenSpeedAdapter);
    setRenSpeedRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetrenderspeedRenderFuzzTest(data, size);
    return 0;
}