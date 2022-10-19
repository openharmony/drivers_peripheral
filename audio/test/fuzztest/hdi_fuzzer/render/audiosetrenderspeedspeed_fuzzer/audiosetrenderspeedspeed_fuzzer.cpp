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

#include "audiosetrenderspeedspeed_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetrenderspeedSpeedFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *setSpeedManager = nullptr;
    struct AudioAdapter *setSpeedAdapter = nullptr;
    struct AudioRender *setSpeedRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(setSpeedManager, &setSpeedAdapter, &setSpeedRender);
    if (ret < 0 || setSpeedAdapter == nullptr || setSpeedRender == nullptr || setSpeedManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }

    float speedFuzz = *(reinterpret_cast<float *>(const_cast<uint8_t *>(data)));
    ret = setSpeedRender->SetRenderSpeed(setSpeedRender, speedFuzz);
    if (ret == HDF_ERR_NOT_SUPPORT) {
        result = true;
    }
    setSpeedRender->control.Stop((AudioHandle)setSpeedRender);
    setSpeedAdapter->DestroyRender(setSpeedAdapter, setSpeedRender);
    setSpeedManager->UnloadAdapter(setSpeedManager, setSpeedAdapter);
    setSpeedRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetrenderspeedSpeedFuzzTest(data, size);
    return 0;
}