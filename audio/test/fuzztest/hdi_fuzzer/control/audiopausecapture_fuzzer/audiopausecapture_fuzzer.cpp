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

#include "audiopausecapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioPauseCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *pauseFuzzManager = nullptr;
    struct AudioAdapter *pauseFuzzAdapter = nullptr;
    struct AudioCapture *pauseFuzzCapture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(pauseFuzzManager, &pauseFuzzAdapter, &pauseFuzzCapture);
    if (ret < 0 || pauseFuzzAdapter == nullptr || pauseFuzzCapture == nullptr || pauseFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartCapture failed \n", __func__);
        return false;
    }

    struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = pauseFuzzCapture->control.Pause((AudioHandle)captureFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    pauseFuzzCapture->control.Stop((AudioHandle)pauseFuzzCapture);
    pauseFuzzAdapter->DestroyCapture(pauseFuzzAdapter, pauseFuzzCapture);
    pauseFuzzManager->UnloadAdapter(pauseFuzzManager, pauseFuzzAdapter);
    pauseFuzzCapture = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioPauseCaptureFuzzTest(data, size);
    return 0;
}