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
    TestAudioManager *manager = nullptr;
    struct AudioAdapter *adapter = nullptr;
    struct AudioCapture *capture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(manager, &adapter, &capture);
    if (ret < 0 || adapter == nullptr || capture == nullptr || manager == nullptr) {
        return false;
    }

    struct AudioCapture *captureFuzz = (struct AudioCapture *)(data);
    ret = capture->control.Pause((AudioHandle)captureFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    capture->control.Stop((AudioHandle)capture);
    adapter->DestroyCapture(adapter, capture);
    manager->UnloadAdapter(manager, adapter);
    capture = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioPauseCaptureFuzzTest(data, size);
    return 0;
}