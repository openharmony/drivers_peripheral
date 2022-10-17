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

#include "audiostopcapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioStopCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *stopFuzzManager = nullptr;
    struct AudioAdapter *stopFuzzAdapter = nullptr;
    struct AudioCapture *stopFuzzCapture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(stopFuzzManager, &stopFuzzAdapter, &stopFuzzCapture);
    if (ret < 0 || stopFuzzAdapter == nullptr || stopFuzzCapture == nullptr || stopFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartCapture failed \n", __func__);
        return false;
    }

    struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = stopFuzzCapture->control.Stop((AudioHandle)captureFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    stopFuzzAdapter->DestroyCapture(stopFuzzAdapter, stopFuzzCapture);
    stopFuzzManager->UnloadAdapter(stopFuzzManager, stopFuzzAdapter);
    stopFuzzCapture = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioStopCaptureFuzzTest(data, size);
    return 0;
}