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

#include "audiocapturegetmmappositioncapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioCaptureGetmmappositionCaptureFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *positionFuzzManager = nullptr;
        struct AudioAdapter *positionFuzzAdapter = nullptr;
        struct AudioCapture *positionFuzzCapture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(positionFuzzManager, &positionFuzzAdapter, &positionFuzzCapture);
        if (ret < 0 || positionFuzzAdapter == nullptr ||
            positionFuzzCapture == nullptr || positionFuzzManager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
            return false;
        }
        uint64_t frames = 0;
        struct AudioTimeStamp time = {};
        struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
        ret = positionFuzzCapture->attr.GetMmapPosition(captureFuzz, &frames, &time);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        positionFuzzAdapter->DestroyCapture(positionFuzzAdapter, positionFuzzCapture);
        positionFuzzManager->UnloadAdapter(positionFuzzManager, positionFuzzAdapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCaptureGetmmappositionCaptureFuzzTest(data, size);
    return 0;
}