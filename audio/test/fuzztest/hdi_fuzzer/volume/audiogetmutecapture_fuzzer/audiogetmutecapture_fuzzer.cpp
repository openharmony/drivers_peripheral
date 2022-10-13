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

#include "audiogetmutecapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetmuteCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    bool mute = false;
    TestAudioManager *geMuteCapManager = nullptr;
    struct AudioAdapter *geMuteCapAdapter = nullptr;
    struct AudioCapture *geMuteCapCapture = nullptr;
    int32_t ret = AudioGetManagerCreateCapture(geMuteCapManager, &geMuteCapAdapter, &geMuteCapCapture);
    if (ret < 0 || geMuteCapAdapter == nullptr || geMuteCapCapture == nullptr || geMuteCapManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateCapture failed \n", __func__);
        return false;
    }

    struct AudioCapture *handle = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = geMuteCapCapture->volume.GetMute(handle, &mute);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    geMuteCapAdapter->DestroyCapture(geMuteCapAdapter, geMuteCapCapture);
    geMuteCapManager->UnloadAdapter(geMuteCapManager, geMuteCapAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetmuteCaptureFuzzTest(data, size);
    return 0;
}