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

#include "audioresumecapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioResumeCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *resumeFuzzManager = nullptr;
    struct AudioAdapter *resumeFuzzAdapter = nullptr;
    struct AudioCapture *resumeFuzzCapture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(resumeFuzzManager, &resumeFuzzAdapter, &resumeFuzzCapture);
    if (ret < 0 || resumeFuzzAdapter == nullptr || resumeFuzzCapture == nullptr || resumeFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartCapture failed \n", __func__);
        return false;
    }
    ret = resumeFuzzCapture->control.Pause((AudioHandle)resumeFuzzCapture);
    if (ret < 0) {
        resumeFuzzAdapter->DestroyCapture(resumeFuzzAdapter, resumeFuzzCapture);
        resumeFuzzManager->UnloadAdapter(resumeFuzzManager, resumeFuzzAdapter);
        resumeFuzzCapture = nullptr;
        HDF_LOGE("%{public}s: Pause failed \n", __func__);
        return false;
    }

    struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = resumeFuzzCapture->control.Resume((AudioHandle)captureFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    resumeFuzzCapture->control.Stop((AudioHandle)resumeFuzzCapture);
    resumeFuzzAdapter->DestroyCapture(resumeFuzzAdapter, resumeFuzzCapture);
    resumeFuzzManager->UnloadAdapter(resumeFuzzManager, resumeFuzzAdapter);
    resumeFuzzCapture = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioResumeCaptureFuzzTest(data, size);
    return 0;
}