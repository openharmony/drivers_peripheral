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

#include "audiogetcapturepositioncapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetcapturepositionCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *getCapPosFuzzManager = nullptr;
    struct AudioAdapter *getCapPosFuzzAdapter = nullptr;
    struct AudioCapture *getCapPosFuzzCapture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(getCapPosFuzzManager, &getCapPosFuzzAdapter, &getCapPosFuzzCapture);
    if (ret < 0 || getCapPosFuzzAdapter == nullptr ||
        getCapPosFuzzCapture == nullptr || getCapPosFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartCapture failed \n", __func__);
        return false;
    }
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_LENTH;
    struct AudioTimeStamp time = {.tvSec = 0, .tvNSec = 0};
    char *frame = reinterpret_cast<char *>(calloc(1, BUFFER_LENTH));
    if (frame == nullptr) {
        getCapPosFuzzCapture->control.Stop((AudioHandle)getCapPosFuzzCapture);
        getCapPosFuzzAdapter->DestroyCapture(getCapPosFuzzAdapter, getCapPosFuzzCapture);
        getCapPosFuzzManager->UnloadAdapter(getCapPosFuzzManager, getCapPosFuzzAdapter);
        return false;
    }
    ret = getCapPosFuzzCapture->CaptureFrame(getCapPosFuzzCapture, frame, requestBytes, &replyBytes);
    if (ret < 0) {
        getCapPosFuzzAdapter->DestroyCapture(getCapPosFuzzAdapter, getCapPosFuzzCapture);
        getCapPosFuzzManager->UnloadAdapter(getCapPosFuzzManager, getCapPosFuzzAdapter);
        getCapPosFuzzCapture = nullptr;
        return false;
    }

    replyBytes = 0;
    struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = getCapPosFuzzCapture->GetCapturePosition(captureFuzz, &replyBytes, &time);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    getCapPosFuzzCapture->control.Stop((AudioHandle)getCapPosFuzzCapture);
    getCapPosFuzzAdapter->DestroyCapture(getCapPosFuzzAdapter, getCapPosFuzzCapture);
    getCapPosFuzzManager->UnloadAdapter(getCapPosFuzzManager, getCapPosFuzzAdapter);
    getCapPosFuzzCapture = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetcapturepositionCaptureFuzzTest(data, size);
    return 0;
}