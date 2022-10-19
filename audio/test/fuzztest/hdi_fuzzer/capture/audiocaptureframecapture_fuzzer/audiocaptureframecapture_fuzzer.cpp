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

#include "audiocaptureframecapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioCaptureframeCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *capFrameFuzzManager = nullptr;
    struct AudioAdapter *capFrameFuzzAdapter = nullptr;
    struct AudioCapture *capFrameFuzzCapture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(capFrameFuzzManager, &capFrameFuzzAdapter, &capFrameFuzzCapture);
    if (ret < 0 || capFrameFuzzAdapter == nullptr ||
        capFrameFuzzCapture == nullptr || capFrameFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartCapture failed \n", __func__);
        return false;
    }
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_LENTH;
    char *frame = reinterpret_cast<char *>(calloc(1, BUFFER_LENTH));
    if (frame == nullptr) {
        capFrameFuzzCapture->control.Stop((AudioHandle)capFrameFuzzCapture);
        capFrameFuzzAdapter->DestroyCapture(capFrameFuzzAdapter, capFrameFuzzCapture);
        capFrameFuzzManager->UnloadAdapter(capFrameFuzzManager, capFrameFuzzAdapter);
        return false;
    }
    struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
    ret = capFrameFuzzCapture->CaptureFrame(captureFuzz, frame, requestBytes, &replyBytes);
    if (ret == HDF_SUCCESS) {
        result = true;
    }

    capFrameFuzzCapture->control.Stop((AudioHandle)capFrameFuzzCapture);
    capFrameFuzzAdapter->DestroyCapture(capFrameFuzzAdapter, capFrameFuzzCapture);
    capFrameFuzzManager->UnloadAdapter(capFrameFuzzManager, capFrameFuzzAdapter);
    capFrameFuzzCapture = nullptr;
    free(frame);
    frame = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCaptureframeCaptureFuzzTest(data, size);
    return 0;
}