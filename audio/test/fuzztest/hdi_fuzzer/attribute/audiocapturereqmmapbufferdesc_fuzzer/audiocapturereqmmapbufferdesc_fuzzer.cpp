/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "audiocapturereqmmapbufferdesc_fuzzer.h"
#include "securec.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioCaptureReqmmapbufferDescFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *manager = nullptr;
        struct AudioAdapter *adapter = nullptr;
        struct AudioCapture *capture = nullptr;
        int32_t ret = AudioGetManagerCreateStartCapture(manager, &adapter, &capture);
        if (ret < 0 || adapter == nullptr || capture == nullptr || manager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateStartCapture failed \n", __func__);
            return false;
        }

        struct AudioMmapBufferDescripter descFuzz = {};
        if (memcpy_s((void *)&descFuzz, sizeof(descFuzz), data, sizeof(descFuzz)) != 0) {
            return false;
        }
        ret = capture->attr.ReqMmapBuffer((AudioHandle)capture, size, &descFuzz);
        if (ret == HDF_SUCCESS) {
            (void)munmap(descFuzz.memoryAddress, size);
            result = true;
        }
        adapter->DestroyCapture(adapter, capture);
        manager->UnloadAdapter(manager, adapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCaptureReqmmapbufferDescFuzzTest(data, size);
    return 0;
}