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

#include "audiogetsampleattributescapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioGetSampleAttributesCaptureFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *attributesManager = nullptr;
        struct AudioAdapter *attributesadapter = nullptr;
        struct AudioCapture *capture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(attributesManager, &attributesadapter, &capture);
        if (ret < 0 || attributesadapter == nullptr || capture == nullptr || attributesManager == nullptr) {
            return false;
        }
        struct AudioSampleAttributes attrs = {};

        struct AudioCapture *handle = reinterpret_cast<struct AudioCapture *>(const_cast<uint8_t *>(data));
        ret = capture->attr.SetSampleAttributes(handle, &attrs);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        attributesadapter->DestroyCapture(attributesadapter, capture);
        attributesManager->UnloadAdapter(attributesManager, attributesadapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetSampleAttributesCaptureFuzzTest(data, size);
    return 0;
}