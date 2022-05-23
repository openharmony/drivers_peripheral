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

#include "audiosetsampleattributescaptureattrs_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioSetSampleAttributesCaptureAttrsFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *manager = nullptr;
        struct AudioAdapter *adapter = nullptr;
        struct AudioCapture *capture = nullptr;
        int32_t ret = AudioGetManagerCreateCapture(manager, &adapter, &capture);
        if (ret < 0 || adapter == nullptr || capture == nullptr || manager == nullptr) {
            return false;
        }

    struct AudioSampleAttributes attrsFuzz {
        .type = *(AudioCategory *)data,
        .interleaved = *(bool *)data,
        .format = *(AudioFormat *)data,
        .sampleRate = *(uint32_t *)data,
        .channelCount = *(uint32_t *)data,
        .period = *(uint32_t *)data,
        .frameSize = *(uint32_t *)data,
        .isBigEndian = *(bool *)data,
        .isSignedData = *(bool *)data,
        .startThreshold = *(uint32_t *)data,
        .stopThreshold = *(uint32_t *)data,
        .silenceThreshold = *(uint32_t *)data,
    };
        ret = capture->attr.SetSampleAttributes(capture, &attrsFuzz);
        if (ret == HDF_SUCCESS) {
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
    OHOS::Audio::AudioSetSampleAttributesCaptureAttrsFuzzTest(data, size);
    return 0;
}