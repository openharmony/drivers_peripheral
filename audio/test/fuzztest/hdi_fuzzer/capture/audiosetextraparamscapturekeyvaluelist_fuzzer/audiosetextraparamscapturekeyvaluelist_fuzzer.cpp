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

#include "audiosetextraparamscapturekeyvaluelist_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetextraparamsCaptureKeyvaluelistFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *capKeyValueFuzzManager = nullptr;
    struct AudioAdapter *capKeyValueFuzzAdapter = nullptr;
    struct AudioCapture *capKeyValueFuzzCapture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(capKeyValueFuzzManager,
        &capKeyValueFuzzAdapter, &capKeyValueFuzzCapture);
    if (ret < 0 || capKeyValueFuzzAdapter == nullptr ||
        capKeyValueFuzzCapture == nullptr || capKeyValueFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartCapture failed \n", __func__);
        return false;
    }
    char *keyValueListFuzz = reinterpret_cast<char *>(const_cast<uint8_t *>(data));
    ret = capKeyValueFuzzCapture->attr.SetExtraParams(capKeyValueFuzzCapture, keyValueListFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }

    capKeyValueFuzzCapture->control.Stop((AudioHandle)capKeyValueFuzzCapture);
    capKeyValueFuzzAdapter->DestroyCapture(capKeyValueFuzzAdapter, capKeyValueFuzzCapture);
    capKeyValueFuzzManager->UnloadAdapter(capKeyValueFuzzManager, capKeyValueFuzzAdapter);
    capKeyValueFuzzCapture = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetextraparamsCaptureKeyvaluelistFuzzTest(data, size);
    return 0;
}