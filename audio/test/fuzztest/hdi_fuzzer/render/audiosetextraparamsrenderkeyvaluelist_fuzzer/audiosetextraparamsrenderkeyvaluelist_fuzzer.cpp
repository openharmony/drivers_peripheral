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

#include "audiosetextraparamsrenderkeyvaluelist_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetextraparamsRenderKeyvaluelistFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *renKeyValueManager = nullptr;
    struct AudioAdapter *renKeyValueAdapter = nullptr;
    struct AudioRender *renKeyValueRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(renKeyValueManager, &renKeyValueAdapter, &renKeyValueRender);
    if (ret < 0 || renKeyValueAdapter == nullptr || renKeyValueRender == nullptr || renKeyValueManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    char *keyValueListFuzz = reinterpret_cast<char *>(const_cast<uint8_t *>(data));
    ret = renKeyValueRender->attr.SetExtraParams(renKeyValueRender, keyValueListFuzz);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    renKeyValueRender->control.Stop((AudioHandle)renKeyValueRender);
    renKeyValueAdapter->DestroyRender(renKeyValueAdapter, renKeyValueRender);
    renKeyValueManager->UnloadAdapter(renKeyValueManager, renKeyValueAdapter);
    renKeyValueRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetextraparamsRenderKeyvaluelistFuzzTest(data, size);
    return 0;
}