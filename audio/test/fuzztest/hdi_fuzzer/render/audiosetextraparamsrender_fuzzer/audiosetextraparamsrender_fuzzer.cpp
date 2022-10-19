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

#include "audiosetextraparamsrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioSetextraparamsRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *setExtFuzzManager = nullptr;
    struct AudioAdapter *setExtFuzzAdapter = nullptr;
    struct AudioRender *setExtFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(setExtFuzzManager, &setExtFuzzAdapter, &setExtFuzzRender);
    if (ret < 0 || setExtFuzzAdapter == nullptr || setExtFuzzRender == nullptr || setExtFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = setExtFuzzRender->attr.SetExtraParams(renderFuzz, keyValueList);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    setExtFuzzRender->control.Stop((AudioHandle)setExtFuzzRender);
    setExtFuzzAdapter->DestroyRender(setExtFuzzAdapter, setExtFuzzRender);
    setExtFuzzManager->UnloadAdapter(setExtFuzzManager, setExtFuzzAdapter);
    setExtFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetextraparamsRenderFuzzTest(data, size);
    return 0;
}