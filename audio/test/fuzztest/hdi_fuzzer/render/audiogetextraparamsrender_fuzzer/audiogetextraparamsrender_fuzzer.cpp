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

#include "audiogetextraparamsrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetextraparamsRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *getExtRenFuzzManager = nullptr;
    struct AudioAdapter *getExtRenFuzzAdapter = nullptr;
    struct AudioRender *getExtRenFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(getExtRenFuzzManager, &getExtRenFuzzAdapter, &getExtRenFuzzRender);
    if (ret < 0 || getExtRenFuzzAdapter == nullptr ||
        getExtRenFuzzRender == nullptr || getExtRenFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    ret = getExtRenFuzzRender->attr.SetExtraParams(getExtRenFuzzRender, keyValueList);
    if (ret < 0) {
        getExtRenFuzzAdapter->DestroyRender(getExtRenFuzzAdapter, getExtRenFuzzRender);
        getExtRenFuzzManager->UnloadAdapter(getExtRenFuzzManager, getExtRenFuzzAdapter);
        HDF_LOGE("%{public}s: SetExtraParams failed \n", __func__);
        return false;
    }

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = getExtRenFuzzRender->attr.GetExtraParams(renderFuzz, keyValueListValue, listLenth);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    getExtRenFuzzRender->control.Stop((AudioHandle)getExtRenFuzzRender);
    getExtRenFuzzAdapter->DestroyRender(getExtRenFuzzAdapter, getExtRenFuzzRender);
    getExtRenFuzzManager->UnloadAdapter(getExtRenFuzzManager, getExtRenFuzzAdapter);
    getExtRenFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetextraparamsRenderFuzzTest(data, size);
    return 0;
}