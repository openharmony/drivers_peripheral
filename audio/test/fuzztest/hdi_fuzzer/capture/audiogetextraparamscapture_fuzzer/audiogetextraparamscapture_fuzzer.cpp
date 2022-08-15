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

#include "audiogetextraparamscapture_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetextraparamsCaptureFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *getextFuzzManager = nullptr;
    struct AudioAdapter *getextFuzzAdapter = nullptr;
    struct AudioCapture *getextFuzzCapture = nullptr;
    int32_t ret = AudioGetManagerCreateStartCapture(getextFuzzManager, &getextFuzzAdapter, &getextFuzzCapture);
    if (ret < 0 || getextFuzzAdapter == nullptr || getextFuzzCapture == nullptr || getextFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartCapture failed \n", __func__);
        return false;
    }
    char keyValueList[] = "attr-route=1;attr-format=32;attr-channels=2;attr-frame-count=82;attr-sampling-rate=48000";
    char keyValueListValue[256] = {};
    int32_t listLenth = 256;
    ret = getextFuzzCapture->attr.SetExtraParams(getextFuzzCapture, keyValueList);
    if (ret < 0) {
        getextFuzzAdapter->DestroyCapture(getextFuzzAdapter, getextFuzzCapture);
        getextFuzzManager->UnloadAdapter(getextFuzzManager, getextFuzzAdapter);
        HDF_LOGE("%{public}s: SetExtraParams failed \n", __func__);
        return false;
    }
    uint8_t *dataFuzz = const_cast<uint8_t *>(data);
    struct AudioCapture *captureFuzz = reinterpret_cast<struct AudioCapture *>(dataFuzz);
    ret = getextFuzzCapture->attr.GetExtraParams(captureFuzz, keyValueListValue, listLenth);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    getextFuzzCapture->control.Stop((AudioHandle)getextFuzzCapture);
    getextFuzzAdapter->DestroyCapture(getextFuzzAdapter, getextFuzzCapture);
    getextFuzzManager->UnloadAdapter(getextFuzzManager, getextFuzzAdapter);
    getextFuzzCapture = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetextraparamsCaptureFuzzTest(data, size);
    return 0;
}