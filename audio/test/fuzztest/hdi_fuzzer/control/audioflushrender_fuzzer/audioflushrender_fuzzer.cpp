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

#include "audioflushrender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioFlushRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *flushFuzzManager = nullptr;
    struct AudioAdapter *flushFuzzAdapter = nullptr;
    struct AudioRender *flushFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(flushFuzzManager, &flushFuzzAdapter, &flushFuzzRender);
    if (ret < 0 || flushFuzzAdapter == nullptr || flushFuzzRender == nullptr || flushFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    ret = flushFuzzRender->control.Stop((AudioHandle)flushFuzzRender);
    if (ret < 0) {
        flushFuzzAdapter->DestroyRender(flushFuzzAdapter, flushFuzzRender);
        flushFuzzManager->UnloadAdapter(flushFuzzManager, flushFuzzAdapter);
        flushFuzzRender = nullptr;
        HDF_LOGE("%{public}s: Stop failed \n", __func__);
        return false;
    }

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = flushFuzzRender->control.Flush((AudioHandle)renderFuzz);
    if (ret == HDF_ERR_NOT_SUPPORT) {
        result = true;
    }
    flushFuzzAdapter->DestroyRender(flushFuzzAdapter, flushFuzzRender);
    flushFuzzManager->UnloadAdapter(flushFuzzManager, flushFuzzAdapter);
    flushFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioFlushRenderFuzzTest(data, size);
    return 0;
}