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

#include "audiorenderframerender_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioRenderframeRenderFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *renFrameFuzzManager = nullptr;
    struct AudioAdapter *renFrameFuzzAdapter = nullptr;
    struct AudioRender *renFrameFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(renFrameFuzzManager, &renFrameFuzzAdapter, &renFrameFuzzRender);
    if (ret < 0 || renFrameFuzzAdapter == nullptr ||
        renFrameFuzzRender == nullptr || renFrameFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    uint64_t replyBytes = 0;
    uint64_t requestBytes = BUFFER_LENTH;
    char *frame = reinterpret_cast<char *>(calloc(1, BUFFER_LENTH));
    if (frame == nullptr) {
        renFrameFuzzRender->control.Stop((AudioHandle)renFrameFuzzRender);
        renFrameFuzzAdapter->DestroyRender(renFrameFuzzAdapter, renFrameFuzzRender);
        renFrameFuzzManager->UnloadAdapter(renFrameFuzzManager, renFrameFuzzAdapter);
        return false;
    }

    struct AudioRender *renderFuzz = reinterpret_cast<struct AudioRender *>(const_cast<uint8_t *>(data));
    ret = renFrameFuzzRender->RenderFrame(renderFuzz, frame, requestBytes, &replyBytes);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    renFrameFuzzRender->control.Stop((AudioHandle)renFrameFuzzRender);
    renFrameFuzzAdapter->DestroyRender(renFrameFuzzAdapter, renFrameFuzzRender);
    renFrameFuzzManager->UnloadAdapter(renFrameFuzzManager, renFrameFuzzAdapter);
    renFrameFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioRenderframeRenderFuzzTest(data, size);
    return 0;
}