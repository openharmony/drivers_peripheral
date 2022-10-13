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

#include "audiorenderframerequestbytes_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioRenderframeRequestbytesFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *renReqFuzzManager = nullptr;
    struct AudioAdapter *renFrameFuzzAdapter = nullptr;
    struct AudioRender *renFrameFuzzRender = nullptr;
    int32_t ret = AudioGetManagerCreateStartRender(renReqFuzzManager, &renFrameFuzzAdapter, &renFrameFuzzRender);
    if (ret < 0 || renFrameFuzzAdapter == nullptr || renFrameFuzzRender == nullptr || renReqFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: AudioGetManagerCreateStartRender failed \n", __func__);
        return false;
    }
    uint64_t replyBytes = 0;
    char *frame = reinterpret_cast<char *>(const_cast<uint8_t *>(data));
    ret = renFrameFuzzRender->RenderFrame(renFrameFuzzRender, frame, size, &replyBytes);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    renFrameFuzzRender->control.Stop((AudioHandle)renFrameFuzzRender);
    renFrameFuzzAdapter->DestroyRender(renFrameFuzzAdapter, renFrameFuzzRender);
    renReqFuzzManager->UnloadAdapter(renReqFuzzManager, renFrameFuzzAdapter);
    renFrameFuzzRender = nullptr;
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioRenderframeRequestbytesFuzzTest(data, size);
    return 0;
}