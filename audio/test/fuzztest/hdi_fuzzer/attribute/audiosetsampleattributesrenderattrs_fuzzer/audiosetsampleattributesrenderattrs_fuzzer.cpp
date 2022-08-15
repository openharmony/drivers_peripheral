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

#include "audiosetsampleattributesrenderattrs_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
    bool AudioSetSampleAttributesRenderAttrsFuzzTest(const uint8_t *data, size_t size)
    {
        bool result = false;
        TestAudioManager *setSampleRenManager = nullptr;
        struct AudioAdapter *setSampleRenAdapter = nullptr;
        struct AudioRender *render = nullptr;
        int32_t ret = AudioGetManagerCreateRender(setSampleRenManager, &setSampleRenAdapter, &render);
        if (ret < 0 || setSampleRenAdapter == nullptr || render == nullptr || setSampleRenManager == nullptr) {
            HDF_LOGE("%{public}s: AudioGetManagerCreateRender failed \n", __func__);
            return false;
        }
        struct AudioSampleAttributes attrsFuzz = {};
        int32_t copySize = sizeof(attrsFuzz) > size ? size : sizeof(attrsFuzz);
        if (memcpy_s((void *)&attrsFuzz, sizeof(attrsFuzz), data, copySize) != 0) {
            return false;
        }
        ret = render->attr.SetSampleAttributes(render, &attrsFuzz);
        if (ret == HDF_SUCCESS) {
            result = true;
        }
        setSampleRenAdapter->DestroyRender(setSampleRenAdapter, render);
        setSampleRenManager->UnloadAdapter(setSampleRenManager, setSampleRenAdapter);
        return result;
    }
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioSetSampleAttributesRenderAttrsFuzzTest(data, size);
    return 0;
}