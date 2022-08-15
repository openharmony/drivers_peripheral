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
#include "audio_hdi_fuzzer_common.h"
#include "securec.h"
#include "audiocreaterenderdesc_fuzzer.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioCreaterenderDescFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *descFuzzManager = nullptr;
    int32_t ret = GetManager(descFuzzManager);
    if (ret < 0 || descFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: GetManager failed \n", __func__);
        return false;
    }
    struct AudioAdapter *descFuzzAdapter = nullptr;
    struct AudioPort *renderPort = nullptr;
    ret = GetLoadAdapter(descFuzzManager, &descFuzzAdapter, renderPort);
    if (ret < 0 || descFuzzAdapter == nullptr) {
        HDF_LOGE("%{public}s: GetLoadAdapter failed \n", __func__);
        return false;
    }
    struct AudioSampleAttributes attrs = {};
    InitAttrs(attrs);

    struct AudioRender *descFuzzRender = nullptr;
    struct AudioDeviceDescriptor devDescFuzz = {};
    int32_t copySize = sizeof(devDescFuzz) > size ? size : sizeof(devDescFuzz);
    if (memcpy_s((void *)&devDescFuzz, sizeof(devDescFuzz), data, copySize) != 0) {
        return false;
    }
    ret = descFuzzAdapter->CreateRender(descFuzzAdapter, &devDescFuzz, &attrs, &descFuzzRender);
    if (ret == HDF_SUCCESS) {
        descFuzzAdapter->DestroyRender(descFuzzAdapter, descFuzzRender);
        result = true;
    }
    descFuzzManager->UnloadAdapter(descFuzzManager, descFuzzAdapter);
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioCreaterenderDescFuzzTest(data, size);
    return 0;
}