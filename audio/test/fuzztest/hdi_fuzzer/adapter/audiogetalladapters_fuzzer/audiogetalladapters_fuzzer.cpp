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
#include "audiogetalladapters_fuzzer.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioGetalladaptersFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *getAllFuzzManager = nullptr;
    int32_t ret = GetManager(getAllFuzzManager);
    if (ret < 0 || getAllFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: GetManager failed \n", __func__);
        return false;
    }
    struct AudioAdapterDescriptor *descs = nullptr;
    int sizeone = 0;

    TestAudioManager *managerFuzz = reinterpret_cast<TestAudioManager *>(const_cast<uint8_t *>(data));
    ret = getAllFuzzManager->GetAllAdapters(managerFuzz, &descs, &sizeone);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioGetalladaptersFuzzTest(data, size);
    return 0;
}