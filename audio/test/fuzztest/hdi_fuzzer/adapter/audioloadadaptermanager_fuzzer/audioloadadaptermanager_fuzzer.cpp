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

#include "audioloadadaptermanager_fuzzer.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioLoadadapterManagerFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *loadAdapterFuzzManager = nullptr;
    int32_t ret = GetManager(loadAdapterFuzzManager);
    if (ret < 0 || loadAdapterFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: GetManager failed \n", __func__);
        return false;
    }
    struct AudioAdapterDescriptor *descs = nullptr;
    int sizeone = 0;
    ret = loadAdapterFuzzManager->GetAllAdapters(loadAdapterFuzzManager, &descs, &sizeone);
    if (ret < 0) {
        HDF_LOGE("%{public}s: GetAllAdapters failed \n", __func__);
        return false;
    }
    struct AudioAdapterDescriptor *desc = &descs[0];
    struct AudioAdapter *adapter = nullptr;
    TestAudioManager *managerFuzz = reinterpret_cast<TestAudioManager *>(const_cast<uint8_t *>(data));
    ret = loadAdapterFuzzManager->LoadAdapter(managerFuzz, desc, &adapter);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioLoadadapterManagerFuzzTest(data, size);
    return 0;
}