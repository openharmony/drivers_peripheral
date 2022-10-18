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

#include "audioloadadapterdesc_fuzzer.h"
#include "securec.h"
#include "audio_hdi_fuzzer_common.h"

using namespace OHOS::Audio;
namespace OHOS {
namespace Audio {
bool AudioLoadadapterDescFuzzTest(const uint8_t *data, size_t size)
{
    bool result = false;
    TestAudioManager *loadAdapterFuzzManager = nullptr;
    int32_t ret = GetManager(loadAdapterFuzzManager);
    if (ret < 0 || loadAdapterFuzzManager == nullptr) {
        HDF_LOGE("%{public}s: GetManager failed \n", __func__);
        return false;
    }
    uint8_t *dataFuzz = const_cast<uint8_t *>(data);
    struct AudioPort portFuzz = {
        .dir = *(reinterpret_cast<AudioPortDirection *>(dataFuzz)),
        .portId = *(reinterpret_cast<uint32_t *>(dataFuzz)),
        .portName = reinterpret_cast<char *>(dataFuzz),
    };
    struct AudioAdapterDescriptor descFuzz = {
        .adapterName = reinterpret_cast<char *>(dataFuzz),
        .ports = &portFuzz,
    };
    struct AudioAdapter *adapter = nullptr;
    ret = loadAdapterFuzzManager->LoadAdapter(loadAdapterFuzzManager, &descFuzz, &adapter);
    if (ret == HDF_SUCCESS) {
        result = true;
    }
    return result;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Audio::AudioLoadadapterDescFuzzTest(data, size);
    return 0;
}