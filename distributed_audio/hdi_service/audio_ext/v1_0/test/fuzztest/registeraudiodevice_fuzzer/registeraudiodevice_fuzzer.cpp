/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "registeraudiodevice_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "daudio_manager_interface_impl.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audioext {
namespace V2_1 {
void RegisterAudioDeviceFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }

    std::string adpName(reinterpret_cast<const char*>(data), size);
    int32_t devId = *(reinterpret_cast<const int32_t*>(data));
    std::string capability(reinterpret_cast<const char*>(data), size);
    sptr<IDAudioCallback> callbackObj = nullptr;

    DAudioManagerInterfaceImpl::GetDAudioManager()->RegisterAudioDevice(adpName, devId, capability, callbackObj);
}
} // V2_1
} // AudioExt
} // Distributedaudio
} // HDI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::DistributedAudio::Audioext::V2_1::RegisterAudioDeviceFuzzTest(data, size);
    return 0;
}

