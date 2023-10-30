/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "createrender_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "audio_adapter_interface_impl.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
void CreateRenderFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)))) {
        return;
    }

    AudioAdapterDescriptor desc;
    auto audioAdapter = std::make_shared<AudioAdapterInterfaceImpl>(desc);

    AudioDeviceDescriptor deviceDes = {
        .portId = *(reinterpret_cast<const uint32_t*>(data)),
        .pins = *(reinterpret_cast<const AudioPortPin*>(data)),
        .desc = std::string(reinterpret_cast<const char*>(data), size),
    };

    AudioSampleAttributes sampleAttr = {
        .type = *(reinterpret_cast<const AudioCategory*>(data)),
        .interleaved = *(reinterpret_cast<const uint32_t*>(data)),
        .format = *(reinterpret_cast<const AudioFormat*>(data)),
        .sampleRate = *(reinterpret_cast<const uint32_t*>(data)),
        .channelCount = *(reinterpret_cast<const uint32_t*>(data)),
        .period = *(reinterpret_cast<const uint32_t*>(data)),
        .frameSize = *(reinterpret_cast<const uint32_t*>(data)),
        .isBigEndian = *(reinterpret_cast<const uint32_t*>(data)),
        .isSignedData = *(reinterpret_cast<const uint32_t*>(data)),
        .startThreshold = *(reinterpret_cast<const uint32_t*>(data)),
        .stopThreshold = *(reinterpret_cast<const uint32_t*>(data)),
        .silenceThreshold = *(reinterpret_cast<const uint32_t*>(data)),
        .streamId = *(reinterpret_cast<const uint32_t*>(data)),
    };

    sptr<IAudioRender> render;
    uint32_t renderId;
    audioAdapter->CreateRender(deviceDes, sampleAttr, render, renderId);
}
} // V1_0
} // Audio
} // Distributedaudio
} // HDI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HDI::DistributedAudio::Audio::V1_0::CreateRenderFuzzTest(data, size);
    return 0;
}

