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

#include "createcapture_fuzzer.h"

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
const uint32_t VAR_NUM = 16;
void CreateCaptureFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(int32_t)) * VAR_NUM)) {
        return;
    }

    AudioAdapterDescriptor desc;
    auto audioAdapter = std::make_shared<AudioAdapterInterfaceImpl>(desc);
    uint32_t offset = sizeof(uint32_t);
    uint32_t i = 0;

    AudioDeviceDescriptor deviceDes = {
        .portId = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .pins = *(reinterpret_cast<const AudioPortPin*>(data + (i++ * offset))),
        .desc = std::string(reinterpret_cast<const char*>(data + (i++ * offset)), size),
    };

    AudioSampleAttributes sampleAttr = {
        .type = *(reinterpret_cast<const AudioCategory*>(data + (i++ * offset))),
        .interleaved = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .format = *(reinterpret_cast<const AudioFormat*>(data + (i++ * offset))),
        .sampleRate = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .channelCount = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .period = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .frameSize = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .isBigEndian = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .isSignedData = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .startThreshold = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .stopThreshold = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .silenceThreshold = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
        .streamId = *(reinterpret_cast<const uint32_t*>(data + (i++ * offset))),
    };

    sptr<IAudioCapture> capture;
    uint32_t capId;
    audioAdapter->CreateCapture(deviceDes, sampleAttr, capture, capId);
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
    OHOS::HDI::DistributedAudio::Audio::V1_0::CreateCaptureFuzzTest(data, size);
    return 0;
}

