/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "captureframe_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "audio_capture_interface_impl.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace HDI {
namespace DistributedAudio {
namespace Audio {
namespace V1_0 {
void CaptureFrameFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < (sizeof(uint64_t)))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string adpName = fdp.ConsumeRandomLengthString();
    AudioDeviceDescriptor desc;
    AudioSampleAttributes attrs;
    sptr<IDAudioCallback> callback = nullptr;
    auto audioCapture = std::make_shared<AudioCaptureInterfaceImpl>(adpName, desc, attrs, callback);
    std::vector<int8_t> frame;
    uint64_t requestBytes = fdp.ConsumeIntegral<uint64_t>();

    audioCapture->CaptureFrame(frame, requestBytes);
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
    OHOS::HDI::DistributedAudio::Audio::V1_0::CaptureFrameFuzzTest(data, size);
    return 0;
}

