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
#include "audiomanager_fuzzer.h"
#include "v4_0/iaudio_manager.h"
#include "v4_0/audio_types.h"
#include "hdi_service_common.h"

using namespace std;
namespace OHOS {
namespace Audio {
constexpr size_t THRESHOLD = 200;
constexpr int32_t OFFSET = 4;
enum ManagerCmdId {
    AUDIO_MANAGER_LOAD_ADAPTER,
    AUDIO_MANAGER_UNLOAD_ADAPTER,
};
static uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[BUFFER_INDEX_ZERO] << PCM_24_BIT) | (ptr[BUFFER_INDEX_ONE] << PCM_16_BIT) |
        (ptr[BUFFER_INDEX_TWO] << PCM_8_BIT) | (ptr[BUFFER_INDEX_THREE]);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    uint32_t cmd = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    struct IAudioManager *manager = IAudioManagerGet(false);
    if (manager == nullptr) {
        return false;
    }
    uint8_t *data = const_cast<uint8_t *>(rawData);
    switch (cmd) {
        case AUDIO_MANAGER_LOAD_ADAPTER: {
            struct AudioPort port = {
                .dir = *(reinterpret_cast<AudioPortDirection *>(data)),
                .portId = *(reinterpret_cast<uint32_t *>(data)),
                .portName = reinterpret_cast<char *>(data),
            };
            struct AudioAdapterDescriptor desc = {
                .adapterName = reinterpret_cast<char *>(data),
                .ports = &port,
            };
            struct IAudioAdapter *adapter = nullptr;
            manager->LoadAdapter(manager, &desc, &adapter);
            break;
        }
        case AUDIO_MANAGER_UNLOAD_ADAPTER:
            manager->UnloadAdapter(manager, reinterpret_cast<char *>(data));
            break;
        default:
            break;
    }
    IAudioManagerRelease(manager, false);
    return true;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::Audio::THRESHOLD) {
        return 0;
    }
    OHOS::Audio::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}