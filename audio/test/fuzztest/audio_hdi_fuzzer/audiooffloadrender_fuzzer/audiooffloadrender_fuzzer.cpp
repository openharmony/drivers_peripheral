/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "audiooffloadrender_fuzzer.h"
#include "hdi_service_common.h"
using namespace std;
namespace OHOS {
namespace Audio {
constexpr size_t THRESHOLD = 200;
constexpr int32_t OFFSET = 4;

enum OffloadRenderCmdId {
    AUDIO_OFFLOAD_RENDER_SET_BUFFER_SIZE,
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

void RenderFucSwitch(struct IAudioRender *&render, uint32_t cmd, const uint8_t *&rawData, size_t size)
{
    uint8_t *data = const_cast<uint8_t *>(rawData);
    switch (cmd) {
        case AUDIO_OFFLOAD_RENDER_SET_BUFFER_SIZE:
            render->SetBufferSize(render, *(reinterpret_cast<uint32_t *>(data)));
            break;
        default:
            return;
    }
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    struct IAudioAdapter *adapter = nullptr;
    struct IAudioRender *render = nullptr;
    uint32_t cmd = Convert2Uint32(rawData);
    uint32_t renderId = 0;

    rawData = rawData + OFFSET;
    size = size - OFFSET;
    struct IAudioManager *manager = IAudioManagerGet(false);
    if (manager == nullptr) {
        return false;
    }
    int32_t ret = AudioOffloadCreateRender(manager, PIN_OUT_SPEAKER, ADAPTER_NAME, &adapter, &render, &renderId);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    RenderFucSwitch(render, cmd, rawData, size);
    adapter->DestroyRender(adapter, renderId);
    manager->UnloadAdapter(manager, ADAPTER_NAME.c_str());
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