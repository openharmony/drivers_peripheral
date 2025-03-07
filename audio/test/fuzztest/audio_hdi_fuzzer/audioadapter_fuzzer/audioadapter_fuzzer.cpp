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
#include "audioadapter_fuzzer.h"
#include "hdi_service_common.h"

namespace OHOS {
namespace Audio {

constexpr size_t THRESHOLD = 200;
constexpr int32_t OFFSET = 4;
uint32_t g_captureId = 0;
uint32_t g_renderId = 0;
struct AudioDeviceDescriptor g_devDesc;
enum AdapterCmdId {
    AUDIO_ADAPTER_CREAT_RENDER,
    AUDIO_ADAPTER_DESTORY_RENDER,
    AUDIO_ADAPTER_CREAT_CAPTURE,
    AUDIO_ADAPTER_DESTORY_CAPTURE,
    AUDIO_ADAPTER_GET_PORT_CAPABILITY,
    AUDIO_ADAPTER_SET_PASSTHROUGH_MODE,
    AUDIO_ADAPTER_GET_PASSTHROUGH_MODE,
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

static int32_t InitDevDesc(const struct AudioDeviceDescriptor *devDesc)
{
    if (devDesc == nullptr) {
        return HDF_FAILURE;
    }

    g_devDesc.portId = devDesc->portId;
    g_devDesc.pins = devDesc->pins;
    g_devDesc.desc = NULL;
    return HDF_SUCCESS;
}

static void AdapterFucSwitch(struct IAudioAdapter *&adapter, uint32_t cmd, const uint8_t *&rawData)
{
    uint8_t *data = const_cast<uint8_t *>(rawData);
    switch (cmd) {
        case AUDIO_ADAPTER_CREAT_RENDER: {
            struct IAudioRender *render = nullptr;
            InitDevDesc((const struct AudioDeviceDescriptor *)(rawData));
            adapter->CreateRender(adapter, &g_devDesc,
                reinterpret_cast<const struct AudioSampleAttributes *>(rawData), &render, &g_renderId);
            break;
        }
        case AUDIO_ADAPTER_DESTORY_RENDER: {
            adapter->DestroyRender(adapter, g_renderId);
        }
            break;
        case AUDIO_ADAPTER_CREAT_CAPTURE: {
            struct IAudioCapture *capture = nullptr;
            InitDevDesc((const struct AudioDeviceDescriptor *)(rawData));
            adapter->CreateCapture(adapter, &g_devDesc,
                reinterpret_cast<const struct AudioSampleAttributes *>(rawData), &capture, &g_captureId);
            break;
        }
        case AUDIO_ADAPTER_DESTORY_CAPTURE: {
            adapter->DestroyCapture(adapter, g_captureId);
        }
            break;
        case AUDIO_ADAPTER_GET_PORT_CAPABILITY: {
            struct AudioPortCapability capability = {};
            struct AudioPort port = {
                .dir = *(reinterpret_cast<AudioPortDirection *>(data)),
                .portId = *(reinterpret_cast<uint32_t *>(data)),
                .portName = reinterpret_cast<char *>(data),
            };
            adapter->GetPortCapability(adapter, &port, &capability);
            break;
        }
        case AUDIO_ADAPTER_SET_PASSTHROUGH_MODE: {
            struct AudioPort port = {
                .dir = *(reinterpret_cast<AudioPortDirection *>(data)),
                .portId = *(reinterpret_cast<uint32_t *>(data)),
                .portName = reinterpret_cast<char *>(data),
            };
            adapter->SetPassthroughMode(adapter, &port, *(reinterpret_cast<const AudioPortPassthroughMode *>(rawData)));
            break;
        }
        case AUDIO_ADAPTER_GET_PASSTHROUGH_MODE: {
            AudioPortPassthroughMode mode = PORT_PASSTHROUGH_LPCM;
            struct AudioPort port = {
                .dir = *(reinterpret_cast<AudioPortDirection *>(data)),
                .portId = *(reinterpret_cast<uint32_t *>(data)),
                .portName = reinterpret_cast<char *>(data),
            };
            adapter->GetPassthroughMode(adapter, &port, &mode);
            break;
        }
        default:
            return;
    }
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
    struct AudioPort audioPort = {};
    struct IAudioAdapter *adapter = nullptr;
    int32_t ret = GetLoadAdapter(manager, PORT_OUT, ADAPTER_NAME, &adapter, audioPort);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    AdapterFucSwitch(adapter, cmd, rawData);
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