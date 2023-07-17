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

#include "effectcontrol_fuzzer.h"

#include <cstdlib>
#include "v1_0/effect_types.h"
#include "v1_0/ieffect_control.h"
#include "v1_0/ieffect_model.h"

using namespace std;

namespace OHOS {
namespace Audio {
constexpr int32_t OFFSET = 4;
constexpr size_t THRESHOLD = 10;
constexpr uint32_t GET_BUFFER_LEN = 10;

enum EffectControlCmdId {
    EFFECT_CONTROL_EFFECT_PROCESS,
    EFFECT_CONTROL_SEND_COMMAND,
    EFFECT_CONTROL_GET_DESCRIPTOR,
    EFFECT_CONTROL_EFFECT_REVERSE,
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
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}

void EffectControlFucSwitch(struct IEffectControl *&controller, uint32_t cmd, const uint8_t *&rawData, size_t size)
{
    uint8_t *data = const_cast<uint8_t *>(rawData);
    switch (cmd) {
        case EFFECT_CONTROL_EFFECT_PROCESS: {
            struct AudioEffectBuffer output = {0};
            controller->EffectProcess(controller, reinterpret_cast<AudioEffectBuffer *>(data), &output);
            break;
        }
        case EFFECT_CONTROL_SEND_COMMAND: {
            int8_t output[GET_BUFFER_LEN] = {0};
            uint32_t replyLen = GET_BUFFER_LEN;
            controller->SendCommand(controller, (*data) % AUDIO_EFFECT_COMMAND_GET_PARAM,
                                        reinterpret_cast<int8_t *>(data), size, output, &replyLen);
            break;
        }
        case EFFECT_CONTROL_GET_DESCRIPTOR: {
            struct EffectControllerDescriptor desc;
            controller->GetEffectDescriptor(controller, &desc);
            break;
        }
        case EFFECT_CONTROL_EFFECT_REVERSE: {
            struct AudioEffectBuffer output = {0};
            controller->EffectReverse(controller, reinterpret_cast<struct AudioEffectBuffer *>(data), &output);
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
    uint32_t cmd = Convert2Uint32(rawData) % EFFECT_CONTROL_EFFECT_REVERSE;
    rawData = rawData + OFFSET;

    struct IEffectModel *model = IEffectModelGet(true);
    if (model == nullptr) {
        return false;
    }

    char *libName = strdup("libmock_effect_lib");
    char *effectId = strdup("aaaabbbb-8888-9999-6666-aabbccdd9966ff");
    struct EffectInfo info = {
        .libName = libName,
        .effectId = effectId,
        .ioDirection = 1,
    };
    struct IEffectControl *controller = nullptr;
    struct ControllerId contollerId;

    int32_t ret = model->CreateEffectController(model, &info, &controller, &contollerId);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    if (controller == nullptr) {
        return false;
    }

    EffectControlFucSwitch(controller, cmd, rawData, size);

    if (libName != nullptr) {
        free(libName);
        libName = nullptr;
    }
    if (effectId != nullptr) {
        free(effectId);
        effectId = nullptr;
    }

    ret = model->DestroyEffectController(model, &contollerId);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    IEffectModelRelease(model, true);
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