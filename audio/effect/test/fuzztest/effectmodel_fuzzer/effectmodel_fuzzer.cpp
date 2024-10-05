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

#include "effectmodel_fuzzer.h"

#include <cstdlib>
#include "v1_0/effect_types.h"
#include "v1_0/ieffect_control.h"
#include "v1_0/ieffect_model.h"

using namespace std;

namespace OHOS {
namespace Audio {
constexpr int32_t OFFSET = 4;
constexpr size_t THRESHOLD = 10;
constexpr uint32_t MAX_DESCRIPTOR_NUM = 20;

enum EffectModelCmdId {
    EFFECT_MODEL_IS_SUPPLY_LIBS,
    EFFECT_MODEL_GET_ALL_DESCRIPTORS,
    EFFECT_MODEL_CREATE_EFFECT_CONTROLLER,
    EFFECT_MODEL_DESTROY_EFFECT_CONTROLLER,
    EFFECT_MODEL_GET_EFFECT_DESCRIPTOR,
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

void EffectModelFucSwitch(struct IEffectModel *&model, uint32_t cmd, const uint8_t *&rawData, size_t size)
{
    uint8_t *data = const_cast<uint8_t *>(rawData);
    switch (cmd) {
        case EFFECT_MODEL_IS_SUPPLY_LIBS: {
            bool isSupport = false;
            model->IsSupplyEffectLibs(model, &isSupport);
            break;
        }
        case EFFECT_MODEL_GET_ALL_DESCRIPTORS: {
            uint32_t descsLen = MAX_DESCRIPTOR_NUM;
            struct EffectControllerDescriptor descs[MAX_DESCRIPTOR_NUM];
            model->GetAllEffectDescriptors(model, descs, &descsLen);
            break;
        }
        case EFFECT_MODEL_CREATE_EFFECT_CONTROLLER: {
            struct IEffectControl *contoller = nullptr;
            struct ControllerId contollerId;
            struct EffectInfo info = {
                .libName = reinterpret_cast<char *>(data),
                .effectId = reinterpret_cast<char *>(data),
                .ioDirection = 1,
    };
            model->CreateEffectController(model, &info, &contoller, &contollerId);
            break;
        }
        case EFFECT_MODEL_DESTROY_EFFECT_CONTROLLER: {
            struct ControllerId contollerId{
                .libName = reinterpret_cast<char *>(data),
                .effectId = reinterpret_cast<char *>(data),
            };
            model->DestroyEffectController(model, &contollerId);
            break;
        }
        case EFFECT_MODEL_GET_EFFECT_DESCRIPTOR: {
            struct EffectControllerDescriptor desc;
            model->GetEffectDescriptor(model, reinterpret_cast<const char *>(data), &desc);
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
    uint32_t cmd = Convert2Uint32(rawData) % EFFECT_MODEL_GET_EFFECT_DESCRIPTOR;
    rawData = rawData + OFFSET;

    struct IEffectModel *model = IEffectModelGet(true);
    if (model == nullptr) {
        return false;
    }

    EffectModelFucSwitch(model, cmd, rawData, size);

    if (model != nullptr) {
        IEffectModelRelease(model, true);
    }
    return true;
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::Audio::THRESHOLD) {
        return 0;
    }

    if (data == nullptr) {
        return 0;
    }

    for (int i = 0; i < size - 1; i++) {
        if (data[i] == '\0') {
            return 0;
        }
    }

    if (data[size -1] != '\0') {
        return 0;
    }
    OHOS::Audio::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}