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

#ifndef OHOS_VDI_AUDIO_EFFECT_V1_0_IEFFECTMODEL_H
#define OHOS_VDI_AUDIO_EFFECT_V1_0_IEFFECTMODEL_H

#include <stdint.h>
#include "v1_0/effect_types_vdi.h"
#include "v1_0/ieffect_control_vdi.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IEFFECT_VDI_MODEL_MAJOR_VERSION 1
#define IEFFECT_VDI_MODEL_MINOR_VERSION 0

struct IEffectModelVdi {
    int32_t (*IsSupplyEffectLibs)(struct IEffectModelVdi *self, bool *supply);
    int32_t (*GetAllEffectDescriptors)(struct IEffectModelVdi *self, struct EffectControllerDescriptorVdi *descs,
        uint32_t *descsLen);
    int32_t (*CreateEffectController)(struct IEffectModelVdi *self, const struct EffectInfoVdi *info,
        struct IEffectControlVdi **contoller, struct ControllerIdVdi *id);
    int32_t (*DestroyEffectController)(struct IEffectModelVdi *self, const struct ControllerIdVdi *id);
    int32_t (*GetEffectDescriptor)(struct IEffectModelVdi *self, const char *effectId,
        struct EffectControllerDescriptorVdi *desc);
    int32_t (*GetVersion)(struct IEffectModelVdi *self, uint32_t *majorVer, uint32_t *minorVer);
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_VDI_AUDIO_EFFECT_V1_0_IEFFECTMODEL_H */