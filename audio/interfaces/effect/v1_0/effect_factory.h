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

#ifndef OHOS_VDI_AUDIO_EFFECT_V1_0_IEFFECTFACTORY_H
#define OHOS_VDI_AUDIO_EFFECT_V1_0_IEFFECTFACTORY_H

#include <stdint.h>
#include "effect_types_vdi.h"
#include "ieffect_control_vdi.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IEFFECT_VDI_MODEL_MAJOR_VERSION 1
#define IEFFECT_VDI_MODEL_MINOR_VERSION 0

typedef int32_t (*ComandProccess)(const int8_t *commandData, uint32_t commandSize,
    int8_t *replyData, uint32_t *replySize);
struct EffectCommandTable {
    enum EffectCommandTableIndexVdi cmd;
    ComandProccess func;
};

/**
 * @brief Defines Audio effect model data process interfaces.
 *
 * @since 4.0
 * @version 1.0
 */
struct EffectFactory {
    int32_t version;     /**< version tag to match the corresponding version of the APIs and the library */
    char *effectLibName; /**< To identify the effect library name for knowing which effect library it is */
    char *supplier;      /**< To identify who supply the effect library, it can be assigned as the EOM/ISV name */
    /**
     *
     * @brief
     * the input and output buffer have to be specificed, if they are not specified，the process have to use the
     * data process function which is provided by the command
     *
     * @param self Indicates the pointer to the effect interfaces to operate.
     * @param EffectInfo Indicates the information of the effect control.
     * @param handle Indicates the double pointer to the <b>EffectControl</b> object.
     *
     * @return Returns <b>0</b> if the operation is successful; returns a negative value otherwise.
     *
     * @since 4.0
     * @version 1.0
     */
    int32_t (*CreateController)(struct EffectFactory *self, const struct EffectInfoVdi *info,
                                struct IEffectControlVdi **handle);
    /**
     *
     * @brief Destroy the effect controller specified by the controllerId
     *
     * @param self Indicates the pointer to the effect interfaces to operate.
     * @param handle Indicates the pointer to the <b>EffectControl</b> object.
     *
     * @return Returns <b>0</b> if the operation is successful; returns a negative value otherwise.
     *
     * @since 4.0
     * @version 1.0
     */
    int32_t (*DestroyController)(struct EffectFactory *self, struct IEffectControlVdi *handle);

    /**
     * @brief Get the effect descriptor by effectId.
     *
     * @param self Indicates the pointer to the effect interfaces to operate.
     * @param effectId Indicates the effectId of the effect.
     * @param desc Indicates the descriptor of the effect controller.
     *
     * @return Returns <b>0</b> if the command send success; returns a non-zero value otherwise.
     *
     * @since 4.0
     * @version 1.0
     */
    int32_t (*GetDescriptor)(struct EffectFactory *self, const char *effectId,
        struct EffectControllerDescriptorVdi *desc);
};

/* this name is going to get effect lib, it has to be realized */
struct EffectFactory *GetEffectoyFactoryLib(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* OHOS_VDI_AUDIO_EFFECT_V1_0_IEFFECTFACTORY_H */