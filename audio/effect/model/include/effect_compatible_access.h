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

#include "v1_0/effect_types.h"

typedef int32_t (*ComandProccess)(int8_t *commandData, uint32_t commandSize, int8_t *replyData, uint32_t *replySize);
struct EffectCommandTable {
    enum EffectCommandTableIndex cmd;
    ComandProccess func;
};

struct EffectControl {
    /**
     * @brief Process the audio raw data. 
     * the input and output buffer have to be specificed, if they are not specified，the process have to use the
     * data process function which is provided by the command 
     *
     * @param self Indicates the pointer to the effect interfaces to operate.
     * @param input Indicates the pointer to the buffer for original data.
     * @param output Indicates the pointer to the buffer for output data.
     *
     * @return Returns <b>0</b> if the process success; returns a non-zero value otherwise.
     *
     * @since 4.0
     * @version 1.0
     */
    int32_t (*EffectProcess)(struct EffectControl *self, const struct AudioEffectBuffer *input,
                             struct AudioEffectBuffer *output);
    /**
     * @brief Effect process command which is used 
     * the input and output buffer have to be specificed, if they are not specified，the process have to use the
     * data process function which is provided by the command 
     *
     * @param self Indicates the pointer to the effect interfaces to operate.
     * @param cmdId Command index used to match command options in the command table.
     * @param CommandData Data comes from the system service.
     *
     * @return Returns <b>0</b> if the command send success; returns a non-zero value otherwise.
     *
     * @since 4.0
     * @version 1.0
     */
    int32_t (*SendCommand)(struct EffectControl *self, uint32_t cmdId, int8_t *CommandData,
                           uint32_t commandSize, int8_t *replyData, uint32_t *replySize);

    /**
     * @brief Get the effect descriptor
     *
     * @param self Indicates the pointer to the effect interfaces to operate.
     * @param desc Indicates the descriptor of the effect controller
     *
     * @return Returns <b>0</b> if the command send success; returns a non-zero value otherwise.
     *
     * @since 4.0
     * @version 1.0
     */
    int32_t (*GetEffectDescriptor)(struct EffectControl *self, struct EffectControllerDescriptor *desc);
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
    int32_t (*CreateController)(struct EffectFactory *self, const struct EffectInfo *info, 
                                      struct EffectControl **handle);
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
    int32_t (*DestroyController)(struct EffectFactory *self, struct EffectControl *handle);
};

/* this name is going to get effect lib, it has to be realized */
struct EffectFactory *GetEffectoyFactoryLib();