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

/**
 * @addtogroup Audio Effect
 * @{
 *
 * @brief Defines audio-related APIs, including custom data types and functions for loading drivers,
 * accessing a audio effect factory, a effect controller.
 *
 * @since 4.0
 * @version 1.0
 */

/**
 * @file effect_host_common.h
 *
 * @brief Defines custom data types used in API declarations for the effect module.
 *
 * @version 1.0
 */

#ifndef EFFECT_HOST_COMMON_H
#define EFFECT_HOST_COMMON_H

#include "v1_0/effect_types.h"
#include "v1_0/ieffect_model.h"
#include "v1_0/ieffect_control.h"
#include "v1_0/ieffect_control_vdi.h"
#include "hdf_dlist.h"

#define HDF_EFFECT_LIB_NAME_LEN 64
#define HDF_LOG_TAG HDF_AUDIO_EFFECT
#define AEM_INIT_LIST_HEAD(name) { &(name), &(name) }
#define AEM_GET_INITED_DLIST(name) \
    struct DListHead name = AEM_INIT_LIST_HEAD(name)

struct EffectModelService {
    struct IEffectModel interface;
};

struct ControllerManager {
    struct IEffectControl ctrlImpls;
    struct IEffectControlVdi *ctrlOps;
    char *libName;
};

/* declare functions */
int32_t EffectControlEffectProcess(struct IEffectControl *self, const struct AudioEffectBuffer *input,
                                   struct AudioEffectBuffer *output);
int32_t EffectControlSendCommand(struct IEffectControl *self, enum EffectCommandTableIndex cmdId, const int8_t *cmdData,
    uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen);
int32_t EffectGetOwnDescriptor(struct IEffectControl *self, struct EffectControllerDescriptor *desc);
int32_t EffectControlEffectReverse(struct IEffectControl *self, const struct AudioEffectBuffer *input,
                                   struct AudioEffectBuffer *output);

#endif
