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

#include "effect_core.h"
#include "hdf_base.h"
#include "hdf_log.h"

#define HDF_LOG_TAG HDF_AUDIO_EFFECT

int32_t EffectControlEffectProcess(struct IEffectControl *self, const struct AudioEffectBuffer *input,
     struct AudioEffectBuffer *output)
{
    if (self == NULL || input == NULL || output == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct ControllerManager *manager = (struct ControllerManager *)self;
    if (manager->ctrlOps == NULL || manager->ctrlOps->EffectProcess == NULL) {
        HDF_LOGE("%{public}s: controller has no options", __func__);
        return HDF_FAILURE;
    }

    return manager->ctrlOps->EffectProcess(manager->ctrlOps, input, output);
}

int32_t EffectControlSendCommand(struct IEffectControl *self, uint32_t cmdId, const int8_t *cmdData,
     uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (self == NULL || cmdData == NULL || replyData == NULL || replyDataLen == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct ControllerManager *manager = (struct ControllerManager *)self;
    if (manager->ctrlOps == NULL || manager->ctrlOps->SendCommand == NULL) {
        HDF_LOGE("%{public}s: controller has no options", __func__);
        return HDF_FAILURE;
    }

    return manager->ctrlOps->SendCommand(manager->ctrlOps, cmdId, (void *)cmdData, cmdDataLen,
                                         (void *)replyData, replyDataLen);
}

int32_t EffectGetOwnDescriptor(struct IEffectControl *self, struct EffectControllerDescriptor *desc)
{
    if (self == NULL || desc == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct ControllerManager *manager = (struct ControllerManager *)self;
    if (manager->ctrlOps == NULL || manager->ctrlOps->GetEffectDescriptor == NULL) {
        HDF_LOGE("%{public}s: controller has no options", __func__);
        return HDF_FAILURE;
    }

    return manager->ctrlOps->GetEffectDescriptor(manager->ctrlOps, desc);
}
