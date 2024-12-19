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

#include "effect_host_common.h"

#include "hdf_base.h"
#include "v1_0/effect_types.h"
#include "v1_0/effect_types_vdi.h"
#include "v1_0/ieffect_control_vdi.h"
#include "audio_uhdf_log.h"
#include "osal_mem.h"
#include "audio_dfx_util.h"

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
    if (strcmp(manager->libName, "libmock_effect_lib") != 0) {
        output->frameCount = input->frameCount;
        output->datatag = input->datatag;
        output->rawDataLen = input->rawDataLen;
        output->rawData = (int8_t *)OsalMemCalloc(sizeof(int8_t) * output->rawDataLen);
        if (output->rawData == NULL) {
            HDF_LOGE("%{public}s: OsalMemCalloc fail", __func__);
            return HDF_FAILURE;
        }
    }
    struct AudioEffectBufferVdi *inputVdi = (struct AudioEffectBufferVdi *)input;
    struct AudioEffectBufferVdi *outputVdi = (struct AudioEffectBufferVdi *)output;
    HdfAudioStartTrace(__func__, 0);
    int32_t ret = manager->ctrlOps->EffectProcess(manager->ctrlOps, inputVdi, outputVdi);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("AudioEffectProcess failed, ret=%{public}d", ret);
        return ret;
    }

    output = (struct AudioEffectBuffer *)outputVdi; 
    return ret;
}

int32_t EffectControlSendCommand(struct IEffectControl *self, enum EffectCommandTableIndex cmdId, const int8_t *cmdData,
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
    enum EffectCommandTableIndexVdi cmdIdVdi = (enum EffectCommandTableIndexVdi)cmdId;
    HdfAudioStartTrace(__func__, 0);
    int32_t ret = manager->ctrlOps->SendCommand(manager->ctrlOps, cmdIdVdi, (void *)cmdData, cmdDataLen,
                                         (void *)replyData, replyDataLen);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("SendCommand failed, ret=%{public}d", ret);
        return ret;
    }
    return ret;
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
    struct EffectControllerDescriptorVdi *descVdi = (struct EffectControllerDescriptorVdi *)desc;
    HdfAudioStartTrace(__func__, 0);
    int32_t ret = manager->ctrlOps->GetEffectDescriptor(manager->ctrlOps, descVdi);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("EffectGetOwnDescriptor failed, ret=%{public}d", ret);
        return ret;
    }

    desc = (struct EffectControllerDescriptor *)descVdi;
    return ret;
}

int32_t EffectControlEffectReverse(struct IEffectControl *self, const struct AudioEffectBuffer *input,
    struct AudioEffectBuffer *output)
{
    if (self == NULL || input == NULL || output == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct ControllerManager *manager = (struct ControllerManager *)self;
    if (manager->ctrlOps == NULL || manager->ctrlOps->EffectReverse == NULL) {
        HDF_LOGE("%{public}s: controller has no options", __func__);
        return HDF_FAILURE;
    }
    struct AudioEffectBufferVdi *inputVdi = (struct AudioEffectBufferVdi *)input;
    struct AudioEffectBufferVdi *outputVdi = (struct AudioEffectBufferVdi *)output;
    HdfAudioStartTrace(__func__, 0);
    int32_t ret = manager->ctrlOps->EffectReverse(manager->ctrlOps, inputVdi, outputVdi);
    HdfAudioFinishTrace();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("EffectReverse failed, ret=%{public}d", ret);
        return ret;
    }
    output = (struct AudioEffectBuffer *)outputVdi;     
    return ret;
}
