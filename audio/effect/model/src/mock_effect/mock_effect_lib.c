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

#include "effect_compatible_access.h"
#include "hdf_log.h"
#include "osal_mem.h"

#define HDF_LOG_TAG HDF_AUDIO_EFFECT
struct EffectHwControl {
    struct EffectControl impls;
};

static int32_t MockEffectInitController(int8_t *commandData, uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    (void)commandData;
    (void)cmdDataLen;
    return HDF_SUCCESS;
}

static int32_t MockEffectSetConfig(int8_t *commandData, uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    (void)commandData;
    (void)cmdDataLen;
    return HDF_SUCCESS;
}

static int32_t MockEffectGetCofig(int8_t *commandData, uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    (void)commandData;
    (void)cmdDataLen;
    return HDF_SUCCESS;
}

static int32_t MockEffectReset(int8_t *commandData, uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    (void)commandData;
    (void)cmdDataLen;
    return HDF_SUCCESS;
}

static int32_t MockEffectEnable(int8_t *commandData, uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    (void)commandData;
    (void)cmdDataLen;
    return HDF_SUCCESS;
}

static int32_t MockEffectDisable(int8_t *commandData, uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    (void)commandData;
    (void)cmdDataLen;
    return HDF_SUCCESS;
}

static int32_t MockEffectSetparams(int8_t *commandData, uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    (void)commandData;
    (void)cmdDataLen;
    return HDF_SUCCESS;
}

static int32_t MockEffectGetParams(int8_t *commandData, uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        return HDF_ERR_INVALID_PARAM;
    }
    (void)commandData;
    (void)cmdDataLen;
    return HDF_SUCCESS;
}

static struct EffectCommandTable g_effectCommandTable[] = {
    {AUDIO_EFFECT_COMMAND_INIT_CONTOLLER, MockEffectInitController},
    {AUDIO_EFFECT_COMMAND_SET_CONFIG, MockEffectSetConfig},
    {AUDIO_EFFECT_COMMAND_GET_CONFIG, MockEffectGetCofig},
    {AUDIO_EFFECT_COMMAND_RESET, MockEffectReset},
    {AUDIO_EFFECT_COMMAND_ENABLE, MockEffectEnable},
    {AUDIO_EFFECT_COMMAND_DISABLE, MockEffectDisable},
    {AUDIO_EFFECT_COMMAND_SET_PARAM, MockEffectSetparams},
    {AUDIO_EFFECT_COMMAND_GET_PARAM, MockEffectGetParams},
};

static int32_t MockEffectProcess(struct EffectControl *self, const struct AudioEffectBuffer *input,
                                 struct AudioEffectBuffer *output)
{
    if (self == NULL || input == NULL || output == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t MockSendCommand(struct EffectControl *self, uint32_t cmdId, int8_t *commandData,
                               uint32_t cmdDataLen, int8_t *replyData, uint32_t *replyDataLen)
{
    if (self == NULL || commandData == NULL || replyData == NULL || replyDataLen == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct EffectCommandTable *cmdTable = g_effectCommandTable;
    
    if (cmdId >= (sizeof(g_effectCommandTable) / sizeof(struct EffectCommandTable))) {
        HDF_LOGE("%{public}s: the index of the table is invailied", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (cmdTable[cmdId].func == NULL) {
        HDF_LOGE("%{public}s: the corresponding command function is null", __func__);
        return HDF_FAILURE;
    }

    return cmdTable[cmdId].func(commandData, cmdDataLen, replyData, replyDataLen);
}

int32_t MockGetEffectDescriptor(struct EffectControl *self, struct EffectControllerDescriptor *desc)
{
    if (self == NULL || desc == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    return HDF_SUCCESS;
}

static int32_t MockCreateController(struct EffectFactory *self, const struct EffectInfo *info, 
                                    struct EffectControl **handle)
{
    if (self == NULL || info == NULL || handle == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct EffectHwControl *hwCtrl = (struct EffectHwControl *)OsalMemCalloc(sizeof(struct EffectHwControl));
    if (hwCtrl == NULL) {
        HDF_LOGE("%{public}s: hwCtrl is NULL", __func__);
        return HDF_FAILURE;
    }

    hwCtrl->impls.EffectProcess = MockEffectProcess;
    hwCtrl->impls.SendCommand = MockSendCommand;
    hwCtrl->impls.GetEffectDescriptor = MockGetEffectDescriptor,
    *handle = &hwCtrl->impls;

    return HDF_SUCCESS;
}

static int32_t MockDestroyController(struct EffectFactory *self, struct EffectControl *handle)
{
    if (self == NULL || handle == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct EffectHwControl *hwCtrl = (struct EffectHwControl *)handle;
    OsalMemFree(hwCtrl);
    hwCtrl = NULL;

    return HDF_SUCCESS;
}

struct EffectFactory g_mockFactoryLib = {
    .version = 1,
    .effectLibName = "libmock_effect_lib",
    .supplier = "hdf",
    .CreateController = MockCreateController,
    .DestroyController = MockDestroyController,
};

struct EffectFactory *GetEffectoyFactoryLib()
{
    return &g_mockFactoryLib;
}