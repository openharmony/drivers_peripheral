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
#include "securec.h"

#define HDF_EFFECT_NAME_LEN      64
#define HDF_LOG_TAG HDF_AUDIO_EFFECT
struct EffectHwControl {
    struct EffectControl impls;
};

struct EffectControllerDescriptor g_mockEffectDescriptor = {
    .effectId = "aaaabbbb-8888-9999-6666-aabbccdd9966ff",
    .effectName = "mock_effect",
    .libName = "libmock_effect_lib",
    .supplier = "mock"
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

static void MockEffectReleaseDesc(struct EffectControllerDescriptor *desc)
{
    if (desc == NULL) {
        return;
    }

    OsalMemFree((void *)desc->effectId);
    desc->effectId = NULL;

    OsalMemFree((void *)desc->effectName);
    desc->effectName = NULL;

    OsalMemFree((void *)desc->libName);
    desc->libName = NULL;

    OsalMemFree((void *)desc->supplier);
    desc->supplier = NULL;
}

static int32_t MockCpyDesc(const char *src, char **dest)
{
    if (src == NULL || dest == NULL) {
        HDF_LOGE("%{public}s: invalid parameter!", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    *dest = (char *)OsalMemCalloc(HDF_EFFECT_NAME_LEN * sizeof(char));
    if (*dest == NULL) {
        HDF_LOGE("%{public}s: out of memory!", __func__);
        return HDF_ERR_MALLOC_FAIL;
    }

    if (memcpy_s((void *)(*dest), HDF_EFFECT_NAME_LEN, src, strlen(src)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s effect desc fail!", __func__);
        OsalMemFree((void **)dest);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t MockGetEffectDescriptorSub(struct EffectControllerDescriptor *desc)
{
    if (desc == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (MockCpyDesc(g_mockEffectDescriptor.effectId, &(desc->effectId)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: copy item %{public}s fail!", __func__, "effectId");
        MockEffectReleaseDesc(desc);
        return HDF_FAILURE;
    }

    if (MockCpyDesc(g_mockEffectDescriptor.effectName, &(desc->effectName)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: copy item %{public}s fail!", __func__, "effectName");
        MockEffectReleaseDesc(desc);
        return HDF_FAILURE;
    }

    if (MockCpyDesc(g_mockEffectDescriptor.libName, &(desc->libName)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: copy item %{public}s fail!", __func__, "libName");
        MockEffectReleaseDesc(desc);
        return HDF_FAILURE;
    }

    if (MockCpyDesc(g_mockEffectDescriptor.supplier, &(desc->supplier)) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: copy item %{public}s fail!", __func__, "supplier");
        MockEffectReleaseDesc(desc);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t MockGetEffectDescriptor(struct EffectControl *self, struct EffectControllerDescriptor *desc)
{
    HDF_LOGI("enter to %{public}s", __func__);
    if (self == NULL || desc == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (MockGetEffectDescriptorSub(desc) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get descriptor fail!", __func__);
        return HDF_FAILURE;
    }

    HDF_LOGE("%{public}s: succ", __func__);
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

int32_t MockGetDescriptor(struct EffectFactory *self, const char *uuid, struct EffectControllerDescriptor *desc)
{
    HDF_LOGI("enter to %{public}s", __func__);
    if (self == NULL || uuid == NULL || desc == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (strcmp(uuid, g_mockEffectDescriptor.effectId) != 0) {
        HDF_LOGE("%{public}s: error effectId!", __func__);
        return HDF_FAILURE;
    }

    if (MockGetEffectDescriptorSub(desc) != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: get descriptor fail!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

struct EffectFactory g_mockFactoryLib = {
    .version = 1,
    .effectLibName = "libmock_effect_lib",
    .supplier = "hdf",
    .CreateController = MockCreateController,
    .DestroyController = MockDestroyController,
    .GetDescriptor = MockGetDescriptor,
};

struct EffectFactory *GetEffectoyFactoryLib()
{
    return &g_mockFactoryLib;
}
