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
#include <securec.h>
#include <string.h>
#include "effect_core.h"
#include "effect_host_common.h"
#include "v1_0/effect_types_vdi.h"
#include "v1_0/effect_factory.h"
#include "osal_mem.h"
#include "parse_effect_config.h"
#include "audio_uhdf_log.h"

#define AUDIO_EFFECT_PLAFORM_CONFIG HDF_CONFIG_DIR"/audio_effect.json"
#define AUDIO_EFFECT_PRODUCT_CONFIG HDF_CHIP_PROD_CONFIG_DIR"/audio_effect.json"
#define HDF_LOG_TAG HDF_AUDIO_EFFECT
#define AUDIO_EFFECT_NUM_MAX 10
struct ConfigDescriptor *g_cfgDescs = NULL;
struct AudioEffectLibInfo {
    char *libName;
    uint8_t *libHandle;
    struct EffectFactory *libEffect;
    struct ControllerManager *ctrlMgr;
    int32_t effectCnt;
};
struct AudioEffectLibInfo *g_libInfos[AUDIO_EFFECT_NUM_MAX] = { NULL };

static struct AudioEffectLibInfo* GetEffectLibInfoByName(const char *libName)
{
    if (libName == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return NULL;
    }
    struct AudioEffectLibInfo *libInfo = NULL;
    for (int i = 0; i <= AUDIO_EFFECT_NUM_MAX; i++) {
        if (i == AUDIO_EFFECT_NUM_MAX) {
            HDF_LOGE("%{public}s: can not find %{public}s", __func__, libName);
            return NULL;
        }
        if (g_libInfos[i] == NULL || strcmp(g_libInfos[i]->libName, libName) != 0) {
            continue;
        }
        libInfo = g_libInfos[i];
        break;
    }
    return libInfo;
}

static int32_t LoadLibraryByName(const char *libName, uint8_t **libHandle, struct EffectFactory **factLib)
{
    if (libName == NULL || factLib == NULL || libHandle == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    int32_t ret = 0;
    struct EffectFactory *(*getFactoryLib)(void);
    char path[PATH_MAX];
    ret = snprintf_s(path, PATH_MAX, PATH_MAX, "%s.z.so", libName);
    if (ret < 0) {
        HDF_LOGE("%{public}s: get libPath failed", __func__);
        return HDF_FAILURE;
    }

    void *handle = dlopen(path, RTLD_LAZY);
    if (handle == NULL) {
        HDF_LOGE("%{public}s: open so failed, reason:%{public}s", __func__, dlerror());
        return HDF_FAILURE;
    }

    getFactoryLib = dlsym(handle, "GetEffectoyFactoryLib");
    if (getFactoryLib == NULL) {
        HDF_LOGE("%{public}s: dlsym failed %{public}s", __func__, dlerror());
        dlclose(handle);
        return HDF_FAILURE;
    }
    *factLib = getFactoryLib();
    if (*factLib == NULL) {
        HDF_LOGE("%{public}s: get fact lib failed %{public}s", __func__, dlerror());
        dlclose(handle);
        return HDF_FAILURE;
    }
    *libHandle = handle;
    return HDF_SUCCESS;
}

static struct AudioEffectLibInfo* AddEffectLibInfo(const char *libName, uint8_t *libHandle,
    struct EffectFactory *factLib)
{
    if (libName == NULL || factLib == NULL || libHandle == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return NULL;
    }
    struct AudioEffectLibInfo *libInfo = NULL;
    libInfo = (struct AudioEffectLibInfo *)OsalMemCalloc(sizeof(struct AudioEffectLibInfo));
    if (libInfo == NULL) {
        HDF_LOGE("%{public}s: OsalMemCalloc fail", __func__);
        return NULL;
    }
    libInfo->libName = strdup(libName);
    if (libInfo->libName == NULL) {
        HDF_LOGE("%{public}s: strdup fail", __func__);
        OsalMemFree(libInfo);
        libInfo = NULL;
        return NULL;
    }
    libInfo->libHandle = libHandle;
    libInfo->libEffect = factLib;
    libInfo->ctrlMgr = NULL;
    libInfo->effectCnt = 1;
    return libInfo;
}

static int32_t LoadEffectLibrary(const char *libName, struct EffectFactory **factLib,
    struct ControllerManager** ctrlMgr)
{
    if (libName == NULL || factLib == NULL || ctrlMgr == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    uint8_t *libHandle = NULL;
    int32_t index = 0;
    for (int i = 0; i <= AUDIO_EFFECT_NUM_MAX; i++) {
        if (i == AUDIO_EFFECT_NUM_MAX) {
            HDF_LOGE("%{public}s: over effect max num", __func__);
            return HDF_FAILURE;
        }
        if (g_libInfos[i] == NULL) {
            index = i;
            break;
        }
        if (strcmp(g_libInfos[i]->libName, libName) != 0) {
            continue;
        }
        g_libInfos[i]->effectCnt++;
        *factLib = g_libInfos[i]->libEffect;
        *ctrlMgr = g_libInfos[i]->ctrlMgr;
        HDF_LOGI("%{public}s: %{public}s increase, cnt=[%{public}d]", __func__, libName, g_libInfos[i]->effectCnt);
        return HDF_SUCCESS;
    }
    int32_t ret = LoadLibraryByName(libName, &libHandle, factLib);
    if (ret != HDF_SUCCESS || libHandle == NULL || *factLib == NULL) {
        HDF_LOGE("%{public}s: load lib fail, libName:[%{public}s]", __func__, libName);
        return HDF_FAILURE;
    }
    g_libInfos[index] = AddEffectLibInfo(libName, libHandle, *factLib);
    if (g_libInfos[index] == NULL) {
        HDF_LOGE("%{public}s: AddEffectLibInfo fail", __func__);
        dlclose((void *)libHandle);
        return HDF_FAILURE;
    }
    HDF_LOGI("%{public}s: %{public}s create, cnt=[%{public}d]", __func__, libName, g_libInfos[index]->effectCnt);
    return HDF_SUCCESS;
}

static int32_t DeleteEffectLibrary(const char *libName)
{
    if (libName == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    for (int i = 0; i <= AUDIO_EFFECT_NUM_MAX; i++) {
        if (i == AUDIO_EFFECT_NUM_MAX) {
            HDF_LOGE("%{public}s: fail to destroy effect, can not find %{public}s", __func__, libName);
            return HDF_FAILURE;
        }
        if (g_libInfos[i] == NULL || strcmp(g_libInfos[i]->libName, libName) != 0) {
            continue;
        }
        if (g_libInfos[i]->effectCnt > 1) {
            g_libInfos[i]->effectCnt--;
            HDF_LOGI("%{public}s: %{public}s decrease, cnt=[%{public}d]", __func__, libName, g_libInfos[i]->effectCnt);
            return HDF_SUCCESS;
        }
        dlclose((void*)g_libInfos[i]->libHandle);
        OsalMemFree(g_libInfos[i]->libName);
        OsalMemFree(g_libInfos[i]->ctrlMgr);
        OsalMemFree(g_libInfos[i]);
        g_libInfos[i] = NULL;
        break;
    }
    HDF_LOGI("%{public}s: %{public}s delete", __func__, libName);
    return HDF_SUCCESS;
}

static int32_t EffectModelIsSupplyEffectLibs(struct IEffectModel *self, bool *supply)
{
    if (self == NULL || supply == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    *supply = IsEffectLibExist();
    return HDF_SUCCESS;
}

static int32_t EffectModelGetAllEffectDescriptors(struct IEffectModel *self,
                                                  struct EffectControllerDescriptor *descs, uint32_t *descsLen)
{
    HDF_LOGD("enter to %{public}s", __func__);
    int32_t ret;
    uint32_t i;
    uint32_t descNum = 0;
    struct EffectFactory *factLib = NULL;
    struct ControllerManager *ctrlMgr = NULL;

    if (self == NULL || descs == NULL || descsLen == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    if (g_cfgDescs == NULL) {
        HDF_LOGE("%{public}s: point is null!", __func__);
        return HDF_FAILURE;
    }
    struct EffectControllerDescriptorVdi *descsVdi = (struct EffectControllerDescriptorVdi *)descs;
    for (i = 0; i < g_cfgDescs->effectNum; i++) {
        ret = LoadEffectLibrary(g_cfgDescs->effectCfgDescs[i].library, &factLib, &ctrlMgr);
        if (ret != HDF_SUCCESS || factLib == NULL) {
            HDF_LOGE("%{public}s: GetEffectLibFromList fail!", __func__);
            continue;
        }
        ret = factLib->GetDescriptor(factLib, g_cfgDescs->effectCfgDescs[i].effectId, &descsVdi[descNum]);
        if (ret != HDF_SUCCESS) {
            DeleteEffectLibrary(g_cfgDescs->effectCfgDescs[i].library);
            HDF_LOGE("%{public}s: GetDescriptor fail!", __func__);
            continue;
        }
        DeleteEffectLibrary(g_cfgDescs->effectCfgDescs[i].library);
        factLib = NULL;
        descNum++;
    }
    *descsLen = descNum;
    descs = (struct EffectControllerDescriptor *)descsVdi;
    HDF_LOGD("%{public}s success", __func__);
    return HDF_SUCCESS;
}

static int32_t EffectModelGetEffectDescriptor(struct IEffectModel *self, const char *uuid,
    struct EffectControllerDescriptor *desc)
{
    HDF_LOGD("enter to %{public}s", __func__);
    uint32_t i;
    struct EffectFactory *factLib = NULL;
    struct ControllerManager *ctrlMgr = NULL;
    if (self == NULL || uuid == NULL || desc == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct EffectControllerDescriptorVdi *descVdi = (struct EffectControllerDescriptorVdi *)desc;
    for (i = 0; i < g_cfgDescs->effectNum; i++) {
        if (strcmp(uuid, g_cfgDescs->effectCfgDescs[i].effectId) != 0) {
            continue;
        }

        LoadEffectLibrary(g_cfgDescs->effectCfgDescs[i].library, &factLib, &ctrlMgr);
        if (factLib == NULL) {
            HDF_LOGE("%{public}s: GetEffectLibFromList fail!", __func__);
            return HDF_FAILURE;
        }

        if (factLib->GetDescriptor(factLib, uuid, descVdi) != HDF_SUCCESS) {
            DeleteEffectLibrary(g_cfgDescs->effectCfgDescs[i].library);
            HDF_LOGE("%{public}s: GetDescriptor fail!", __func__);
            return HDF_FAILURE;
        }
        DeleteEffectLibrary(g_cfgDescs->effectCfgDescs[i].library);
        HDF_LOGD("%{public}s success", __func__);
        return HDF_SUCCESS;
    }
    desc = (struct EffectControllerDescriptor *)descVdi;
    HDF_LOGE("%{public}s fail!", __func__);
    return HDF_FAILURE;
}

static int32_t CreateEffectController(const struct EffectInfo *info, struct IEffectControl **contoller,
    struct ControllerId *contollerId, struct IEffectControlVdi *ctrlOps)
{
    if (info == NULL || contoller == NULL || contollerId == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    struct ControllerManager *ctrlMgr = (struct ControllerManager *)OsalMemCalloc(sizeof(struct ControllerManager));
    CHECK_NULL_PTR_RETURN_VALUE(ctrlMgr, HDF_FAILURE);
    struct AudioEffectLibInfo *libInfo = GetEffectLibInfoByName(info->libName);
    if (libInfo == NULL) {
        HDF_LOGE("%{public}s: GetEffectLibInfoByName failed", __func__);
        OsalMemFree(ctrlMgr);
        return HDF_FAILURE;
    }
    libInfo->ctrlMgr = ctrlMgr;
    ctrlMgr->ctrlOps = ctrlOps;
    ctrlMgr->libName = strdup(info->libName);
    if (ctrlMgr->libName == NULL) {
        HDF_LOGE("%{public}s: strdup failed, info->effectId = %{public}s", __func__, info->effectId);
        OsalMemFree(ctrlMgr);
        return HDF_FAILURE;
    }
    ctrlMgr->ctrlImpls.EffectProcess = EffectControlEffectProcess;
    ctrlMgr->ctrlImpls.SendCommand = EffectControlSendCommand;
    ctrlMgr->ctrlImpls.GetEffectDescriptor = EffectGetOwnDescriptor;
    ctrlMgr->ctrlImpls.EffectReverse = EffectControlEffectReverse;
    *contoller = &ctrlMgr->ctrlImpls;
    // free after send reply
    contollerId->libName = strdup(info->libName);
    contollerId->effectId = strdup(info->effectId);
    if (contollerId->libName == NULL || contollerId->effectId == NULL) {
        HDF_LOGE("%{public}s: strdup failed, info->libName = %{public}s", __func__, info->libName);
        OsalMemFree(ctrlMgr->libName);
        OsalMemFree(ctrlMgr);
        *contoller = NULL;
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

static int32_t EffectModelCreateEffectController(struct IEffectModel *self, const struct EffectInfo *info,
    struct IEffectControl **contoller, struct ControllerId *contollerId)
{
    if (self == NULL || info == NULL || contoller == NULL || contollerId == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct EffectFactory *lib = NULL;
    struct ControllerManager *ctrlMgr = NULL;
    struct IEffectControlVdi *ctrlOps = NULL;

    int32_t ret = LoadEffectLibrary(info->libName, &lib, &ctrlMgr);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: LoadEffectLibrary fail", __func__);
        return HDF_FAILURE;
    }
    if (ctrlMgr != NULL) {
        contollerId->libName = strdup(info->libName);
        contollerId->effectId = strdup(info->effectId);
        if (contollerId->libName == NULL || contollerId->effectId == NULL) {
            HDF_LOGE("%{public}s: strdup failed", __func__);
            return HDF_FAILURE;
        }
        *contoller = &ctrlMgr->ctrlImpls;
        return HDF_SUCCESS;
    }
    CHECK_NULL_PTR_RETURN_VALUE(lib, HDF_FAILURE);
    CHECK_NULL_PTR_RETURN_VALUE(lib->CreateController, HDF_FAILURE);
    
    struct EffectInfoVdi *infoVdi = (struct EffectInfoVdi *)info;
    lib->CreateController(lib, infoVdi, &ctrlOps);
    CHECK_NULL_PTR_RETURN_VALUE(ctrlOps, HDF_FAILURE);

    ret = CreateEffectController(info, contoller, contollerId, ctrlOps);
    if (ret != HDF_SUCCESS) {
        DeleteEffectLibrary(info->libName);
        return HDF_FAILURE;
    }
    
    HDF_LOGI("%{public}s: create effect succeed, libName = %{public}s", __func__, info->libName);
    return HDF_SUCCESS;
}

int32_t EffectModelDestroyEffectController(struct IEffectModel *self, const struct ControllerId *contollerId)
{
    if (self == NULL || contollerId == NULL) {
        HDF_LOGE("%{public}s: invailid input params", __func__);
        return HDF_ERR_INVALID_PARAM;
    }

    struct AudioEffectLibInfo *libInfo = GetEffectLibInfoByName(contollerId->libName);
    CHECK_NULL_PTR_RETURN_VALUE(libInfo, HDF_FAILURE);
    if (libInfo->effectCnt > 1) {
        libInfo->effectCnt--;
        return HDF_SUCCESS;
    }
    struct EffectFactory *lib = libInfo->libEffect;
    CHECK_NULL_PTR_RETURN_VALUE(lib, HDF_FAILURE);
    struct ControllerManager *ctrlMgr = libInfo->ctrlMgr;
    CHECK_NULL_PTR_RETURN_VALUE(ctrlMgr, HDF_FAILURE);

    if (ctrlMgr->libName != NULL) {
        OsalMemFree(ctrlMgr->libName);
        ctrlMgr->libName = NULL;
    }

    if (ctrlMgr->ctrlOps == NULL) {
        HDF_LOGE("%{public}s: controller has no options", __func__);
        return HDF_FAILURE;
    }

    /* call the lib destroy method，then free controller manager */
    lib->DestroyController(lib, ctrlMgr->ctrlOps);
    DeleteEffectLibrary(contollerId->libName);
    HDF_LOGI("%{public}s: destroy effect succeed, libName = %{public}s", __func__, contollerId->libName);
    return HDF_SUCCESS;
}

void ModelInit(void)
{
    FILE *file;
    struct ConfigDescriptor *cfgDesc = NULL;
    int32_t ret;
    file = fopen(AUDIO_EFFECT_PRODUCT_CONFIG, "r");
    if (file == NULL) {
        ret = AudioEffectGetConfigDescriptor(AUDIO_EFFECT_PLAFORM_CONFIG, &cfgDesc);
        HDF_LOGI("%{public}s: %{public}s!", __func__, AUDIO_EFFECT_PLAFORM_CONFIG);
    } else {
        ret = AudioEffectGetConfigDescriptor(AUDIO_EFFECT_PRODUCT_CONFIG, &cfgDesc);
        HDF_LOGI("%{public}s: %{public}s!", __func__, AUDIO_EFFECT_PRODUCT_CONFIG);
        (void)fclose(file);
    }
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: AudioEffectGetConfigDescriptor fail!", __func__);
        return;
    }

    if (cfgDesc == NULL || cfgDesc->effectCfgDescs == NULL || cfgDesc->libCfgDescs == NULL) {
        HDF_LOGE("cfgDesc is null!");
        return;
    }
    g_cfgDescs = cfgDesc;
    HDF_LOGD("%{public}s end!", __func__);
}

struct IEffectModel *EffectModelImplGetInstance(void)
{
    struct EffectModelService *service = (struct EffectModelService *)OsalMemCalloc(sizeof(struct EffectModelService));
    if (service == NULL) {
        HDF_LOGE("%{public}s: malloc EffectModelService obj failed!", __func__);
        return NULL;
    }

    ModelInit();
    service->interface.IsSupplyEffectLibs = EffectModelIsSupplyEffectLibs;
    service->interface.GetAllEffectDescriptors = EffectModelGetAllEffectDescriptors;
    service->interface.CreateEffectController = EffectModelCreateEffectController;
    service->interface.DestroyEffectController = EffectModelDestroyEffectController;
    service->interface.GetEffectDescriptor = EffectModelGetEffectDescriptor;

    return &service->interface;
}

void EffectModelImplRelease(struct IEffectModel *instance)
{
    if (instance == NULL) {
        return;
    }

    AudioEffectReleaseCfgDesc(g_cfgDescs);
    struct EffectModelService *service = CONTAINER_OF(instance, struct EffectModelService, interface);
    if (service == NULL) {
        return;
    }
    OsalMemFree(service);
    service = NULL;
}
