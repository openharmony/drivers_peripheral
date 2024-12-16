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

#include <dlfcn.h>
#include <hdf_log.h>

#include "huks_hdi_passthrough_adapter.h"
#include "huks_sa_type.h"
#include "huks_sa_hdi_struct.h"
#include "huks_hdi_template.h"


typedef struct HuksHdi *(*HalCreateHandle)(void);
typedef void (*HalDestroyHandle)(struct HuksHdi *);

static struct HuksHdi *g_coreEngine = NULL;
static void *g_coreEngineHandle = NULL;

int32_t HuksHdiAdapterModuleInit(void)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiModuleInit, HUKS_ERROR_NULL_POINTER,
        "Module Init function is null pointer")

    return g_coreEngine->HuksHdiModuleInit();
}

int32_t HuksHdiAdapterModuleDestroy(void)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiModuleDestroy, HUKS_ERROR_NULL_POINTER,
        "Module Destroy function is null pointer")

    return g_coreEngine->HuksHdiModuleDestroy();
}

int32_t HuksHdiAdapterRefresh(void)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiRefresh, HUKS_ERROR_NULL_POINTER,
        "Refresh function is null pointer")

    return g_coreEngine->HuksHdiRefresh();
}

int32_t HuksHdiAdapterGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiGenerateKey, HUKS_ERROR_NULL_POINTER,
        "GenerateKey function is null pointer")

    return g_coreEngine->HuksHdiGenerateKey(keyAlias, paramSetIn, keyIn, keyOut);
}

int32_t HuksHdiAdapterImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiImportKey, HUKS_ERROR_NULL_POINTER,
        "ImportKey function is null pointer")

    return g_coreEngine->HuksHdiImportKey(keyAlias, key, paramSet, keyOut);
}

int32_t HuksHdiAdapterImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *wrappingKey,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiImportWrappedKey, HUKS_ERROR_NULL_POINTER,
        "ImportWrappedKey function is null pointer")

    return g_coreEngine->HuksHdiImportWrappedKey(wrappingKeyAlias, wrappingKey, wrappedKeyData, paramSet, keyOut);
}

int32_t HuksHdiAdapterExportPublicKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiExportPublicKey, HUKS_ERROR_NULL_POINTER,
        "ExportPublicKey function is null pointer")

    return g_coreEngine->HuksHdiExportPublicKey(key, paramSet, keyOut);
}

int32_t HuksHdiAdapterInit(const struct  HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiInit, HUKS_ERROR_NULL_POINTER,
        "Init function is null pointer")

    return g_coreEngine->HuksHdiInit(key, paramSet, handle, token);
}

int32_t HuksHdiAdapterUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiUpdate, HUKS_ERROR_NULL_POINTER,
        "Update function is null pointer")

    return g_coreEngine->HuksHdiUpdate(handle, paramSet, inData, outData);
}

int32_t HuksHdiAdapterFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiFinish, HUKS_ERROR_NULL_POINTER,
        "Finish function is null pointer")

    return g_coreEngine->HuksHdiFinish(handle, paramSet, inData, outData);
}

int32_t HuksHdiAdapterAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiAbort, HUKS_ERROR_NULL_POINTER,
        "Abort function is null pointer")

    return g_coreEngine->HuksHdiAbort(handle, paramSet);
}

int32_t HuksHdiAdapterGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiGetKeyProperties, HUKS_ERROR_NULL_POINTER,
        "GetKeyProperties function is null pointer")

    return g_coreEngine->HuksHdiGetKeyProperties(paramSet, key);
}

int32_t HuksHdiAdapterSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiSign, HUKS_ERROR_NULL_POINTER,
        "Sign function is null pointer")

    return g_coreEngine->HuksHdiSign(key, paramSet, srcData, signature);
}

int32_t HuksHdiAdapterVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiVerify, HUKS_ERROR_NULL_POINTER,
        "Verify function is null pointer")

    return g_coreEngine->HuksHdiVerify(key, paramSet, srcData, signature);
}

int32_t HuksHdiAdapterEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiEncrypt, HUKS_ERROR_NULL_POINTER,
        "Encrypt function is null pointer")

    return g_coreEngine->HuksHdiEncrypt(key, paramSet, plainText, cipherText);
}

int32_t HuksHdiAdapterDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiDecrypt, HUKS_ERROR_NULL_POINTER,
        "Decrypt function is null pointer")

    return g_coreEngine->HuksHdiDecrypt(key, paramSet, cipherText, plainText);
}

int32_t HuksHdiAdapterAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiAgreeKey, HUKS_ERROR_NULL_POINTER,
        "AgreeKey function is null pointer")

    return g_coreEngine->HuksHdiAgreeKey(paramSet, privateKey, peerPublicKey, agreedKey);
}

int32_t HuksHdiAdapterDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    struct HksBlob *derivedKey)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiDeriveKey, HUKS_ERROR_NULL_POINTER,
        "DeriveKey function is null pointer")

    return g_coreEngine->HuksHdiDeriveKey(paramSet, kdfKey, derivedKey);
}

int32_t HuksHdiAdapterMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiMac, HUKS_ERROR_NULL_POINTER,
        "Mac function is null pointer")

    return g_coreEngine->HuksHdiMac(key, paramSet, srcData, mac);
}

int32_t HuksHdiAdapterUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiUpgradeKey, HUKS_ERROR_NULL_POINTER,
        "Change key owner function is null pointer")

    return g_coreEngine->HuksHdiUpgradeKey(oldKey, paramSet, newKey);
}

int32_t HuksHdiAdapterAttestKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *certChain)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiAttestKey, HUKS_ERROR_NULL_POINTER,
        "AttestKey function is null pointer")

    return g_coreEngine->HuksHdiAttestKey(key, paramSet, certChain);
}

int32_t HuksHdiAdapterGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiGenerateRandom, HUKS_ERROR_NULL_POINTER,
        "GenerateRandom function is null pointer")

    return g_coreEngine->HuksHdiGenerateRandom(paramSet, random);
}

int32_t HuksHdiAdapterGetErrorInfo(struct HksBlob *errorInfo)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiGetErrorInfo, HUKS_ERROR_NULL_POINTER,
        "Init function is null pointer")

    return g_coreEngine->HuksHdiGetErrorInfo(errorInfo);
}

int32_t HuksHdiAdapterGetStatInfo(struct HksBlob *statInfo)
{
    HUKS_HDI_IF_NOT_SUCC_RETURN(HuksInitHuksCoreEngine(), HUKS_ERROR_NULL_POINTER)

    HUKS_HDI_IF_NULL_LOGE_RETURN(g_coreEngine->HuksHdiGetStatInfo, HUKS_ERROR_NULL_POINTER,
        "Init function is null pointer")

    return g_coreEngine->HuksHdiGetStatInfo(statInfo);
}

int32_t HuksInitHuksCoreEngine(void)
{
    if (g_coreEngine != NULL) {
        return HUKS_SUCCESS;
    }

    // libhuks_engine_core_standard is a software implementation version of huks driver, built-in system image
    // by the source code at security_huks/services/huks_standard/huks_engine/main
    g_coreEngineHandle = dlopen("libhuks_engine_core_standard.z.so", RTLD_NOW);
    if (g_coreEngineHandle == NULL) {
        HDF_LOGE("HUKS dlopen failed, %{public}s!", dlerror());
        return HUKS_ERROR_NULL_POINTER;
    }

    HalCreateHandle devicePtr = (HalCreateHandle)dlsym(g_coreEngineHandle, "HuksCreateHdiDevicePtr");
    if (devicePtr == NULL) {
        HDF_LOGE("HUKS dlsym failed, %{public}s!", dlerror());
        dlclose(g_coreEngineHandle);
        g_coreEngineHandle = NULL;
        return HUKS_ERROR_NULL_POINTER;
    }

    g_coreEngine = (*devicePtr)();
    if (g_coreEngine == NULL) {
        HDF_LOGE("HUKS coreEngine is NULL!");
        dlclose(g_coreEngineHandle);
        g_coreEngineHandle = NULL;
        return HUKS_ERROR_NULL_POINTER;
    }
    HDF_LOGI("HUKS HuksInitHuksCoreEngine init success!");
    return HUKS_SUCCESS;
}

int32_t HuksReleaseCoreEngine(void)
{
    if (g_coreEngine == NULL) {
        return HUKS_SUCCESS;
    }
    
    if (g_coreEngineHandle == NULL) {
        HDF_LOGE("HUKS g_coreEngineHandle is NULL!");
        return HUKS_ERROR_NULL_POINTER;
    }

    HalDestroyHandle halDestroyHandle = (HalDestroyHandle)dlsym(g_coreEngineHandle, "HuksDestoryHdiDevicePtr");
    (*halDestroyHandle)(g_coreEngine);
    g_coreEngine = NULL;

    dlclose(g_coreEngineHandle);
    g_coreEngineHandle = NULL;
    return HUKS_SUCCESS;
}

struct HuksHdi *HuksGetCoreEngine(void)
{
    return g_coreEngine;
}
