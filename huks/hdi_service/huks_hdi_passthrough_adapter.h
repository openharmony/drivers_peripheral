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

#ifndef HUKS_HDI_PASSTHROUGH_ADAPTER_H
#define HUKS_HDI_PASSTHROUGH_ADAPTER_H

#include "huks_hdi_template.h"
#include "huks_sa_type.h"
#include "huks_sa_hdi_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t HuksHdiAdapterGenerateKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn,
    const struct HksBlob *keyIn, struct HksBlob *keyOut);

int32_t HuksHdiAdapterSign(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *srcData,
    struct HksBlob *signature);

int32_t HuksHdiAdapterVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature);

int32_t HuksHdiAdapterEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText);

int32_t HuksHdiAdapterDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText);

int32_t HuksHdiAdapterGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random);

int32_t HuksHdiAdapterImportKey(const struct HksBlob *keyAlias, const struct HksBlob *key,
    const struct HksParamSet *paramSet, struct HksBlob *keyOut);

int32_t HuksHdiAdapterExportPublicKey(const struct HksBlob *key, const struct HksParamSet *paramSet,
    struct HksBlob *keyOut);

int32_t HuksHdiAdapterAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

int32_t HuksHdiAdapterDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
    struct HksBlob *derivedKey);

int32_t HuksHdiAdapterMac(const struct HksBlob *key, const struct HksParamSet *paramSet, const struct HksBlob *srcData,
    struct HksBlob *mac);

int32_t HuksHdiAdapterModuleInit(void);

int32_t HuksHdiAdapterModuleDestroy(void);

int32_t HuksHdiAdapterImportWrappedKey(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *wrappingKey,
    const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut);

int32_t HuksHdiAdapterInit(const struct  HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle,
    struct HksBlob *token);

int32_t HuksHdiAdapterUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

int32_t HuksHdiAdapterFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

int32_t HuksHdiAdapterAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet);

int32_t HuksHdiAdapterGetKeyProperties(const struct HksParamSet *paramSet, const struct HksBlob *key);

int32_t HuksHdiAdapterAttestKey(const struct HksBlob *key, const  struct HksParamSet *paramSet,
    struct HksBlob *certChain);

int32_t HuksHdiAdapterUpgradeKey(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
    struct HksBlob *newKey);

int32_t HuksInitHuksCoreEngine(void);

int32_t HuksReleaseCoreEngine(void);

struct HuksHdi *HuksGetCoreEngine(void);

#ifdef __cplusplus
}
#endif

#endif