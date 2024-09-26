/*
  *Copyright (c) 2023 Huawei Device Co., Ltd.
  *Licensed under the Apache License, Version 2.0 (the "License");
  *you may not use this file except in compliance with the License.
  *You may obtain a copy of the License at
 *
  *    http://www.apache.org/licenses/LICENSE-2.0
 *
  *Unless required by applicable law or agreed to in writing, software
  *distributed under the License is distributed on an "AS IS" BASIS,
  *WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  *See the License for the specific language governing permissions and
  *limitations under the License.
 */

#include <securec.h>

#include "v1_0/ihuks.h"
#include "v1_0/ihuks_types.h"

#include "huks_hdi_passthrough_adapter.h"
#include "huks_hdi_template.h"
#include "huks_sa_type.h"

#define HDF_LOG_TAG    huks_hdi_service

struct HuksService {
    struct IHuks interface;
};

static int32_t HuksModuleInit(struct IHuks *self)
{
    (void)self;
    return HuksHdiAdapterModuleInit();
}

static int32_t HuksModuleDestroy(struct IHuks *self)
{
    (void)self;
    return HuksHdiAdapterModuleDestroy();
}

static int32_t HuksGenerateKey(struct IHuks *self, const struct HuksBlob *keyAlias, const struct HuksParamSet *paramSet,
    const struct HuksBlob *keyIn, struct HuksBlob *encKeyOut)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_GENERATEKEY(keyAlias, paramSet, keyIn, encKeyOut, ret, HuksHdiAdapterGenerateKey)
    return ret;
}

static int32_t HuksImportKey(struct IHuks *self, const struct HuksBlob *keyAlias, const struct HuksBlob *key,
    const struct HuksParamSet *paramSet, struct HuksBlob *encKeyOut)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_IMPORTKEY(keyAlias, key, paramSet, encKeyOut, ret, HuksHdiAdapterImportKey)
    return ret;
}

static int32_t HuksImportWrappedKey(struct IHuks *self, const struct HuksBlob *wrappingKeyAlias,
    const struct HuksBlob *wrappingEncKey, const struct HuksBlob *wrappedKeyData, const struct HuksParamSet *paramSet,
    struct HuksBlob *encKeyOut)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_IMPORTWRAPPEDKEY(wrappingKeyAlias, wrappingEncKey, wrappedKeyData, paramSet, encKeyOut, ret,
        HuksHdiAdapterImportWrappedKey)
    return ret;
}

static int32_t HuksExportPublicKey(struct IHuks *self, const struct HuksBlob *encKey,
    const struct HuksParamSet *paramSet, struct HuksBlob *keyOut)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_EXPORTPUBLICKEY(encKey, paramSet, keyOut, ret, HuksHdiAdapterExportPublicKey)
    return ret;
}

static int32_t HuksInit(struct IHuks *self, const struct HuksBlob *encKey, const struct HuksParamSet *paramSet,
    struct HuksBlob *handle, struct HuksBlob *token)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_INIT(encKey, paramSet, handle, token, ret, HuksHdiAdapterInit)
    return ret;
}

static int32_t HuksUpdate(struct IHuks *self, const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_UPDATE(handle, paramSet, inData, outData, ret, HuksHdiAdapterUpdate)
    return ret;
}

static int32_t HuksFinish(struct IHuks *self, const struct HuksBlob *handle, const struct HuksParamSet *paramSet,
    const struct HuksBlob *inData, struct HuksBlob *outData)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_FINISH(handle, paramSet, inData, outData, ret, HuksHdiAdapterFinish)
    return ret;
}

static int32_t HuksAbort(struct IHuks *self, const struct HuksBlob *handle, const struct HuksParamSet *paramSet)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_ABORT(handle, paramSet, ret, HuksHdiAdapterAbort)
    return ret;
}

static int32_t HuksCheckKeyValidity(struct IHuks *self, const struct HuksParamSet *paramSet,
    const struct HuksBlob *encKey)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_CHECKKEYVALIDITY(paramSet, encKey, ret, HuksHdiAdapterGetKeyProperties)
    return ret;
}

static int32_t HuksAttestKey(struct IHuks *self, const struct HuksBlob *encKey, const struct HuksParamSet *paramSet,
    struct HuksBlob *certChain)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_ATTESTKEY(encKey, paramSet, certChain, ret, HuksHdiAdapterAttestKey)
    return ret;
}

static int32_t HuksGenerateRandom(struct IHuks *self, const struct HuksParamSet *paramSet, struct HuksBlob *random)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_GENERATERANDOM(paramSet, random, ret, HuksHdiAdapterGenerateRandom)
    return ret;
}

static int32_t HuksSign(struct IHuks *self, const struct HuksBlob *encKey, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *signature)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_SIGN(encKey, paramSet, srcData, signature, ret, HuksHdiAdapterSign)
    return ret;
}

static int32_t HuksVerify(struct IHuks *self, const struct HuksBlob *encKey, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, const struct HuksBlob *signature)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_VERIFY(encKey, paramSet, srcData, signature, ret, HuksHdiAdapterVerify)
    return ret;
}

static int32_t HuksEncrypt(struct IHuks *self, const struct HuksBlob *encKey, const struct HuksParamSet *paramSet,
    const struct HuksBlob *plainText, struct HuksBlob *cipherText)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_ENCRYPT(encKey, paramSet, plainText, cipherText, ret, HuksHdiAdapterEncrypt)
    return ret;
}

static int32_t HuksDecrypt(struct IHuks *self, const struct HuksBlob *encKey, const struct HuksParamSet *paramSet,
    const struct HuksBlob *cipherText, struct HuksBlob *plainText)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_DECRYPT(encKey, paramSet, cipherText, plainText, ret, HuksHdiAdapterDecrypt)
    return ret;
}

static int32_t HuksAgreeKey(struct IHuks *self, const struct HuksParamSet *paramSet,
    const struct HuksBlob *encPrivateKey, const struct HuksBlob *peerPublicKey, struct HuksBlob *agreedKey)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_AGREEKEY(paramSet, encPrivateKey, peerPublicKey, agreedKey, ret, HuksHdiAdapterAgreeKey)
    return ret;
}

static int32_t HuksDeriveKey(struct IHuks *self, const struct HuksParamSet *paramSet, const struct HuksBlob *encKdfKey,
    struct HuksBlob *derivedKey)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_DERIVEKEY(paramSet, encKdfKey, derivedKey, ret, HuksHdiAdapterDeriveKey)
    return ret;
}

static int32_t HuksMac(struct IHuks *self, const struct HuksBlob *encKey, const struct HuksParamSet *paramSet,
    const struct HuksBlob *srcData, struct HuksBlob *mac)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_MAC(encKey, paramSet, srcData, mac, ret, HuksHdiAdapterMac)
    return ret;
}

static int32_t HuksUpgradeKey(struct IHuks *self, const struct HuksBlob *encOldKey, const struct HuksParamSet *paramSet,
    struct HuksBlob *encNewKey)
{
    (void)self;
    int32_t ret = HUKS_FAILURE;
    HDI_CONVERTER_FUNC_UPGRADEKEY(encOldKey, paramSet, encNewKey, ret, HuksHdiAdapterUpgradeKey)
    return ret;
}

static int32_t HuksGetVersion(struct IHuks *self, uint32_t *majorVer, uint32_t *minorVer)
{
    *majorVer = IHUKS_MAJOR_VERSION;
    *minorVer = IHUKS_MINOR_VERSION;
    return HUKS_SUCCESS;
}

struct IHuks *HuksImplGetInstance(void)
{
    struct HuksService *service = (struct HuksService *)malloc(sizeof(struct HuksService));
    if (service == NULL) {
        return NULL;
    }

    service->interface.ModuleInit = HuksModuleInit;
    service->interface.ModuleDestroy = HuksModuleDestroy;
    service->interface.GenerateKey = HuksGenerateKey;
    service->interface.ImportKey = HuksImportKey;
    service->interface.ImportWrappedKey = HuksImportWrappedKey;
    service->interface.ExportPublicKey = HuksExportPublicKey;
    service->interface.Init = HuksInit;
    service->interface.Update = HuksUpdate;
    service->interface.Finish = HuksFinish;
    service->interface.Abort = HuksAbort;
    service->interface.CheckKeyValidity = HuksCheckKeyValidity;
    service->interface.AttestKey = HuksAttestKey;
    service->interface.GenerateRandom = HuksGenerateRandom;
    service->interface.Sign = HuksSign;
    service->interface.Verify = HuksVerify;
    service->interface.Encrypt = HuksEncrypt;
    service->interface.Decrypt = HuksDecrypt;
    service->interface.AgreeKey = HuksAgreeKey;
    service->interface.DeriveKey = HuksDeriveKey;
    service->interface.Mac = HuksMac;
    service->interface.UpgradeKey = HuksUpgradeKey;
    service->interface.GetVersion = HuksGetVersion;
    return &service->interface;
}

void HuksImplRelease(struct IHuks *instance)
{
    if (instance == NULL) {
        return;
    }
    (void)HuksReleaseCoreEngine();
    free(instance);
}
