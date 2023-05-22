#ifndef OHOS_HDI_HUKS_V1_0_IHUKS_H
#define OHOS_HDI_HUKS_V1_0_IHUKS_H

#include <stdbool.h>
#include <stdint.h>
#include <hdf_base.h>
#include "huks/v1_0/ihuks_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define IHUKS_INTERFACE_DESC "ohos.hdi.huks.v1_0.IHuks"

#define IHUKS_MAJOR_VERSION 1
#define IHUKS_MINOR_VERSION 0

struct IHuks {
    int32_t (*ModuleInit)(struct IHuks *self);

    int32_t (*GenerateKey)(struct IHuks *self, const struct HuksBlob* keyAlias, const struct HuksParamSet* paramSet,
         const struct HuksBlob* keyIn, struct HuksBlob* keyOut);

    int32_t (*ImportKey)(struct IHuks *self, const struct HuksBlob* keyAlias, const struct HuksBlob* key,
         const struct HuksParamSet* paramSet, struct HuksBlob* keyOut);

    int32_t (*ImportWrappedKey)(struct IHuks *self, const struct HuksBlob* wrappingKeyAlias, const struct HuksBlob* key,
         const struct HuksBlob* wrappedKeyData, const struct HuksParamSet* paramSet, struct HuksBlob* keyOut);

    int32_t (*ExportPublicKey)(struct IHuks *self, const struct HuksBlob* key, const struct HuksParamSet* paramSet,
         struct HuksBlob* keyOut);

    int32_t (*Init)(struct IHuks *self, const struct HuksBlob* key, const struct HuksParamSet* paramSet,
         struct HuksBlob* handle, struct HuksBlob* token);

    int32_t (*Update)(struct IHuks *self, const struct HuksBlob* handle, const struct HuksParamSet* paramSet,
         const struct HuksBlob* inData, struct HuksBlob* outData);

    int32_t (*Finish)(struct IHuks *self, const struct HuksBlob* handle, const struct HuksParamSet* paramSet,
         const struct HuksBlob* inData, struct HuksBlob* outData);

    int32_t (*Abort)(struct IHuks *self, const struct HuksBlob* handle, const struct HuksParamSet* paramSet);

    int32_t (*GetKeyProperties)(struct IHuks *self, const struct HuksParamSet* paramSet, const struct HuksBlob* key);

    int32_t (*AttestKey)(struct IHuks *self, const struct HuksBlob* key, const struct HuksParamSet* paramSet,
         struct HuksBlob* certChain);

    int32_t (*GenerateRandom)(struct IHuks *self, const struct HuksParamSet* paramSet, struct HuksBlob* random);

    int32_t (*Sign)(struct IHuks *self, const struct HuksBlob* key, const struct HuksParamSet* paramSet,
         const struct HuksBlob* srcData, struct HuksBlob* signature);

    int32_t (*Verify)(struct IHuks *self, const struct HuksBlob* key, const struct HuksParamSet* paramSet,
         const struct HuksBlob* srcData, const struct HuksBlob* signature);

    int32_t (*Encrypt)(struct IHuks *self, const struct HuksBlob* key, const struct HuksParamSet* paramSet,
         const struct HuksBlob* plainText, struct HuksBlob* cipherText);

    int32_t (*Decrypt)(struct IHuks *self, const struct HuksBlob* key, const struct HuksParamSet* paramSet,
         const struct HuksBlob* cipherText, struct HuksBlob* plainText);

    int32_t (*AgreeKey)(struct IHuks *self, const struct HuksParamSet* paramSet, const struct HuksBlob* privateKey,
         const struct HuksBlob* peerPublicKey, struct HuksBlob* agreedKey);

    int32_t (*DeriveKey)(struct IHuks *self, const struct HuksParamSet* paramSet, const struct HuksBlob* kdfKey,
         struct HuksBlob* derivedKey);

    int32_t (*Mac)(struct IHuks *self, const struct HuksBlob* key, const struct HuksParamSet* paramSet,
         const struct HuksBlob* srcData, struct HuksBlob* mac);

    int32_t (*UpgradeKey)(struct IHuks *self, const struct HuksBlob* oldKey, const struct HuksParamSet* paramSet,
         struct HuksBlob* newKey);

    int32_t (*ExportChipsetPlatformPublicKey)(struct IHuks *self, const struct HuksBlob* salt,
         enum HuksChipsetPlatformDecryptScene scene, struct HuksBlob* publicKey);

    int32_t (*GetVersion)(struct IHuks *self, uint32_t* majorVer, uint32_t* minorVer);
};

// external method used to create client object, it support ipc and passthrought mode
struct IHuks *IHuksGet(bool isStub);
struct IHuks *IHuksGetInstance(const char *serviceName, bool isStub);

// external method used to create release object, it support ipc and passthrought mode
void IHuksRelease(struct IHuks *instance, bool isStub);
void IHuksReleaseInstance(const char *serviceName, struct IHuks *instance, bool isStub);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OHOS_HDI_HUKS_V1_0_IHUKS_H