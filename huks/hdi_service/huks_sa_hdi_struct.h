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

#ifndef HUKS_SA_HDI_H
#define HUKS_SA_HDI_H

#include "huks_sa_type.h"

struct HuksHdi {
    /**
     * @brief HUKS initialize
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiModuleInit)(void);

    /**
     * @brief HUKS destroy
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiModuleDestroy)(void);

    /**
     * @brief HUKS fresh key info
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiRefresh)(void);

    /**
     * @brief Generate key
     * @param keyAlias key alias
     * @param paramSet required parameter set
     * @param keyIn key to generate key
     * @param keyOut output key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiGenerateKey)(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
        const struct HksBlob *keyIn, struct HksBlob *keyOut);

    /**
     * @brief Import key
     * @param keyAlias key alias
     * @param key the key needs to be imported
     * @param paramSet required parameter set
     * @param keyOut output key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiImportKey)(const struct HksBlob *keyAlias, const struct HksBlob *key,
        const struct HksParamSet *paramSet, struct HksBlob *keyOut);

    /**
     * @brief Import wrapped key
     * @param wrappingKeyAlias alias used to decrypt the key data after the wrap
     * @param key the key to wrap key
     * @param wrappedKeyData wrapped key data out
     * @param paramSet required parameter set
     * @param keyOut output key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiImportWrappedKey)(const struct HksBlob *wrappingKeyAlias, const struct HksBlob *key,
        const struct HksBlob *wrappedKeyData, const struct HksParamSet *paramSet, struct HksBlob *keyOut);

    /**
     * @brief Export public key
     * @param key key need to export
     * @param paramSet required parameter set
     * @param keyOut exported key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiExportPublicKey)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        struct HksBlob *keyOut);

    /**
     * @brief Init operation
     * @param key the key
     * @param paramSet required parameter set
     * @param handle operation handle
     * @param token token
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiInit)(const struct HksBlob *key, const struct HksParamSet *paramSet, struct HksBlob *handle,
        struct HksBlob *token);

    /**
     * @brief Update operation
     * @param handle operation handle
     * @param paramSet required parameter set
     * @param inData the data to update
     * @param outData output data
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiUpdate)(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData);

    /**
     * @brief Finish operation
     * @param handle operation handle
     * @param paramSet required parameter set
     * @param inData the data to update
     * @param outData output data
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiFinish)(const struct HksBlob *handle, const struct HksParamSet *paramSet,
        const struct HksBlob *inData, struct HksBlob *outData);

    /**
     * @brief Finish operation
     * @param handle operation handle
     * @param paramSet required parameter set
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiAbort)(const struct HksBlob *handle, const struct HksParamSet *paramSet);

    /**
     * @brief Get key properties
     * @param paramSet required parameter set
     * @param key the key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiGetKeyProperties)(const struct HksParamSet *paramSet, const struct HksBlob *key);

    /**
     * @brief Attest key
     * @param key the key
     * @param paramSet required parameter set
     * @param certChain cert chain
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiAttestKey)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        struct HksBlob *certChain);

    /**
     * @brief Get ability
     * @param funcType the function type
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiGetAbility)(int32_t funcType);

    /**
     * @brief Get hardware info
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiGetHardwareInfo)(void);

    /**
     * @brief Calculate mac header
     * @param paramSet required parameter set
     * @param salt the salt value
     * @param srcData the data to calculte
     * @param mac output mac value
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiCalcMacHeader)(const struct HksParamSet *paramSet, const struct HksBlob *salt,
        const struct HksBlob *srcData, struct HksBlob *mac);

    /**
     * @brief Upgrade key info
     * @param keyAlias key alias
     * @param keyInfo key info
     * @param keyOut output key value
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiUpgradeKeyInfo)(const struct HksBlob *keyAlias, const struct HksBlob *keyInfo,
        struct HksBlob *keyOut);

    /**
     * @brief Generate random
     * @param paramSet required parameter set
     * @param random output random
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiGenerateRandom)(const struct HksParamSet *paramSet, struct HksBlob *random);

    /**
     * @brief Sign operation
     * @param key required key to sign data
     * @param paramSet required parameter set
     * @param srcData the data needs to sign
     * @param signature signatured data
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiSign)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, struct HksBlob *signature);

    /**
     * @brief Verify operation
     * @param key required key to verify data
     * @param paramSet required parameter set
     * @param srcData the data needs to verify
     * @param signature verified data
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiVerify)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, const struct HksBlob *signature);

    /**
     * @brief Encrypt operation
     * @param key required key to encrypt data
     * @param paramSet required parameter set
     * @param plainText the data needs to encrypt
     * @param cipherText encrypted data
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiEncrypt)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *plainText, struct HksBlob *cipherText);

    /**
     * @brief Decrypt operation
     * @param key required key to decrypt data
     * @param paramSet required parameter set
     * @param cipherText the data needs to decrypt
     * @param plainText decrypted data
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiDecrypt)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *cipherText, struct HksBlob *plainText);

    /**
     * @brief Agree key
     * @param paramSet required parameter set
     * @param privateKey self private key
     * @param peerPublicKey peer public key
     * @param agreedKey agreed key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiAgreeKey)(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
        const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

    /**
     * @brief Derive key
     * @param paramSet required parameter set
     * @param kdfKey main key to derive key
     * @param derivedKey derived key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiDeriveKey)(const struct HksParamSet *paramSet, const struct HksBlob *kdfKey,
        struct HksBlob *derivedKey);

    /**
     * @brief Mac operation
     * @param key main key to derive key
     * @param paramSet required parameter set
     * @param srcData data needs to mac
     * @param mac mac value
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiMac)(const struct HksBlob *key, const struct HksParamSet *paramSet,
        const struct HksBlob *srcData, struct HksBlob *mac);

    /**
     * @brief Upgrade key
     * @param oldKey old key to be upgraded
     * @param paramSet required parameter set
     * @param newKey new key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiUpgradeKey)(const struct HksBlob *oldKey, const struct HksParamSet *paramSet,
        struct HksBlob *newKey);

    /**
     * @brief Export chipset platform publicKey
     * @param salt salt value
     * @param scene scene
     * @param publicKey public key
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiExportChipsetPlatformPublicKey)(const struct HksBlob *salt,
        enum HksChipsetPlatformDecryptScene scene, struct HksBlob *publicKey);

    /**
     * @brief Get the detailed error information.
     * @param errorInfo indicates the detailed error information
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiGetErrorInfo)(struct HksBlob *errorInfo);

        /**
     * @brief Get the statistic information.
     * @param errorInfo indicates the detailed statistic information
     * @return error code, see huks_sa_type.h
     */
    int32_t (*HuksHdiGetStatInfo)(struct HksBlob *statInfo);
};

#endif