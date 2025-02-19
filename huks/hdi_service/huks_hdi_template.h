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

#ifndef HUKS_HDI_TEMPLATE_H
#define HUKS_HDI_TEMPLATE_H

#include "huks_sa_type.h"

typedef struct HksBlob TargetBlob;
typedef struct HksParamSet TargetParamSet;

#define HDI_ADAPTER_PARAM(oldParamPtr, newParamPtr) ((oldParamPtr) == NULL ?  NULL : (newParamPtr))


#define HDI_CONVERTER_PARAM_IN_BLOB(fromHuksBlobPtr, toHksBlobPtr)  \
    if ((fromHuksBlobPtr) != NULL && (toHksBlobPtr) != NULL) {      \
        (toHksBlobPtr)->data = (fromHuksBlobPtr)->data;             \
        (toHksBlobPtr)->size = (fromHuksBlobPtr)->dataLen;          \
    }

#define HDI_CONVERTER_PARAM_IN_PARAMSET(fromHuksParamSetPtr, toHksParamSetPtr)   \
    if ((fromHuksParamSetPtr) != NULL && (fromHuksParamSetPtr)->data != NULL &&  \
        (fromHuksParamSetPtr)->dataLen >= sizeof(TargetParamSet)) {              \
        (toHksParamSetPtr) = (TargetParamSet *)(fromHuksParamSetPtr)->data;      \
    }

#define HDI_CONVERTER_PARAM_OUT_BLOB(fromHksBlobPtr, toHuksBlobPtr) \
    if ((fromHksBlobPtr) != NULL && (toHuksBlobPtr) != NULL) {      \
        (toHuksBlobPtr)->data = (fromHksBlobPtr)->data;             \
        (toHuksBlobPtr)->dataLen = (fromHksBlobPtr)->size;          \
    }

#define HDI_CONVERTER_FUNC_GENERATEKEY(keyAlias, paramSet, keyIn, keyOut, ret, func) \
    TargetBlob keyAliasCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob keyInCore = {0};  \
    TargetBlob keyOutCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyAlias, &keyAliasCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyIn, &keyInCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyOut, &keyOutCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(keyAlias, &keyAliasCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(keyIn, &keyInCore),        \
                 HDI_ADAPTER_PARAM(keyOut, &keyOutCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&keyOutCore, keyOut)

#define HDI_CONVERTER_FUNC_IMPORTKEY(keyAlias, key, paramSet, keyOut, ret, func) \
    TargetBlob keyAliasCore = {0};   \
    TargetParamSet *paramSetCore = NULL;   \
    TargetBlob keyCore = {0};   \
    TargetBlob keyOutCore = {0};   \
    HDI_CONVERTER_PARAM_IN_BLOB(keyAlias, &keyAliasCore)   \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)   \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)   \
    HDI_CONVERTER_PARAM_IN_BLOB(keyOut, &keyOutCore)   \
    ret = (func)(HDI_ADAPTER_PARAM(keyAlias, &keyAliasCore), \
                 HDI_ADAPTER_PARAM(key, &keyCore),   \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore), \
                 HDI_ADAPTER_PARAM(keyOut, &keyOutCore));   \
    HDI_CONVERTER_PARAM_OUT_BLOB(&keyOutCore, keyOut)

#define HDI_CONVERTER_FUNC_IMPORTWRAPPEDKEY(wrappedKeyAlias, key, wrappedKeyData, paramSet, keyOut, ret, func)   \
    TargetBlob wrappingKeyAliasCore = {0};  \
    TargetBlob keyCore = {0};  \
    TargetBlob wrappedKeyDataCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob keyOutCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(wrappingKeyAlias, &wrappingKeyAliasCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(wrappedKeyData, &wrappedKeyDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyOut, &keyOutCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(wrappingKeyAlias, &wrappedKeyDataCore),  \
                 HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(wrappedKeyData, &wrappedKeyDataCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(keyOut, &keyOutCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&keyOutCore, keyOut)

#define HDI_CONVERTER_FUNC_EXPORTPUBLICKEY(key, paramSet, keyOut, ret, func)  \
    TargetBlob keyCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob keyOutCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(keyOut, &keyOutCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(keyOut, &keyOutCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&keyOutCore, keyOut)

#define HDI_CONVERTER_FUNC_INIT(key, paramSet, handle, token, ret, func)  \
    TargetBlob keyCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob handleCore = {0};  \
    TargetBlob tokenCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(handle, &handleCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(token, &tokenCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(handle, &handleCore),  \
                 HDI_ADAPTER_PARAM(token, &tokenCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&handleCore, handle)  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&tokenCore, token)

#define HDI_CONVERTER_FUNC_UPDATE(handle, paramSet, inData, outData, ret, func)  \
    TargetBlob handleCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob inDataCore = {0};  \
    TargetBlob outDataCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(handle, &handleCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(inData, &inDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(outData, &outDataCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(handle, &handleCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(inData, &inDataCore),  \
                 HDI_ADAPTER_PARAM(outData, &outDataCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&outDataCore, outData)

#define HDI_CONVERTER_FUNC_FINISH(handle, paramSet, inData, outData, ret, func)  \
    TargetBlob handleCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob inDataCore = {0};  \
    TargetBlob outDataCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(handle, &handleCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(inData, &inDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(outData, &outDataCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(handle, &handleCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(inData, &inDataCore),  \
                 HDI_ADAPTER_PARAM(outData, &outDataCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&outDataCore, outData)

#define HDI_CONVERTER_FUNC_ABORT(handle, paramSet, ret, func)  \
    TargetBlob handleCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    HDI_CONVERTER_PARAM_IN_BLOB(handle, &handleCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(handle, &handleCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore));

#define HDI_CONVERTER_FUNC_CHECKKEYVALIDITY(paramSet, key, ret, func)  \
    TargetBlob keyCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(key, &keyCore));

#define HDI_CONVERTER_FUNC_ATTESTKEY(key, paramSet, certChain, ret, func)  \
    TargetBlob keyCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob certChainCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(certChain, &certChainCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(certChain, &certChainCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&certChainCore, certChain)

#define HDI_CONVERTER_FUNC_GENERATERANDOM(paramSet, random, ret, func)  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob randomCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(random, &randomCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(random, &randomCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&randomCore, random)

#define HDI_CONVERTER_FUNC_GETERRORINFO(errorInfo, ret, func)  \
    TargetBlob errorInfoCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB((errorInfo), &errorInfoCore)  \
    (ret) = (func)(HDI_ADAPTER_PARAM((errorInfo), &errorInfoCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&errorInfoCore, errorInfo)

#define HDI_CONVERTER_FUNC_GETSTATINFO(statInfo, ret, func)  \
    TargetBlob statInfoCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB((statInfo), &statInfoCore)  \
    (ret) = (func)(HDI_ADAPTER_PARAM((statInfo), &statInfoCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&statInfoCore, statInfo)

#define HDI_CONVERTER_FUNC_SIGN(key, paramSet, srcData, signature, ret, func) \
    TargetBlob keyCore = {0}; \
    TargetParamSet *paramSetCore = NULL; \
    TargetBlob srcDataCore = {0}; \
    TargetBlob signatureCore = {0}; \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore) \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore) \
    HDI_CONVERTER_PARAM_IN_BLOB(srcData, &srcDataCore) \
    HDI_CONVERTER_PARAM_IN_BLOB(signature, &signatureCore) \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore), \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore), \
                 HDI_ADAPTER_PARAM(srcData, &srcDataCore), \
                 HDI_ADAPTER_PARAM(signature, &signatureCore)); \
    HDI_CONVERTER_PARAM_OUT_BLOB(&signatureCore, signature)

#define HDI_CONVERTER_FUNC_VERIFY(key, paramSet, srcData, signature, ret, func)  \
    TargetBlob keyCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob srcDataCore = {0};  \
    TargetBlob signatureCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(srcData, &srcDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(signature, &signatureCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(srcData, &srcDataCore),  \
                 HDI_ADAPTER_PARAM(signature, &signatureCore));
    
#define HDI_CONVERTER_FUNC_ENCRYPT(key, paramSet, plainText, cipherText, ret, func)  \
    TargetBlob keyCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob plainTextCore = {0};  \
    TargetBlob cipherTextCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(plainText, &plainTextCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(cipherText, &cipherTextCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(plainText, &plainTextCore),  \
                 HDI_ADAPTER_PARAM(cipherText, &cipherTextCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&cipherTextCore, cipherText)

#define HDI_CONVERTER_FUNC_DECRYPT(key, paramSet, cipherText, plainText, ret, func)  \
    TargetBlob keyCore = {0};  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob cipherTextCore = {0};  \
    TargetBlob plainTextCore = {0};  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(cipherText, &cipherTextCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(plainText, &plainTextCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(cipherText, &cipherTextCore),  \
                 HDI_ADAPTER_PARAM(plainText, &plainTextCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&plainTextCore, plainText)

#define HDI_CONVERTER_FUNC_AGREEKEY(paramSet, privateKey, peerPublicKey, agreedKey, ret, func)  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob privateKeyCore = {0};  \
    TargetBlob peerPublicKeyCore = {0};  \
    TargetBlob agreedKeyCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(privateKey, &privateKeyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(peerPublicKey, &peerPublicKeyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(agreedKey, &agreedKeyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(privateKey, &privateKeyCore),  \
                 HDI_ADAPTER_PARAM(peerPublicKey, &peerPublicKeyCore),  \
                 HDI_ADAPTER_PARAM(agreedKey, &agreedKeyCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&agreedKeyCore, agreedKey)


#define HDI_CONVERTER_FUNC_DERIVEKEY(paramSet, kdfKey, derivedKey, ret, func)  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob kdfKeyCore = {0};  \
    TargetBlob derivedKeyCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(kdfKey, &kdfKeyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(derivedKey, &derivedKeyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(kdfKey, &kdfKeyCore),  \
                 HDI_ADAPTER_PARAM(derivedKey, &derivedKeyCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&derivedKeyCore, derivedKey)

#define HDI_CONVERTER_FUNC_MAC(key, paramSet, srcData, mac, ret, func)  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob keyCore = {0};  \
    TargetBlob srcDataCore = {0};  \
    TargetBlob macCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(key, &keyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(srcData, &srcDataCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(mac, &macCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(key, &keyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(srcData, &srcDataCore),  \
                 HDI_ADAPTER_PARAM(mac, &macCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&macCore, mac)

#define HDI_CONVERTER_FUNC_UPGRADEKEY(oldKey, paramSet, newKey, ret, func)  \
    TargetParamSet *paramSetCore = NULL;  \
    TargetBlob oldKeyCore = {0};  \
    TargetBlob newKeyCore = {0};  \
    HDI_CONVERTER_PARAM_IN_PARAMSET(paramSet, paramSetCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(oldKey, &oldKeyCore)  \
    HDI_CONVERTER_PARAM_IN_BLOB(newKey, &newKeyCore)  \
    ret = (func)(HDI_ADAPTER_PARAM(oldKey, &oldKeyCore),  \
                 HDI_ADAPTER_PARAM(paramSet, paramSetCore),  \
                 HDI_ADAPTER_PARAM(newKey, &newKeyCore));  \
    HDI_CONVERTER_PARAM_OUT_BLOB(&newKeyCore, newKey)

#undef HUKS_NULL_POINTER

#ifdef __cplusplus
#define HUKS_NULL_POINTER nullptr
#else
#define HUKS_NULL_POINTER NULL
#endif

#define HUKS_HDI_IF_NOT_SUCC_RETURN(RESULT, ERROR_CODE) \
if ((RESULT) != HUKS_SUCCESS) { \
    return (ERROR_CODE); \
}

#define HUKS_HDI_IF_NULL_LOGE_RETURN(OBJECT, ERROR_CODE, LOG_MESSAGE, ...) \
if ((OBJECT) == HUKS_NULL_POINTER) { \
    HDF_LOGE(LOG_MESSAGE, ##__VA_ARGS__); \
    return (ERROR_CODE); \
}

#endif
