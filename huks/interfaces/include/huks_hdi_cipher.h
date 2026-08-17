/*
 * Copyright (c) 2026 HiSilicon (Shanghai) Technologies Co., Ltd.
 *
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

#ifndef HUKS_HDI_CIPHER_H
#define HUKS_HDI_CIPHER_H

#include <stdint.h>
#include <stdbool.h>
#include "hks_type.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define HKS_ERROR_BAD_STATE ((int32_t)-137)
#define HKS_SUCCESS ((int32_t)0)

/**
 * @brief Implemented a symmetric encryption/decryption feature to encrypt or decrypt data
 *
 * @param mainKey Indicates the pointer to Encrypted/Decrypted input data.
 * @param keyMaterial Indicates the pointer to Raw material for deriving cryptographic keys.
 * @param isEncrypt isEncrypt.
 * @param derivedKey Indicates the pointer to Store derived keys or encryption/decryption results.
 *
 * @return Returns <b>0</b> if the operation is successful; returns an error code
 * otherwise.
 */
int32_t HksCipherEncryptAndDecrypt(const struct HksBlob *mainKey,
    const struct HksBlob *keyMaterial, bool isEncrypt, struct HksBlob *derivedKey);

/**
 * @brief Generate random numbers and fill them into the specified buffer
 *
 * @param randomData Indicates the pointer to the data to fill.
 *
 * @return Returns <b>0</b> if the operation is successful; returns an error code
 * otherwise.
 */
int32_t HksCipherGenerateRandom(struct HksBlob *randomData);

/**
 * @brief Get device's unique identifier from the device's OTP storage
 *
 * @param dieid Indicates the pointer to dieid to fill.
 * @param dieid dieidLen.
 *
 * @return Returns <b>0</b> if the operation is successful; returns an error code
 * otherwise.
 */
int32_t GetDevDieid(uint8_t *dieid, uint32_t dieidLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif  /* HUKS_HDI_CIPHER_H */