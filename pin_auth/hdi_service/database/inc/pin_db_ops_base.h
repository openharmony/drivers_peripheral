/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef PIN_DB_OPS_BASE_H
#define PIN_DB_OPS_BASE_H

#include <stdint.h>
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define ATTI_BRUTE_FIRST_STAGE 100
#define ATTI_BRUTE_SECOND_STAGE 140

#define MAX_CRYPTO_INFO_SIZE 33
#define ANTI_BRUTE_SUFFIX "_BruteForceCount"
#define MAX_FILE_NAME_LEN 256
#define DEFAULT_FILE_HEAD "/data/service/el1/public/pinauth/"
#define PIN_INDEX_NAME "/data/service/el1/public/pinauth/PinIndexDb"
#define ROOTSECRET_CRYPTO_SUFFIX "_rootSecret_cryptoInfo"

ResultCode GetDataFromBuf(uint8_t **src, uint32_t *srcLen, uint8_t *dest, uint32_t destLen);
ResultCode GetBufFromData(uint8_t *src, uint32_t srcLen, uint8_t **dest, uint32_t *destLen);
ResultCode GenerateFileName(uint64_t templateId, const char *prefix, const char *suffix,
    char *fileName, uint32_t fileNameLen);
ResultCode ReadPinFile(uint8_t *data, uint32_t dataLen, uint64_t templateId, const char *suffix);
ResultCode WritePinFile(const uint8_t *data, uint32_t dataLen, uint64_t templateId, const char *suffix);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif  // PIN_DB_OPS_BASE_H