/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef PIN_DB_H
#define PIN_DB_H

#include "defines.h"
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define INVALID_TEMPLATE_ID 0xFFFFFFFFFFFFFFFF
#define INIT_AUTH_ERROR_COUNT 0
#define INIT_START_FREEZE_TIMES 0
#define CONST_PIN_DATA_LEN 64U
#define CONST_SALT_LEN 32U
#define RESULT_TLV_LEN 2048U

typedef struct {
    uint64_t scheduleId;
    uint64_t subType;
    uint8_t salt[CONST_SALT_LEN];
    uint8_t pinData[CONST_PIN_DATA_LEN];
} __attribute__((__packed__)) PinEnrollParam;

typedef struct {
    uint64_t oldTemplateId;
    uint64_t curTemplateId;
    uint64_t newTemplateId;
    Buffer *newRootSecret;
} __attribute__((__packed__)) AbandonCacheParam;

bool LoadPinDb(void);
void DestroyPinDb(void);

ResultCode AddPin(PinEnrollParam *pinEnrollParam, uint64_t *templateId, Buffer *outRootSecret);
ResultCode DoGetAlgoParameter(uint64_t templateId, uint8_t *salt, uint32_t *saltLen, uint32_t *algoVersion);
ResultCode DoGenerateAlgoParameter(uint8_t *algoParameter, uint32_t *algoParameterLength, uint32_t *algoVersion,
    uint8_t *localDeviceId, uint32_t deviceUuidLength);
ResultCode DelPinById(uint64_t templateId);
ResultCode AuthPinById(const Buffer *inputPinData, uint64_t templateId, Buffer *outRootSecret, ResultCode *compareRet);
ResultCode ComputeFreezeTime(uint64_t templateId, uint32_t *freezeTime, uint32_t count, uint64_t startFreezeTime);
ResultCode GetRemainTimes(uint64_t templateId, uint32_t *remainingAuthTimes, uint32_t authErrorCount);
ResultCode GetSubType(uint64_t templateId, uint64_t *subType);
ResultCode GetAntiBruteInfo(uint64_t templateId, uint32_t *authErrorCount, uint64_t *startFreezeTime);
ResultCode RefreshAntiBruteInfoToFile(uint64_t templateId);
ResultCode VerifyTemplateDataPin(const uint64_t *templateIdList, uint32_t templateIdListLen);
int32_t GetNextFailLockoutDuration(uint32_t authErrorCount);
Buffer *GetRootSecretPlainInfo(Buffer *oldRootSecret, const Buffer *cipherInfo);
Buffer *GenerateDecodeRootSecret(uint64_t templateId, Buffer *oldRootSecret);
ResultCode Abandon(uint64_t oldTemplateId, uint64_t newTemplateId, Buffer *oldRootSecret, Buffer *newRootSecret);
void DestroyAbandonParam();
ResultCode WriteRootSecretFile(uint64_t templateId, uint64_t newTemplateId, Buffer *ciperInfo);
ResultCode ReadRootSecretFile(uint64_t templateId, uint64_t *newTemplateId, Buffer **ciperInfo);
ResultCode ReWriteRootSecretFile(uint64_t templateId);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif  // PIN_DB_H