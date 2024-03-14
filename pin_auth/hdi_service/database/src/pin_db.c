/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "pin_db.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "defines.h"
#include "file_operator.h"
#include "pin_db_ops.h"

#define MAX_RANDOM_TIME 10
#define CRYPTO_SUFFIX "_CryptoInfo"
#define SALT_SUFFIX "_salt"
#define SECRET_SUFFIX "_secret"
#define SALT_PREFIX "hkdf_salt"
#define CREDENTIAL_PREFIX "template_encryption_key"
#define DEFAULT_VALUE 1
#define REMAINING_TIMES_FREEZE 1
#define FIRST_ANTI_BRUTE_COUNT 5
#define SECOND_ANTI_BRUTE_COUNT 8
#define THIRD_ANTI_BRUTE_COUNT 11
#define ANTI_BRUTE_COUNT_FREQUENCY 3
#define ATTI_BRUTE_FIRST_STAGE 100
#define ATTI_BRUTE_SECOND_STAGE 140
#define ONE_MIN_TIME 60
#define TEN_MIN_TIME 600
#define THIRTY_MIN_TIME 1800
#define ONE_HOUR_TIME 3600
#define ONE_DAY_TIME 86400
#define FIRST_EXPONENTIAL_PARA 30
#define SECOND_EXPONENTIAL_PARA 2
#define THIRD_EXPONENTIAL_PARA 10
#define MS_OF_S 1000uLL
#define CONST_PIN_DATA_EXPAND_LEN 92U
#define CONST_CREDENTIAL_PREFIX_LEN 32U
#define CONST_EXPAND_DATA_LEN 128U
#define SOURCE_DATA_LENGTH 97
#define DEVICE_UUID_LENGTH 65
#define SALT_RANDOM_LENGTH 32

static PinDbV1 *g_pinDbOp = NULL;

bool LoadPinDb(void)
{
    if (g_pinDbOp != NULL) {
        return true;
    }
    g_pinDbOp = ReadPinDb();
    if (g_pinDbOp == NULL) {
        LOG_ERROR("ReadPinDb fail.");
        return false;
    }

    LOG_INFO("LoadPinDb succ.");
    return true;
}

void DestroyPinDb(void)
{
    if (g_pinDbOp == NULL) {
        LOG_INFO("g_pinDbOp is null.");
        return;
    }

    FreePinDb(&g_pinDbOp);
    LOG_INFO("DestroyPinDb succ.");
}

/* This is for example only, Should be implemented in trusted environment. */
static ResultCode WritePinFile(const uint8_t *data, uint32_t dataLen, uint64_t templateId, const char *suffix)
{
    FileOperator *fileOp = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOp)) {
        LOG_ERROR("fileOp invalid.");
        return RESULT_GENERAL_ERROR;
    }

    char fileName[MAX_FILE_NAME_LEN] = {'\0'};
    ResultCode ret = GenerateFileName(templateId, DEFAULT_FILE_HEAD, suffix, fileName, MAX_FILE_NAME_LEN);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinFile Generate Pin FileName fail.");
        return RESULT_GENERAL_ERROR;
    }
    ret = (ResultCode)fileOp->writeFile(fileName, data, dataLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinFile fail.");
        return ret;
    }
    LOG_INFO("WritePinFile succ.");

    return RESULT_SUCCESS;
}

static ResultCode CoverData(const char *fileName, const FileOperator *fileOp)
{
    uint32_t fileLen = 0;
    ResultCode ret = (ResultCode)fileOp->getFileLen(fileName, &fileLen);
    /* The maximum length of the fileName is CONST_PIN_DATA_EXPAND_LEN */
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("getFileLen fail.");
        return ret;
    }
    if (fileLen > CONST_PIN_DATA_EXPAND_LEN) {
        LOG_ERROR("Filelen is larger than pin data expand len");
        return RESULT_GENERAL_ERROR;
    }
    uint8_t *data = Malloc(fileLen);
    if (data == NULL) {
        LOG_ERROR("no memory.");
        return RESULT_NO_MEMORY;
    }
    (void)memset_s(data, fileLen, 0, fileLen);
    ret = (ResultCode)fileOp->writeFile(fileName, data, fileLen);
    Free(data);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinFile fail.");
        return ret;
    }

    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
static ResultCode RemovePinFile(const uint64_t templateId, const char *suffix, bool needCover)
{
    FileOperator *fileOp = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOp)) {
        LOG_ERROR("fileOp invalid.");
        return RESULT_GENERAL_ERROR;
    }
    char fileName[MAX_FILE_NAME_LEN] = {'\0'};
    ResultCode ret = GenerateFileName(templateId, DEFAULT_FILE_HEAD, suffix, fileName, MAX_FILE_NAME_LEN);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GenerateCryptoFileName fail.");
        return RESULT_UNKNOWN;
    }

    /* Write data zeros before deleting data, In addition to anti-brute-force cracking */
    if (needCover) {
        ret = CoverData(fileName, fileOp);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("cover data fail.");
            return RESULT_GENERAL_ERROR;
        }
    }
    if ((ResultCode)fileOp->deleteFile(fileName) != RESULT_SUCCESS) {
        LOG_ERROR("file remove fail.");
        return RESULT_BAD_DEL;
    }

    LOG_INFO("RemovePinFile succ.");
    return ret;
}

static ResultCode RemoveAllFile(uint64_t templateId)
{
    /* This is for example only, Anti-brute-force cracking files must have an anti-rollback zone */
    ResultCode ret = RemovePinFile(templateId, ANTI_BRUTE_SUFFIX, false);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("RemovePinAntiBrute fail.");
    }
    ret = RemovePinFile(templateId, CRYPTO_SUFFIX, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("RemovePinCrypto fail.");
        return ret;
    }
    ret = RemovePinFile(templateId, SALT_SUFFIX, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("RemovePinSalt fail.");
    }
    ret = RemovePinFile(templateId, SECRET_SUFFIX, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("RemovePinSecret fail.");
    }

    LOG_INFO("RemoveAllFile succ.");
    return RESULT_SUCCESS;
}

static uint64_t GeneratePinTemplateId(void)
{
    for (uint32_t i = 0; i < MAX_RANDOM_TIME; i++) {
        uint64_t templateId = INVALID_TEMPLATE_ID;
        SecureRandom((uint8_t *)&templateId, sizeof(templateId));
        if (templateId == INVALID_TEMPLATE_ID) {
            continue;
        }
        uint32_t j = 0;
        for (; j < g_pinDbOp->pinIndexLen; j++) {
            if (templateId == g_pinDbOp->pinIndex[i].pinInfo.templateId) {
                break;
            }
        }
        if (j == g_pinDbOp->pinIndexLen) {
            return templateId;
        }
    }
    LOG_ERROR("fail generate pin templateid.");
    return INVALID_TEMPLATE_ID;
}

static uint32_t SearchPinById(uint64_t templateId)
{
    if (g_pinDbOp->pinIndexLen == 0) {
        LOG_ERROR("no pin exist.");
        return MAX_CRYPTO_INFO_SIZE;
    }
    for (uint32_t index = 0; index < g_pinDbOp->pinIndexLen; index++) {
        if (g_pinDbOp->pinIndex[index].pinInfo.templateId == templateId) {
            LOG_INFO("SearchPinById succ.");
            return index;
        }
    }
    LOG_ERROR("no pin match.");
    return MAX_CRYPTO_INFO_SIZE;
}

static ResultCode DelPin(uint32_t index)
{
    /* This is for example only, Should be implemented in trusted environment. */
    ResultCode ret = RemoveAllFile(g_pinDbOp->pinIndex[index].pinInfo.templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("Remove pin file fail.");
        return ret;
    }

    LOG_INFO("DelPin succ.");
    return RESULT_SUCCESS;
}

static ResultCode DelPinInDb(uint32_t index)
{
    uint32_t pinIndexLen = g_pinDbOp->pinIndexLen - 1;
    if (pinIndexLen == 0) {
        (void)memset_s(g_pinDbOp->pinIndex,
            g_pinDbOp->pinIndexLen * sizeof(PinIndexV1), 0, g_pinDbOp->pinIndexLen * sizeof(PinIndexV1));
        Free(g_pinDbOp->pinIndex);
        g_pinDbOp->pinIndex = NULL;
    } else {
        uint32_t size = pinIndexLen * sizeof(PinIndexV1);
        PinIndexV1 *pinIndex = (PinIndexV1 *)Malloc(size);
        if (pinIndex == NULL) {
            LOG_ERROR("PinIndexV1 malloc fail.");
            return RESULT_NO_MEMORY;
        }
        (void)memset_s(pinIndex, size, 0, size);
        for (uint32_t i = 0, j = 0; i < g_pinDbOp->pinIndexLen; i++) {
            if (i != index) {
                pinIndex[j] = g_pinDbOp->pinIndex[i];
                j++;
            }
        }
        (void)memset_s(g_pinDbOp->pinIndex,
            g_pinDbOp->pinIndexLen * sizeof(PinIndexV1), 0, g_pinDbOp->pinIndexLen * sizeof(PinIndexV1));
        Free(g_pinDbOp->pinIndex);
        g_pinDbOp->pinIndex = pinIndex;
    }
    LOG_INFO("%{public}u left after del.", pinIndexLen);
    g_pinDbOp->pinIndexLen = pinIndexLen;
    ResultCode ret = WritePinDb(g_pinDbOp);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinDb fail.");
    }

    LOG_INFO("DelPinInDb succ.");
    return ret;
}

ResultCode DelPinById(uint64_t templateId)
{
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }
    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin match.");
        return RESULT_BAD_MATCH;
    }

    ResultCode ret = DelPin(index);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR(" DelPin fail.");
        return ret;
    }
    ret = DelPinInDb(index);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("DelPinInDb fail.");
        return ret;
    }
    LOG_INFO("DelPinById succ.");
    /* ignore index file remove result, return success when crypto file remove success */
    return ret;
}

static void InitPinInfo(PinInfoV1 *pinInfo, uint64_t templateId, uint64_t subType)
{
    pinInfo->templateId = templateId;
    pinInfo->subType = subType;
    pinInfo->algoVersion = ALGORITHM_VERSION_0;
}

static void InitAntiBruteInfo(AntiBruteInfoV0 *info)
{
    info->authErrorCount = INIT_AUTH_ERROR_COUNT;
    info->startFreezeTime = INIT_START_FREEZE_TIMES;
}

static void InitPinIndex(PinIndexV1 *pinIndex, uint64_t templateId, uint64_t subType)
{
    InitPinInfo(&(pinIndex->pinInfo), templateId, subType);
    InitAntiBruteInfo(&(pinIndex->antiBruteInfo));
}

static ResultCode AddPinInDb(uint64_t templateId, uint64_t subType)
{
    if (g_pinDbOp->pinIndexLen > MAX_CRYPTO_INFO_SIZE - 1) {
        LOG_ERROR("pinIndexLen too large.");
        return RESULT_BAD_PARAM;
    }
    uint32_t size = (g_pinDbOp->pinIndexLen + 1) * sizeof(PinIndexV1);
    PinIndexV1 *pinIndex = (PinIndexV1 *)Malloc(size);
    if (pinIndex == NULL) {
        LOG_ERROR("PinIndexV1 malloc fail.");
        return RESULT_NO_MEMORY;
    }
    (void)memset_s(pinIndex, size, 0, size);
    if (g_pinDbOp->pinIndexLen != 0) {
        if (memcpy_s(pinIndex, size,
            g_pinDbOp->pinIndex, g_pinDbOp->pinIndexLen * sizeof(PinIndexV1)) != EOK) {
            LOG_ERROR("PinIndexV1 copy fail.");
            (void)memset_s(pinIndex, size, 0, size);
            Free(pinIndex);
            return RESULT_NO_MEMORY;
        }
    }
    InitPinIndex(&pinIndex[g_pinDbOp->pinIndexLen], templateId, subType);
    if (g_pinDbOp->pinIndex != NULL) {
        Free(g_pinDbOp->pinIndex);
    }
    g_pinDbOp->pinIndex = pinIndex;
    g_pinDbOp->pinIndexLen++;
    ResultCode ret = WritePinDb(g_pinDbOp);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinDb fail.");
        return ret;
    }

    LOG_INFO("AddPinInDb succ.");
    return RESULT_SUCCESS;
}

static ResultCode RefreshPinDb(uint64_t *templateId, uint64_t subType)
{
    *templateId = GeneratePinTemplateId();
    if (*templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("GeneratePinTemplateId fail.");
        return RESULT_UNKNOWN;
    }
    ResultCode ret = AddPinInDb(*templateId, subType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("AddPinDb fail.");
        return ret;
    }

    LOG_INFO("RefreshPinDb succ.");
    return RESULT_SUCCESS;
}

static ResultCode WriteAddPinInfo(const Buffer *secret, const Buffer *pinCredentialData, uint8_t *salt,
    uint32_t saltLen, const uint64_t templateId)
{
    ResultCode ret = WritePinFile(pinCredentialData->buf, pinCredentialData->contentSize, templateId, CRYPTO_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WriteCryptoFile fail.");
        return ret;
    }

    ret = WritePinFile(salt, saltLen, templateId, SALT_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WriteSaltFile fail.");
        return ret;
    }

    ret = WritePinFile(secret->buf, secret->contentSize, templateId, SECRET_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WriteSecretFile fail.");
        return ret;
    }
    AntiBruteInfoV0 initAntiBrute = {};
    InitAntiBruteInfo(&initAntiBrute);
    ret = WritePinFile((uint8_t *)&initAntiBrute, sizeof(AntiBruteInfoV0), templateId, ANTI_BRUTE_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WriteAntiBruteFile fail.");
        return ret;
    }

    LOG_INFO("WriteAddPinInfo succ.");
    return RESULT_SUCCESS;
}

static Buffer *GenerateExpandData(char *str, const uint8_t *data, const uint32_t dataLen)
{
    /* CONST_EXPAND_DATA_LEN is twice the size of dataLen */
    if (dataLen < strlen(str) || dataLen != (CONST_EXPAND_DATA_LEN / 2)) {
        LOG_ERROR("bad param.");
        return NULL;
    }
    Buffer *outBuff = CreateBufferBySize(CONST_EXPAND_DATA_LEN);
    if (!IsBufferValid(outBuff)) {
        LOG_ERROR("create buffer fail.");
        return NULL;
    }
    (void)memset_s(outBuff->buf, outBuff->maxSize, 0, outBuff->maxSize);
    outBuff->contentSize = outBuff->maxSize;
    uint8_t *temp = outBuff->buf;
    if (memcpy_s(temp, outBuff->maxSize, (uint8_t *)str, strlen(str)) != EOK) {
        LOG_ERROR("copy str fail.");
        DestoryBuffer(outBuff);
        return NULL;
    }

    temp += dataLen;
    if (memcpy_s(temp, outBuff->maxSize - dataLen, data, dataLen) != EOK) {
        LOG_ERROR("copy data fail.");
        DestoryBuffer(outBuff);
        return NULL;
    }

    return outBuff;
}

static ResultCode GenerateRootSecret(const Buffer *deviceKey, const Buffer *pinData, Buffer *outRootSecret)
{
    Buffer *expandData = GenerateExpandData(SALT_PREFIX, pinData->buf, pinData->contentSize);
    if (!IsBufferValid(expandData)) {
        LOG_ERROR("generate expand data fail.");
        return RESULT_GENERAL_ERROR;
    }

    Buffer *hkdfSalt = Sha256Adaptor(expandData);
    if (!IsBufferValid(hkdfSalt)) {
        LOG_ERROR("generate sha256 fail.");
        DestoryBuffer(expandData);
        return RESULT_GENERAL_ERROR;
    }
    Buffer *rootSecret = Hkdf(hkdfSalt, deviceKey);
    DestoryBuffer(expandData);
    DestoryBuffer(hkdfSalt);
    if (!IsBufferValid(rootSecret)) {
        LOG_ERROR("generate rootSecret fail.");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(outRootSecret->buf, outRootSecret->maxSize, rootSecret->buf, rootSecret->contentSize) != EOK) {
        LOG_ERROR("copy root secret fail.");
        DestoryBuffer(rootSecret);
        return RESULT_BAD_COPY;
    }

    outRootSecret->contentSize = rootSecret->contentSize;
    DestoryBuffer(rootSecret);
    return RESULT_SUCCESS;
}

static Buffer *GenerateEncryptionKey(const Buffer *deviceKey)
{
    Buffer *keyStrBuffer = CreateBufferBySize(CONST_CREDENTIAL_PREFIX_LEN);
    if (!IsBufferValid(keyStrBuffer)) {
        LOG_ERROR("generate expand data fail.");
        return NULL;
    }
    (void)memset_s(keyStrBuffer->buf, keyStrBuffer->maxSize, 0, keyStrBuffer->maxSize);
    if (memcpy_s(keyStrBuffer->buf, keyStrBuffer->maxSize,
        (uint8_t *)CREDENTIAL_PREFIX, strlen(CREDENTIAL_PREFIX)) != EOK) {
        LOG_ERROR("copy CREDENTIAL_PREFIX fail.");
        DestoryBuffer(keyStrBuffer);
        return NULL;
    }
    keyStrBuffer->contentSize = keyStrBuffer->maxSize;
    Buffer *encryptionKey = Hkdf(keyStrBuffer, deviceKey);
    DestoryBuffer(keyStrBuffer);
    if (!IsBufferValid(encryptionKey)) {
        LOG_ERROR("generate encryptionKey fail.");
        return NULL;
    }

    return encryptionKey;
}

static ResultCode ProcessAddPin(const Buffer *deviceKey, const Buffer *secret, PinEnrollParam *pinEnrollParam,
    uint64_t templateId)
{
    Buffer *encryptionKey = GenerateEncryptionKey(deviceKey);
    if (!IsBufferValid(encryptionKey)) {
        LOG_ERROR("generate encryptionKey fail.");
        return RESULT_GENERAL_ERROR;
    }
    Buffer *pinDataBuffer = CreateBufferByData(pinEnrollParam->pinData, CONST_PIN_DATA_LEN);
    if (!IsBufferValid(pinDataBuffer)) {
        LOG_ERROR("generate pinDataBuffer fail.");
        DestoryBuffer(encryptionKey);
        return RESULT_GENERAL_ERROR;
    }
    Buffer *pinCredCiphertext = Aes256GcmEncryptNoPadding(pinDataBuffer, encryptionKey);
    if (!IsBufferValid(pinCredCiphertext)) {
        LOG_ERROR("generate pinCredCiphertext fail.");
        DestoryBuffer(encryptionKey);
        DestoryBuffer(pinDataBuffer);
        return RESULT_GENERAL_ERROR;
    }

    ResultCode ret = WriteAddPinInfo(secret, pinCredCiphertext, pinEnrollParam->salt, CONST_SALT_LEN, templateId);
    DestoryBuffer(encryptionKey);
    DestoryBuffer(pinDataBuffer);
    DestoryBuffer(pinCredCiphertext);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("write add pin info fail.");
    }

    return ret;
}

static Buffer *CreateSecretBuffer()
{
    Buffer *secret = CreateBufferBySize(SECRET_SIZE);
    if (!IsBufferValid(secret)) {
        LOG_ERROR("generate buffer fail.");
        return secret;
    }
    if (SecureRandom(secret->buf, secret->maxSize) != RESULT_SUCCESS) {
        LOG_ERROR("generate secure random number fail.");
        DestoryBuffer(secret);
        return NULL;
    }
    secret->contentSize = secret->maxSize;
    return secret;
}

/* This is for example only, Should be implemented in trusted environment. */
ResultCode AddPin(PinEnrollParam *pinEnrollParam, uint64_t *templateId, Buffer *outRootSecret)
{
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }
    if (pinEnrollParam == NULL || templateId == NULL || !IsBufferValid(outRootSecret)) {
        LOG_ERROR("get invalid params.");
        return RESULT_BAD_PARAM;
    }
    ResultCode ret = RefreshPinDb(templateId, pinEnrollParam->subType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("refresh pinDb fail.");
        return ret;
    }
    Buffer *pinCredData = CreateBufferByData(pinEnrollParam->pinData, CONST_PIN_DATA_LEN);
    Buffer *secret = CreateSecretBuffer();
    Buffer *deviceKey = NULL;
    if (!IsBufferValid(pinCredData) || !IsBufferValid(secret)) {
        LOG_ERROR("generate buffer fail.");
        ret = RESULT_NO_MEMORY;
        goto ERROR;
    }
    deviceKey = DeriveDeviceKey(pinCredData, secret);
    if (!IsBufferValid(deviceKey)) {
        LOG_ERROR("generate deviceKey fail.");
        ret = RESULT_GENERAL_ERROR;
        goto ERROR;
    }
    ret = GenerateRootSecret(deviceKey, pinCredData, outRootSecret);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("generate rootSecret fail.");
        goto ERROR;
    }
    ret = ProcessAddPin(deviceKey, secret, pinEnrollParam, *templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("process add pin fail.");
        goto ERROR;
    }
    LOG_INFO("AddPin succ.");

ERROR:
    DestoryBuffer(deviceKey);
    DestoryBuffer(secret);
    DestoryBuffer(pinCredData);
    return ret;
}

ResultCode DoGetAlgoParameter(uint64_t templateId, uint8_t *salt, uint32_t *saltLen, uint32_t *algoVersion)
{
    if (salt == NULL || saltLen == NULL || templateId == INVALID_TEMPLATE_ID || algoVersion == NULL) {
        LOG_ERROR("get invalid algorithm params.");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }

    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin match.");
        return RESULT_BAD_MATCH;
    }

    ResultCode ret = ReadPinFile(salt, *saltLen, templateId, SALT_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("salt file read fail.");
        return ret;
    }

    *algoVersion = g_pinDbOp->pinIndex[index].pinInfo.algoVersion;
    LOG_INFO("DoGetAlgoParameter succ.");
    return RESULT_SUCCESS;
}

static ResultCode GetAntiBruteCountById(uint64_t templateId, uint32_t *count)
{
    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin index match.");
        return RESULT_BAD_MATCH;
    }
    *count = g_pinDbOp->pinIndex[index].antiBruteInfo.authErrorCount;
    return RESULT_SUCCESS;
}

ResultCode RefreshAntiBruteInfoToFile(uint64_t templateId)
{
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }
    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR(" no pin match.");
        return RESULT_BAD_MATCH;
    }
    ResultCode ret = WritePinFile((uint8_t *)(&(g_pinDbOp->pinIndex[index].antiBruteInfo)), sizeof(AntiBruteInfoV0),
        templateId, ANTI_BRUTE_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("write anti brute fail.");
    }

    return ret;
}

static ResultCode SetAntiBruteInfoById(uint64_t templateId, uint32_t count, uint64_t startFreezeTime)
{
    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR(" no pin match.");
        return RESULT_BAD_MATCH;
    }
    g_pinDbOp->pinIndex[index].antiBruteInfo.authErrorCount = count;
    g_pinDbOp->pinIndex[index].antiBruteInfo.startFreezeTime = startFreezeTime;
    ResultCode ret = WritePinFile((uint8_t *)(&(g_pinDbOp->pinIndex[index].antiBruteInfo)), sizeof(AntiBruteInfoV0),
        templateId, ANTI_BRUTE_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("write anti brute fail.");
        return ret;
    }
    return ret;
}

ResultCode GetSubType(uint64_t templateId, uint64_t *subType)
{
    if (templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }

    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin match.");
        return RESULT_BAD_MATCH;
    }
    *subType = g_pinDbOp->pinIndex[index].pinInfo.subType;

    LOG_INFO("GetSubType succ.");
    return RESULT_SUCCESS;
}

ResultCode GetAntiBruteInfo(uint64_t templateId, uint32_t *authErrorCount, uint64_t *startFreezeTime)
{
    if (authErrorCount == NULL || startFreezeTime == NULL || templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("check GetAntiBruteInfo param fail!");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }

    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin match.");
        return RESULT_BAD_MATCH;
    }
    *authErrorCount = g_pinDbOp->pinIndex[index].antiBruteInfo.authErrorCount;
    *startFreezeTime = g_pinDbOp->pinIndex[index].antiBruteInfo.startFreezeTime;

    LOG_INFO("GetAntiBruteInfo succ.");
    return RESULT_SUCCESS;
}

static uint64_t ExponentialFuncTime(uint32_t authErrorCount)
{
    uint32_t ret = DEFAULT_VALUE;
    uint32_t exp = (authErrorCount - FIRST_EXPONENTIAL_PARA) / THIRD_EXPONENTIAL_PARA;
    for (uint32_t index = 0; index < exp; ++index) {
        ret *= SECOND_EXPONENTIAL_PARA;
    }
    return FIRST_EXPONENTIAL_PARA * ret;
}

static uint64_t GetWaitTime(uint32_t authErrorCount)
{
    if (authErrorCount < FIRST_ANTI_BRUTE_COUNT) {
        return 0;
    }
    if (authErrorCount < ATTI_BRUTE_FIRST_STAGE) {
        if (authErrorCount == FIRST_ANTI_BRUTE_COUNT) {
            return ONE_MIN_TIME * MS_OF_S;
        }
        if (authErrorCount == SECOND_ANTI_BRUTE_COUNT) {
            return TEN_MIN_TIME * MS_OF_S;
        }
        if (authErrorCount == THIRD_ANTI_BRUTE_COUNT) {
            return THIRTY_MIN_TIME * MS_OF_S;
        }
        if (((authErrorCount - FIRST_ANTI_BRUTE_COUNT) % ANTI_BRUTE_COUNT_FREQUENCY) == 0) {
            return ONE_HOUR_TIME * MS_OF_S;
        }
        return 0;
    }
    if (authErrorCount > ATTI_BRUTE_SECOND_STAGE) {
        return ONE_DAY_TIME * MS_OF_S;
    }
    return ExponentialFuncTime(authErrorCount) * MS_OF_S;
}

ResultCode ComputeFreezeTime(uint64_t templateId, uint32_t *freezeTime, uint32_t count, uint64_t startFreezeTime)
{
    if (templateId == INVALID_TEMPLATE_ID || freezeTime == NULL) {
        LOG_ERROR("check ComputeFreezeTime param fail!");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }
    uint64_t timeValue = GetRtcTime();
    uint64_t waitTime = GetWaitTime(count);
    if (timeValue >= startFreezeTime) {
        uint64_t usedTime = timeValue - startFreezeTime;
        if (usedTime >= waitTime) {
            *freezeTime = 0;
        } else {
            *freezeTime = (waitTime - usedTime) & 0xffffffff;
        }
    } else {
        /* rtc time is reset, we should update startFreezeTime to timeValue */
        if (SetAntiBruteInfoById(templateId, count, timeValue) != RESULT_SUCCESS) {
            LOG_ERROR("SetAntiBruteInfoById fail.");
            return RESULT_BAD_PARAM;
        }
        *freezeTime = waitTime & 0xffffffff;
    }

    LOG_INFO("ComputeFreezeTime succ.");
    return RESULT_SUCCESS;
}

static uint32_t ComputeRemainingTimes(uint32_t errorCount)
{
    if (errorCount < FIRST_ANTI_BRUTE_COUNT) {
        return FIRST_ANTI_BRUTE_COUNT - errorCount;
    }
    if (errorCount >= ATTI_BRUTE_FIRST_STAGE) {
        return REMAINING_TIMES_FREEZE;
    }
    return ANTI_BRUTE_COUNT_FREQUENCY - (errorCount - FIRST_ANTI_BRUTE_COUNT) % ANTI_BRUTE_COUNT_FREQUENCY;
}

ResultCode GetRemainTimes(uint64_t templateId, uint32_t *remainingAuthTimes, uint32_t authErrorCount)
{
    if (templateId == INVALID_TEMPLATE_ID || remainingAuthTimes == NULL) {
        LOG_ERROR("check GetRemainTimes param fail!");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }
    *remainingAuthTimes = ComputeRemainingTimes(authErrorCount);
    return RESULT_SUCCESS;
}

static ResultCode ClearAntiBruteInfoById(uint64_t templateId)
{
    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR(" no pin match.");
        return RESULT_BAD_MATCH;
    }
    InitAntiBruteInfo(&(g_pinDbOp->pinIndex[index].antiBruteInfo));
    return RESULT_SUCCESS;
}

static ResultCode UpdateAntiBruteFile(uint64_t templateId, bool authResultSucc)
{
    if (templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("check param fail.");
        return RESULT_BAD_PARAM;
    }

    if (authResultSucc) {
        ResultCode ret = ClearAntiBruteInfoById(templateId);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("ClearAntiBruteInfoById fail.");
        }
        return ret;
    }

    uint64_t nowTime = GetRtcTime();
    uint32_t errorCount = 0;
    ResultCode ret = GetAntiBruteCountById(templateId, &errorCount);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetAntiBruteCountById fail.");
        return ret;
    }
    if (errorCount < ATTI_BRUTE_SECOND_STAGE) {
        errorCount++;
    }
    ret = SetAntiBruteInfoById(templateId, errorCount, nowTime);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SetAntiBruteInfoById fail.");
    }
    return ret;
}

static Buffer *GenerateDecodeCredential(const Buffer *deviceKey, const Buffer *pinData)
{
    Buffer *encryptionKey = GenerateEncryptionKey(deviceKey);
    if (!IsBufferValid(encryptionKey)) {
        LOG_ERROR("generate encryptionKey fail.");
        return NULL;
    }

    Buffer *pinDecodeCredential = Aes256GcmDecryptNoPadding(pinData, encryptionKey);
    DestoryBuffer(encryptionKey);
    if (!IsBufferValid(pinDecodeCredential)) {
        LOG_ERROR("generate pinDeCredCiphertext fail.");
        return NULL;
    }

    return pinDecodeCredential;
}

static ResultCode ProcessAuthPin(const Buffer *storeData, const uint8_t *inputData, const uint32_t inputDataLen,
    uint64_t templateId, Buffer *outRootSecret)
{
    Buffer *pinCredData = CreateBufferByData(inputData, inputDataLen);
    Buffer *secret = CreateBufferBySize(SECRET_SIZE);
    Buffer *deviceKey = NULL;
    Buffer *pinDecodeCredential = NULL;
    ResultCode ret = RESULT_COMPARE_FAIL;
    if (!IsBufferValid(pinCredData) || !IsBufferValid(secret)) {
        LOG_ERROR("create buffer fail.");
        goto EXIT;
    }
    if (ReadPinFile(secret->buf, secret->maxSize, templateId, SECRET_SUFFIX) != RESULT_SUCCESS) {
        LOG_ERROR("read pin secret file fail.");
        goto EXIT;
    }
    secret->contentSize = secret->maxSize;
    deviceKey = DeriveDeviceKey(pinCredData, secret);
    if (!IsBufferValid(deviceKey)) {
        LOG_ERROR("generate deviceKey fail.");
        goto EXIT;
    }
    if (GenerateRootSecret(deviceKey, pinCredData, outRootSecret) != RESULT_SUCCESS) {
        LOG_ERROR("generate rootSecret fail.");
        goto EXIT;
    }
    pinDecodeCredential = GenerateDecodeCredential(deviceKey, storeData);
    if (!CheckBufferWithSize(pinDecodeCredential, inputDataLen)) {
        LOG_ERROR("generate pinDecodeCredential fail.");
        goto EXIT;
    }
    if (memcmp(inputData, pinDecodeCredential->buf, inputDataLen) == 0) {
        LOG_INFO("auth pin success.");
        ret = RESULT_SUCCESS;
        goto EXIT;
    }
    LOG_ERROR("auth pin fail.");

EXIT:
    DestoryBuffer(pinDecodeCredential);
    DestoryBuffer(deviceKey);
    DestoryBuffer(secret);
    DestoryBuffer(pinCredData);
    return ret;
}

/* This is for example only, Should be implemented in trusted environment. */
ResultCode AuthPinById(const uint8_t *inputData, const uint32_t inputDataLen, uint64_t templateId,
    Buffer *outRootSecret, ResultCode *compareRet)
{
    if (inputData == NULL || inputDataLen != CONST_PIN_DATA_LEN || templateId == INVALID_TEMPLATE_ID ||
        !IsBufferValid(outRootSecret) || compareRet == NULL) {
        LOG_ERROR("get invalid params.");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }
    *compareRet = RESULT_COMPARE_FAIL;
    if (SearchPinById(templateId) == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin match.");
        return RESULT_BAD_MATCH;
    }
    /* Update anti-brute-force information with authentication failure first */
    if (UpdateAntiBruteFile(templateId, false) != RESULT_SUCCESS) {
        LOG_ERROR("update antiBrute file fail.");
        return RESULT_GENERAL_ERROR;
    }
    Buffer *storeData = CreateBufferBySize(CONST_PIN_DATA_EXPAND_LEN);
    if (!IsBufferValid(storeData)) {
        LOG_ERROR("generate storeData fail.");
        return RESULT_GENERAL_ERROR;
    }
    ResultCode ret = ReadPinFile(storeData->buf, storeData->maxSize, templateId, CRYPTO_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("read pin store file fail.");
        DestoryBuffer(storeData);
        return RESULT_BAD_READ;
    }
    storeData->contentSize = storeData->maxSize;
    *compareRet = ProcessAuthPin(storeData, inputData, inputDataLen, templateId, outRootSecret);
    if ((*compareRet) == RESULT_SUCCESS) {
        ret = UpdateAntiBruteFile(templateId, true);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("UpdateAntiBruteFile fail.");
            goto EXIT;
        }
    }
    LOG_INFO("AuthPinById end.");

EXIT:
    DestoryBuffer(storeData);
    return ret;
}

static bool FindTemplateIdFromList(uint64_t storeTemplateId, const uint64_t *templateIdList, uint32_t templateIdListLen)
{
    for (uint32_t i = 0; i < templateIdListLen; ++i) {
        if (templateIdList[i] == storeTemplateId) {
            return true;
        }
    }

    return false;
}

ResultCode VerifyTemplateDataPin(const uint64_t *templateIdList, uint32_t templateIdListLen)
{
    if (templateIdListLen != 0 && templateIdList == NULL) {
        LOG_ERROR("templateIdList should be not null, when templateIdListLen is not zero");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }
    uint32_t i = 0;
    for (; i < g_pinDbOp->pinIndexLen; i++) {
        if (FindTemplateIdFromList(g_pinDbOp->pinIndex[i].pinInfo.templateId, templateIdList, templateIdListLen)) {
            continue;
        }
        ResultCode ret = DelPinById(g_pinDbOp->pinIndex[i].pinInfo.templateId);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("delete pin file fail.");
            return RESULT_BAD_DEL;
        }
    }
    LOG_INFO("VerifyTemplateDataPin succ.");
    return RESULT_SUCCESS;
}

static ResultCode GenerateSalt(uint8_t *algoParameter, uint32_t *algoParameterLength,
    uint8_t *localDeviceId, uint32_t deviceUuidLength)
{
    uint8_t sourceDataTemp[SOURCE_DATA_LENGTH] = { 0 };
    if (memcpy_s(sourceDataTemp, SOURCE_DATA_LENGTH, localDeviceId, deviceUuidLength) != EOK) {
        LOG_ERROR("memcpy_s localDeviceId to sourceDataTemp failed");
        return RESULT_GENERAL_ERROR;
    }
    if (SecureRandom(&(sourceDataTemp[deviceUuidLength]), SALT_RANDOM_LENGTH) != RESULT_SUCCESS) {
        LOG_ERROR("Generate random number failed");
        return RESULT_GENERAL_ERROR;
    }
    Buffer sourceData = GetTmpBuffer(sourceDataTemp, SOURCE_DATA_LENGTH, SOURCE_DATA_LENGTH);
    if (!IsBufferValid(&sourceData)) {
        LOG_ERROR("sourceData is invalid");
        return RESULT_GENERAL_ERROR;
    }
    Buffer *resultSha256 = Sha256Adaptor(&sourceData);
    if (!IsBufferValid(resultSha256)) {
        LOG_ERROR("result is invalid");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(algoParameter, *algoParameterLength, resultSha256->buf, resultSha256->contentSize) != EOK) {
        LOG_ERROR("memcpy_s result to algoParameter failed");
        DestoryBuffer(resultSha256);
        return RESULT_GENERAL_ERROR;
    }
    *algoParameterLength = resultSha256->contentSize;

    DestoryBuffer(resultSha256);
    LOG_INFO("GenerateAlgoParameterInner succ");
    return RESULT_SUCCESS;
}

ResultCode DoGenerateAlgoParameter(uint8_t *algoParameter, uint32_t *algoParameterLength, uint32_t *algoVersion,
    uint8_t *localDeviceId, uint32_t deviceUuidLength)
{
    LOG_INFO("start");
    if (algoParameter == NULL || algoParameterLength == NULL || localDeviceId == NULL || algoVersion == NULL ||
        deviceUuidLength != DEVICE_UUID_LENGTH) {
        LOG_ERROR("bad parameter");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }

    if (GenerateSalt(algoParameter, algoParameterLength, localDeviceId, deviceUuidLength) != RESULT_SUCCESS) {
        LOG_ERROR("Generate salt failed");
        return RESULT_GENERAL_ERROR;
    }
    *algoVersion = ALGORITHM_VERSION_0;

    LOG_INFO("gen algo succ size is [%{public}u] and version is [%{public}u]", *algoParameterLength, *algoVersion);
    return RESULT_SUCCESS;
}