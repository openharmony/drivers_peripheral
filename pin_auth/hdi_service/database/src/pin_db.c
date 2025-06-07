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
static AbandonCacheParam *g_abandonCacheParam = NULL;

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
    DestroyAbandonParam();
    LOG_INFO("DestroyPinDb succ.");
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
    }
    ret = RemovePinFile(templateId, SALT_SUFFIX, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("RemovePinSalt fail.");
    }
    ret = RemovePinFile(templateId, SECRET_SUFFIX, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("RemovePinSecret fail.");
    }
    ret = RemovePinFile(templateId, ROOTSECRET_CRYPTO_SUFFIX, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("RemovePinSecret fail.");
    }

    LOG_INFO("RemoveAllFile end.");
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

static ResultCode DelPin(uint64_t templateId)
{
    /* This is for example only, Should be implemented in trusted environment. */
    ResultCode ret = RemoveAllFile(templateId);
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
        return ret;
    }

    LOG_INFO("DelPinInDb succ.");
    return ret;
}

static ResultCode SearchPinIndex(uint64_t templateId, uint32_t *index)
{
    if (!LoadPinDb()) {
        LOG_ERROR("SearchPinIndex load pinDb fail.");
        return RESULT_NEED_INIT;
    }

    if (g_pinDbOp->pinIndexLen == 0) {
        LOG_ERROR("SearchPinIndex no pin exist.");
        return RESULT_BAD_MATCH;
    }
    for (uint32_t i = 0; i < g_pinDbOp->pinIndexLen; i++) {
        if (g_pinDbOp->pinIndex[i].pinInfo.templateId == templateId) {
            LOG_INFO("SearchPinIndex succ.");
            (*index) = i;
            return RESULT_SUCCESS;
        }
    }
    LOG_ERROR("SearchPinIndex no pin match.");
    return RESULT_BAD_MATCH;
}

ResultCode DelPinById(uint64_t templateId)
{
    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
    }

    ret = DelPinInDb(index);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("DelPinInDb fail.");
        return ret;
    }

    ret = DelPin(templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR(" DelPin fail.");
        return ret;
    }

    ret = ReWriteRootSecretFile(templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR(" ReWriteRootSecretFile fail.");
        return ret;
    }
    LOG_INFO("DelPinById succ.");
    /* ignore pin file remove result, return success when index file remove success */
    return RESULT_SUCCESS;
}

static void InitPinInfo(PinInfo *pinInfo, uint64_t templateId, uint64_t subType, uint32_t pinLength)
{
    pinInfo->templateId = templateId;
    pinInfo->subType = subType;
    pinInfo->algoVersion = ALGORITHM_VERSION_0;
    pinInfo->pinLength = pinLength;
}

static void InitAntiBruteInfo(AntiBruteInfoV0 *info)
{
    info->authErrorCount = INIT_AUTH_ERROR_COUNT;
    info->startFreezeTime = INIT_START_FREEZE_TIMES;
}

static void InitPinIndex(PinIndex *pinIndex, uint64_t templateId, uint64_t subType, uint32_t pinLength)
{
    InitPinInfo(&(pinIndex->pinInfo), templateId, subType, pinLength);
    InitAntiBruteInfo(&(pinIndex->antiBruteInfo));
}

static ResultCode AddPinInDb(uint64_t templateId, uint64_t subType, uint32_t pinLength)
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
    InitPinIndex(&pinIndex[g_pinDbOp->pinIndexLen], templateId, subType, pinLength);
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
    ret = WritePinFile((uint8_t *)(&initAntiBrute), sizeof(AntiBruteInfoV0), templateId, ANTI_BRUTE_SUFFIX);
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
    int32_t multiple = 2;
    if (dataLen < strlen(str) || dataLen != (CONST_EXPAND_DATA_LEN / multiple)) {
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
        DestroyBuffer(outBuff);
        return NULL;
    }

    temp += dataLen;
    if (memcpy_s(temp, outBuff->maxSize - dataLen, data, dataLen) != EOK) {
        LOG_ERROR("copy data fail.");
        DestroyBuffer(outBuff);
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
        DestroyBuffer(expandData);
        return RESULT_GENERAL_ERROR;
    }
    Buffer *rootSecret = Hkdf(hkdfSalt, deviceKey);
    DestroyBuffer(expandData);
    DestroyBuffer(hkdfSalt);
    if (!IsBufferValid(rootSecret)) {
        LOG_ERROR("generate rootSecret fail.");
        return RESULT_GENERAL_ERROR;
    }
    if (memcpy_s(outRootSecret->buf, outRootSecret->maxSize, rootSecret->buf, rootSecret->contentSize) != EOK) {
        LOG_ERROR("copy root secret fail.");
        DestroyBuffer(rootSecret);
        return RESULT_BAD_COPY;
    }

    outRootSecret->contentSize = rootSecret->contentSize;
    DestroyBuffer(rootSecret);
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
        DestroyBuffer(keyStrBuffer);
        return NULL;
    }
    keyStrBuffer->contentSize = keyStrBuffer->maxSize;
    Buffer *encryptionKey = Hkdf(keyStrBuffer, deviceKey);
    DestroyBuffer(keyStrBuffer);
    if (!IsBufferValid(encryptionKey)) {
        LOG_ERROR("generate encryptionKey fail.");
        return NULL;
    }

    return encryptionKey;
}

static Buffer *SplicePinCiperInfo(const Buffer *iv, const Buffer *tag, const Buffer *ciphertext)
{
    Buffer *cipherInfo = CreateBufferBySize(iv->contentSize + tag->contentSize + ciphertext->contentSize);
    if (cipherInfo == NULL) {
        LOG_ERROR("create cipherInfo fail");
        return NULL;
    }
    if (memcpy_s(cipherInfo->buf, cipherInfo->maxSize, iv->buf, iv->contentSize) != EOK) {
        LOG_ERROR("failed to copy iv");
        goto ERROR;
    }
    cipherInfo->contentSize += iv->contentSize;
    if (memcpy_s(cipherInfo->buf + cipherInfo->contentSize, cipherInfo->maxSize - cipherInfo->contentSize,
        tag->buf, tag->contentSize) != EOK) {
        LOG_ERROR("failed to copy tag");
        goto ERROR;
    }
    cipherInfo->contentSize += tag->contentSize;
    if (memcpy_s(cipherInfo->buf + cipherInfo->contentSize, cipherInfo->maxSize - cipherInfo->contentSize,
        ciphertext->buf, ciphertext->contentSize) != EOK) {
        LOG_ERROR("failed to copy ciphertext");
        goto ERROR;
    }
    cipherInfo->contentSize += ciphertext->contentSize;
    return cipherInfo;

ERROR:
    DestroyBuffer(cipherInfo);
    return NULL;
}

static Buffer *GetPinCiperInfo(Buffer *key, Buffer *pinData)
{
    Buffer *cipherText = NULL;
    Buffer *tag = NULL;
    Buffer *cipherInfo = NULL;
    AesGcmParam param = {};
    param.key = key;
    param.iv = CreateBufferBySize(AES_GCM_256_IV_SIZE);
    if (!IsBufferValid(param.iv)) {
        LOG_ERROR("create iv fail.");
        goto EXIT;
    }
    if (SecureRandom(param.iv->buf, param.iv->maxSize) != RESULT_SUCCESS) {
        LOG_ERROR("random iv fail.");
        goto EXIT;
    }
    param.iv->contentSize = param.iv->maxSize;
    if (AesGcm256Encrypt(pinData, &param, &cipherText, &tag) != RESULT_SUCCESS) {
        LOG_ERROR("AesGcmEncrypt fail.");
        goto EXIT;
    }

    cipherInfo = SplicePinCiperInfo(param.iv, tag, cipherText);
    if (cipherInfo == NULL) {
        LOG_ERROR("SplicePinCiperInfo fail.");
        goto EXIT;
    }

EXIT:
    DestroyBuffer(param.iv);
    DestroyBuffer(cipherText);
    DestroyBuffer(tag);

    return cipherInfo;
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
        DestroyBuffer(secret);
        return NULL;
    }
    secret->contentSize = secret->maxSize;
    return secret;
}

static ResultCode ProcessAddPin(const Buffer *deviceKey, const Buffer *secret, PinEnrollParam *pinEnrollParam,
    uint64_t *templateId)
{
    *templateId = GeneratePinTemplateId();
    if (*templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("GeneratePinTemplateId fail.");
        return RESULT_GENERAL_ERROR;
    }

    Buffer *key = GenerateEncryptionKey(deviceKey);
    if (!IsBufferValid(key)) {
        LOG_ERROR("GenerateEncryptionKey fail.");
        return RESULT_GENERAL_ERROR;
    }
    Buffer pinDataBuffer = GetTmpBuffer(pinEnrollParam->pinData, CONST_PIN_DATA_LEN, CONST_PIN_DATA_LEN);
    Buffer *cipherInfo = GetPinCiperInfo(key, &pinDataBuffer);
    DestroyBuffer(key);
    if (cipherInfo == NULL) {
        LOG_ERROR("GetPinCiperInfo fail.");
        return RESULT_GENERAL_ERROR;
    }

    ResultCode ret = WriteAddPinInfo(secret, cipherInfo, pinEnrollParam->salt, CONST_SALT_LEN, *templateId);
    DestroyBuffer(cipherInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("write add pin info fail.");
        (void)RemoveAllFile(*templateId);
        return ret;
    }

    ret = AddPinInDb(*templateId, pinEnrollParam->subType, pinEnrollParam->pinLength);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("AddPinDb fail.");
        (void)RemoveAllFile(*templateId);
        return ret;
    }
    return ret;
}

static ResultCode UpdatePinLength(uint64_t templateId, uint32_t pinLength)
{
    LOG_INFO("start UpdatePinLength");
    if (templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("check param fail.");
        return RESULT_BAD_PARAM;
    }

    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
    }
    uint32_t currentPinLength = g_pinDbOp->pinIndex[index].pinInfo.pinLength;
    LOG_INFO("currentPinLength : %{public}u, inputPinLength : %{public}u", currentPinLength, pinLength);
    if (currentPinLength == pinLength) {
        return RESULT_SUCCESS;
    }
    g_pinDbOp->pinIndex[index].pinInfo.pinLength = pinLength;
    ret = WritePinDb(g_pinDbOp);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinDb fail.");
        return ret;
    }
    LOG_INFO("end UpdatePinLength");
    return ret;
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
    ResultCode ret = RESULT_GENERAL_ERROR;
    Buffer pinCredData = GetTmpBuffer(pinEnrollParam->pinData, CONST_PIN_DATA_LEN, CONST_PIN_DATA_LEN);
    Buffer *secret = CreateSecretBuffer();
    Buffer *deviceKey = NULL;
    if (!IsBufferValid(secret)) {
        LOG_ERROR("generate buffer fail.");
        ret = RESULT_NO_MEMORY;
        goto ERROR;
    }
    deviceKey = DeriveDeviceKey(&pinCredData, secret);
    if (!IsBufferValid(deviceKey)) {
        LOG_ERROR("generate deviceKey fail.");
        ret = RESULT_GENERAL_ERROR;
        goto ERROR;
    }
    ret = GenerateRootSecret(deviceKey, &pinCredData, outRootSecret);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("generate rootSecret fail.");
        goto ERROR;
    }
    ret = ProcessAddPin(deviceKey, secret, pinEnrollParam, templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("process add pin fail.");
        goto ERROR;
    }
    LOG_INFO("AddPin succ.");

ERROR:
    DestroyBuffer(deviceKey);
    DestroyBuffer(secret);
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

    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
    }

    ret = ReadPinFile(salt, *saltLen, templateId, SALT_SUFFIX);
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
    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
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
    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
    }
    ret = WritePinFile((uint8_t *)(&(g_pinDbOp->pinIndex[index].antiBruteInfo)), sizeof(AntiBruteInfoV0),
        templateId, ANTI_BRUTE_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("write anti brute fail.");
    }

    return ret;
}

static ResultCode SetAntiBruteInfoById(uint64_t templateId, uint32_t count, uint64_t startFreezeTime)
{
    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
    }
    g_pinDbOp->pinIndex[index].antiBruteInfo.authErrorCount = count;
    g_pinDbOp->pinIndex[index].antiBruteInfo.startFreezeTime = startFreezeTime;
    ret = WritePinFile((uint8_t *)(&(g_pinDbOp->pinIndex[index].antiBruteInfo)), sizeof(AntiBruteInfoV0),
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

    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
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

    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
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
    if (authErrorCount >= ATTI_BRUTE_SECOND_STAGE) {
        return ONE_DAY_TIME * MS_OF_S;
    }
    return ExponentialFuncTime(authErrorCount) * MS_OF_S;
}

int32_t GetNextFailLockoutDuration(uint32_t authErrorCount)
{
    if (authErrorCount < FIRST_ANTI_BRUTE_COUNT) {
        return ONE_MIN_TIME * MS_OF_S;
    }
    if (authErrorCount < SECOND_ANTI_BRUTE_COUNT) {
        return TEN_MIN_TIME * MS_OF_S;
    }
    if (authErrorCount < THIRD_ANTI_BRUTE_COUNT) {
        return THIRTY_MIN_TIME * MS_OF_S;
    }
    if (authErrorCount < ATTI_BRUTE_FIRST_STAGE -
        (ATTI_BRUTE_FIRST_STAGE - FIRST_ANTI_BRUTE_COUNT) % ANTI_BRUTE_COUNT_FREQUENCY) {
        return ONE_HOUR_TIME * MS_OF_S;
    }
    if (authErrorCount < ATTI_BRUTE_FIRST_STAGE) {
        return (int32_t)ExponentialFuncTime(ATTI_BRUTE_FIRST_STAGE) * MS_OF_S;
    }
    if (authErrorCount < ATTI_BRUTE_SECOND_STAGE - 1) {
        return (int32_t)ExponentialFuncTime(authErrorCount + 1) * MS_OF_S;
    }
    return ONE_DAY_TIME * MS_OF_S;
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
    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
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
    if (pinData->contentSize <= AES_GCM_256_IV_SIZE + AES_GCM_256_TAG_SIZE) {
        LOG_ERROR("check pin data cipher info fail");
        return NULL;
    }

    AesGcmParam param = {};
    Buffer iv = GetTmpBuffer(pinData->buf, AES_GCM_256_IV_SIZE, AES_GCM_256_IV_SIZE);
    param.iv = &iv;
    param.key = GenerateEncryptionKey(deviceKey);
    if (param.key == NULL) {
        LOG_ERROR("GenerateEncryptionKey fail");
        return NULL;
    }
    Buffer tag = GetTmpBuffer(pinData->buf + AES_GCM_256_IV_SIZE, AES_GCM_256_TAG_SIZE, AES_GCM_256_TAG_SIZE);
    uint32_t cipherTextSize = pinData->contentSize - AES_GCM_256_IV_SIZE - AES_GCM_256_TAG_SIZE;
    Buffer cipherText = GetTmpBuffer(
        pinData->buf + AES_GCM_256_IV_SIZE + AES_GCM_256_TAG_SIZE, cipherTextSize, cipherTextSize);
    Buffer *plainText = NULL;
    int32_t result = AesGcm256Decrypt(&cipherText, &param, &tag, &plainText);
    DestroyBuffer(param.key);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("Aes256GcmDecrypt fail");
        return NULL;
    }

    return plainText;
}

static ResultCode ProcessAuthPin(
    const Buffer *storeData, const Buffer *inputData, uint64_t templateId, Buffer *outRootSecret)
{
    Buffer *secret = CreateBufferBySize(SECRET_SIZE);
    Buffer *deviceKey = NULL;
    Buffer *pinDecodeCredential = NULL;
    ResultCode ret = RESULT_COMPARE_FAIL;
    if (!IsBufferValid(secret)) {
        LOG_ERROR("create buffer fail.");
        goto EXIT;
    }
    if (ReadPinFile(secret->buf, secret->maxSize, templateId, SECRET_SUFFIX) != RESULT_SUCCESS) {
        LOG_ERROR("read pin secret file fail.");
        goto EXIT;
    }
    secret->contentSize = secret->maxSize;
    deviceKey = DeriveDeviceKey(inputData, secret);
    if (!IsBufferValid(deviceKey)) {
        LOG_ERROR("generate deviceKey fail.");
        goto EXIT;
    }
    if ((outRootSecret != NULL) &&
        GenerateRootSecret(deviceKey, inputData, outRootSecret) != RESULT_SUCCESS) {
        LOG_ERROR("generate rootSecret fail.");
        goto EXIT;
    }
    pinDecodeCredential = GenerateDecodeCredential(deviceKey, storeData);
    if (!CheckBufferWithSize(pinDecodeCredential, inputData->contentSize)) {
        LOG_ERROR("generate pinDecodeCredential fail.");
        goto EXIT;
    }
    if (CompareBuffer(inputData, pinDecodeCredential)) {
        LOG_INFO("auth pin success.");
        ret = RESULT_SUCCESS;
        goto EXIT;
    }
    LOG_ERROR("auth pin fail.");

EXIT:
    DestroyBuffer(pinDecodeCredential);
    DestroyBuffer(deviceKey);
    DestroyBuffer(secret);
    return ret;
}

/* This is for example only, Should be implemented in trusted environment. */
ResultCode AuthPinById(const Buffer *inputPinData, uint64_t templateId, uint32_t pinLength, Buffer *outRootSecret,
    ResultCode *compareRet)
{
    if (!CheckBufferWithSize(inputPinData, CONST_PIN_DATA_LEN) ||
        templateId == INVALID_TEMPLATE_ID || compareRet == NULL) {
        LOG_ERROR("get invalid params.");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }
    *compareRet = RESULT_COMPARE_FAIL;
    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        return ret;
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
    ret = ReadPinFile(storeData->buf, storeData->maxSize, templateId, CRYPTO_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("read pin store file fail.");
        DestroyBuffer(storeData);
        return RESULT_BAD_READ;
    }
    storeData->contentSize = storeData->maxSize;
    *compareRet = ProcessAuthPin(storeData, inputPinData, templateId, outRootSecret);
    if ((*compareRet) == RESULT_SUCCESS) {
        ret = UpdateAntiBruteFile(templateId, true);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("UpdateAntiBruteFile fail.");
            goto EXIT;
        }
        ret = UpdatePinLength(templateId, pinLength);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("UpdatePinLength fail.");
            goto EXIT;
        }
    }
    LOG_INFO("AuthPinById end.");

EXIT:
    DestroyBuffer(storeData);
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
        DestroyBuffer(resultSha256);
        return RESULT_GENERAL_ERROR;
    }
    *algoParameterLength = resultSha256->contentSize;

    DestroyBuffer(resultSha256);
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

void DestroyAbandonParam(void)
{
    LOG_INFO("start");
    if (g_abandonCacheParam == NULL) {
        return;
    }
    DestroyBuffer(g_abandonCacheParam->newRootSecret);
    Free(g_abandonCacheParam);
    g_abandonCacheParam = NULL;
    return;
}

static ResultCode CacheAbandonParam(uint64_t oldTemplateId, uint64_t curTemplateId, uint64_t newTemplateId,
    Buffer *ciperInfo)
{
    LOG_INFO("oldTemplateId:0x%{public}x, curTemplateId:0x%{public}x, newTemplateId:0x%{public}x",
        (uint16_t)oldTemplateId, (uint16_t)curTemplateId, (uint16_t)newTemplateId);
    DestroyAbandonParam();
    AbandonCacheParam *cacheParam = (AbandonCacheParam *)Malloc(sizeof(AbandonCacheParam));
    if (cacheParam == NULL) {
        LOG_ERROR("no memory");
        return RESULT_NO_MEMORY;
    }
    (void)memset_s(cacheParam, sizeof(AbandonCacheParam), 0, sizeof(AbandonCacheParam));
    cacheParam->oldTemplateId = oldTemplateId;
    cacheParam->curTemplateId = curTemplateId;
    cacheParam->newTemplateId = newTemplateId;
    cacheParam->newRootSecret = CreateBufferByData(ciperInfo->buf, ciperInfo->contentSize);
    if (cacheParam->newRootSecret == NULL) {
        LOG_ERROR("no memory");
        Free(cacheParam);
        return RESULT_NO_MEMORY;
    }
    g_abandonCacheParam = cacheParam;
    return RESULT_SUCCESS;
}

ResultCode WriteRootSecretFile(uint64_t templateId, uint64_t newTemplateId, Buffer *ciperInfo)
{
    LOG_INFO("templateId:0x%{public}x, newTemplateId:0x%{public}x", (uint16_t)templateId, (uint16_t)newTemplateId);
    if (!IsBufferValid(ciperInfo)) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    Buffer *buffer = CreateBufferBySize(sizeof(uint64_t) + ciperInfo->contentSize);
    if (buffer == NULL) {
        LOG_ERROR("no memory");
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(buffer->buf, sizeof(uint64_t), &newTemplateId, sizeof(uint64_t)) != EOK) {
        LOG_ERROR("copy templateId fialed");
        DestroyBuffer(buffer);
        return RESULT_BAD_COPY;
    }
    buffer->contentSize += sizeof(uint64_t);
    if (memcpy_s(buffer->buf + sizeof(uint64_t), ciperInfo->contentSize, ciperInfo->buf,
        ciperInfo->contentSize) != EOK) {
        LOG_ERROR("copy rootSecret fialed");
        DestroyBuffer(buffer);
        return RESULT_BAD_COPY;
    }
    buffer->contentSize += ciperInfo->contentSize;
    ResultCode ret = WritePinFile(buffer->buf, buffer->contentSize, templateId, ROOTSECRET_CRYPTO_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinFile fail.");
        DestroyBuffer(buffer);
        return ret;
    }
    DestroyBuffer(buffer);
    return RESULT_SUCCESS;
}

ResultCode ReadRootSecretFile(uint64_t templateId, uint64_t *newTemplateId, Buffer **ciperInfo)
{
    LOG_INFO("templateId:0x%{public}x", (uint16_t)templateId);
    uint32_t ciperInfoLen = AES_GCM_256_IV_SIZE + AES_GCM_256_TAG_SIZE + ROOT_SECRET_LEN;
    Buffer *buffer = CreateBufferBySize(sizeof(uint64_t) + ciperInfoLen);
    if (buffer == NULL) {
        LOG_ERROR("no memory");
        return RESULT_NO_MEMORY;
    }

    ResultCode ret = ReadPinFile(buffer->buf, buffer->maxSize, templateId, ROOTSECRET_CRYPTO_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ReadPinFile fail");
        DestroyBuffer(buffer);
        return ret;
    }
    buffer->contentSize = sizeof(uint64_t) + ciperInfoLen;
    if (memcpy_s(newTemplateId, sizeof(uint64_t), buffer->buf, sizeof(uint64_t)) != EOK) {
        LOG_ERROR("copy templateId fialed");
        DestroyBuffer(buffer);
        return RESULT_BAD_COPY;
    }

    *ciperInfo = CreateBufferBySize(ciperInfoLen);
    if (*ciperInfo == NULL) {
        LOG_ERROR("no memory");
        DestroyBuffer(buffer);
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s((*ciperInfo)->buf, ciperInfoLen, buffer->buf + sizeof(uint64_t), ciperInfoLen) != EOK) {
        LOG_ERROR("copy rootSecret fialed");
        DestroyBuffer(buffer);
        DestroyBuffer(*ciperInfo);
        return RESULT_BAD_COPY;
    }
    (*ciperInfo)->contentSize = ciperInfoLen;
    DestroyBuffer(buffer);
    return RESULT_SUCCESS;
}

ResultCode ReWriteRootSecretFile(uint64_t templateId)
{
    LOG_INFO("templateId:0x%{public}x", (uint16_t)templateId);
    if (g_abandonCacheParam == NULL || templateId != g_abandonCacheParam->curTemplateId) {
        LOG_INFO("g_abandonCacheParam is null or templateId is not same");
        return RESULT_SUCCESS;
    }

    ResultCode ret = WriteRootSecretFile(g_abandonCacheParam->oldTemplateId, g_abandonCacheParam->newTemplateId,
        g_abandonCacheParam->newRootSecret);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WriteRootSecretFile fail, ret:%{public}u", ret);
        return ret;
    }
    DestroyAbandonParam();
    return RESULT_SUCCESS;
}

Buffer *GetRootSecretCipherInfo(Buffer *oldRootSecret, Buffer *newRootSecret)
{
    if (!IsBufferValid(oldRootSecret) || !IsBufferValid(newRootSecret)) {
        LOG_ERROR("invalid param.");
        return NULL;
    }

    Buffer *cipherText = NULL;
    Buffer *tag = NULL;
    Buffer *cipherInfo = NULL;
    AesGcmParam param = {};
    param.key = oldRootSecret;
    param.iv = CreateBufferBySize(AES_GCM_256_IV_SIZE);
    if (!IsBufferValid(param.iv)) {
        LOG_ERROR("create iv fail.");
        goto EXIT;
    }
    if (SecureRandom(param.iv->buf, param.iv->maxSize) != RESULT_SUCCESS) {
        LOG_ERROR("random iv fail.");
        goto EXIT;
    }
    param.iv->contentSize = param.iv->maxSize;
    if (AesGcm256Encrypt(newRootSecret, &param, &cipherText, &tag) != RESULT_SUCCESS) {
        LOG_ERROR("AesGcmEncrypt fail.");
        goto EXIT;
    }
    cipherInfo = SplicePinCiperInfo(param.iv, tag, cipherText);
    if (cipherInfo == NULL) {
        LOG_ERROR("SplicePinCiperInfo fail.");
        goto EXIT;
    }

EXIT:
    DestroyBuffer(param.iv);
    DestroyBuffer(cipherText);
    DestroyBuffer(tag);
    return cipherInfo;
}

Buffer *GetRootSecretPlainInfo(Buffer *oldRootSecret, const Buffer *cipherInfo)
{
    if (!IsBufferValid(oldRootSecret) || !IsBufferValid(cipherInfo)) {
        LOG_ERROR("invalid param.");
        return NULL;
    }

    if (cipherInfo->contentSize < AES_GCM_256_IV_SIZE + AES_GCM_256_TAG_SIZE + ROOT_SECRET_LEN) {
        LOG_ERROR("check cipher info fail.");
        return NULL;
    }

    AesGcmParam param = {};
    Buffer iv = GetTmpBuffer(cipherInfo->buf, AES_GCM_256_IV_SIZE, AES_GCM_256_IV_SIZE);
    param.iv = &iv;
    param.key = oldRootSecret;
    Buffer tag = GetTmpBuffer(cipherInfo->buf + AES_GCM_256_IV_SIZE, AES_GCM_256_TAG_SIZE, AES_GCM_256_TAG_SIZE);
    uint32_t cipherTextSize = cipherInfo->contentSize - AES_GCM_256_IV_SIZE - AES_GCM_256_TAG_SIZE;
    Buffer cipherText = GetTmpBuffer(
        cipherInfo->buf + AES_GCM_256_IV_SIZE + AES_GCM_256_TAG_SIZE, cipherTextSize, cipherTextSize);
    Buffer *plainText = NULL;
    int32_t result = AesGcm256Decrypt(&cipherText, &param, &tag, &plainText);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("Aes256GcmDecrypt fail");
        return NULL;
    }

    return plainText;
}

/* This is for example only, Should be implemented in trusted environment. */
ResultCode Abandon(uint64_t oldTemplateId, uint64_t newTemplateId, Buffer *oldRootSecret, Buffer *newRootSecret)
{
    LOG_INFO("oldTemplateId:0x%{public}x, newTemplateId:0x%{public}x",
        (uint16_t)oldTemplateId, (uint16_t)newTemplateId);
    if (!IsBufferValid(oldRootSecret) || !IsBufferValid(newRootSecret)) {
        LOG_ERROR("get invalid params.");
        return RESULT_BAD_PARAM;
    }

    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(oldTemplateId, &index);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get invalid params.");
        return ret;
    }

    Buffer *cipherInfo = GetRootSecretCipherInfo(oldRootSecret, newRootSecret);
    if (cipherInfo == NULL) {
        LOG_ERROR("GetRootSecretCipherInfo fail.");
        return RESULT_GENERAL_ERROR;
    }

    Buffer *oldCipherInfo = NULL;
    uint64_t curTemplateId = 0;
    ret = ReadRootSecretFile(oldTemplateId, &curTemplateId, &oldCipherInfo);
    if (ret == RESULT_SUCCESS) {
        ret = CacheAbandonParam(oldTemplateId, curTemplateId, newTemplateId, cipherInfo);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("CacheAbandonParam fail, ret:%{public}u", ret);
            goto EXIT;
        }
    } else {
        ret = WriteRootSecretFile(oldTemplateId, newTemplateId, cipherInfo);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("WriteRootSecretFile fail.");
            goto EXIT;
        }
    }

    LOG_INFO("Abandon success");
EXIT:
    DestroyBuffer(oldCipherInfo);
    DestroyBuffer(cipherInfo);
    return ret;
}

Buffer *GenerateDecodeRootSecret(uint64_t templateId, Buffer *oldRootSecret)
{
    LOG_INFO("templateId:0x%{public}x", (uint16_t)templateId);
    if (!IsBufferValid(oldRootSecret)) {
        LOG_ERROR("bad param.");
        return NULL;
    }

    Buffer *rootSecretPlain = NULL;
    Buffer *cipherInfo = NULL;
    uint64_t newTemplateId = 0;
    ResultCode ret = ReadRootSecretFile(templateId, &newTemplateId, &cipherInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ReadRootSecretFile fail");
        goto EXIT;
    }

    rootSecretPlain = GetRootSecretPlainInfo(oldRootSecret, cipherInfo);
    if (!IsBufferValid(rootSecretPlain)) {
        LOG_ERROR("rootSecretPlain is invalid.");
        goto EXIT;
    }
    LOG_INFO("GenerateDecodeRootSecret success");
EXIT:
    DestroyBuffer(cipherInfo);
    return rootSecretPlain;
}

ResultCode GetCredentialLength(uint64_t templateId, uint32_t *credentialLength)
{
    if (templateId == INVALID_TEMPLATE_ID || credentialLength == NULL) {
        LOG_ERROR("check param fail!");
        return RESULT_BAD_PARAM;
    }
    if (!LoadPinDb()) {
        LOG_ERROR("LoadPinDb fail.");
        return RESULT_NEED_INIT;
    }

    uint32_t index = MAX_CRYPTO_INFO_SIZE;
    ResultCode ret = SearchPinIndex(templateId, &index);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("SearchPinIndex no pin exist.");
        return ret;
    }
    *credentialLength = g_pinDbOp->pinIndex[index].pinInfo.pinLength;

    LOG_INFO("GetCredentialLength succ.");
    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
ResultCode RestartLockoutDurationByUserId(int32_t userId)
{
    // Example implementation, This will restart lockout duration for all users.
    LOG_INFO("start");
    (void)userId;
    if (!LoadPinDb()) {
        LOG_ERROR("load pinDb fail.");
        return RESULT_NEED_INIT;
    }
    if (g_pinDbOp->pinIndexLen == 0) {
        LOG_ERROR("SearchPinIndex no pin exist.");
        return RESULT_BAD_MATCH;
    }

    uint32_t errorCount = 0;
    uint64_t templateId = 0;
    uint64_t startFreezeTime = 0;
    uint32_t freezeTime = 0;
    ResultCode ret = RESULT_GENERAL_ERROR;
    bool anyLockoutRestart = false;
    for (uint32_t index = 0; index < g_pinDbOp->pinIndexLen; index++) {
        errorCount = g_pinDbOp->pinIndex[index].antiBruteInfo.authErrorCount;
        templateId = g_pinDbOp->pinIndex[index].pinInfo.templateId;
        startFreezeTime = g_pinDbOp->pinIndex[index].antiBruteInfo.startFreezeTime;
        freezeTime = 0;
        ret = ComputeFreezeTime(templateId, &freezeTime, errorCount, startFreezeTime);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("ComputeFreezeTime fail.");
            return ret;
        }
        if (freezeTime != 0) {
            uint64_t nowTime = GetRtcTime();
            ret = SetAntiBruteInfoById(templateId, errorCount, nowTime);
            if (ret != RESULT_SUCCESS) {
                LOG_ERROR("SetAntiBruteInfoById fail.");
                return ret;
            }
            anyLockoutRestart = true;
            LOG_INFO("restart lockout duration success.");
        }
    }
    if (anyLockoutRestart) {
        return RESULT_SUCCESS;
    }
    return RESULT_GENERAL_ERROR;
}