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
#include <inttypes.h>
#include "adaptor_algorithm.h"
#include "adaptor_memory.h"
#include "adaptor_time.h"
#include "defines.h"
#include "file_operator.h"
#include "securec.h"

static PinDb g_pinDbOp = {CURRENT_VERSION, 0, NULL, false};

static ResultCode GetDataFromBuf(uint8_t **src, uint32_t *srcLen, uint8_t *dest, uint32_t destLen)
{
    if (destLen > *srcLen) {
        LOG_ERROR("bad len.");
        return RESULT_BAD_PARAM;
    }
    if (memcpy_s(dest, destLen, *src, destLen) != EOK) {
        LOG_ERROR("copy fail.");
        return RESULT_BAD_COPY;
    }

    *src = *src + destLen;
    *srcLen = *srcLen - destLen;
    return RESULT_SUCCESS;
}

static ResultCode CopyDataToBuf(uint8_t *data, uint32_t dataLen, uint8_t **buf, uint32_t *bufLen)
{
    if (memcpy_s(*buf, *bufLen, data, dataLen) != EOK) {
        LOG_ERROR("CopyFileName fail.");
        return RESULT_BAD_COPY;
    }

    *buf = *buf + dataLen;
    *bufLen = *bufLen - dataLen;
    return RESULT_SUCCESS;
}

static ResultCode GenerateFileName(uint64_t templateId, const char *prefix, const char *suffix,
    char *fileName, uint32_t fileNameLen)
{
    if (memset_s(fileName, fileNameLen, 0, fileNameLen) != EOK) {
        return RESULT_PIN_FAIL;
    }
    char *buf = fileName;
    uint32_t bufLen = fileNameLen;
    if (CopyDataToBuf((uint8_t *)prefix, strlen(prefix), (uint8_t **)&buf, &bufLen) != RESULT_SUCCESS) {
        LOG_ERROR("copy prefix fail.");
        return RESULT_BAD_COPY;
    }
    char templateIdStr[MAX_UINT_LEN] = {'\0'};
    if (snprintf_s(templateIdStr, MAX_UINT_LEN, MAX_UINT_LEN - 1, "%" PRIu64, templateId) < 0) {
        LOG_ERROR("templateIdStr error.");
        return RESULT_UNKNOWN;
    }
    if (CopyDataToBuf((uint8_t *)templateIdStr, strlen(templateIdStr), (uint8_t **)&buf, &bufLen) != RESULT_SUCCESS) {
        LOG_ERROR("copy templateIdStr fail.");
        return RESULT_BAD_COPY;
    }
    if (CopyDataToBuf((uint8_t *)suffix, strlen(suffix), (uint8_t **)&buf, &bufLen) != RESULT_SUCCESS) {
        LOG_ERROR("copy suffix fail.");
        return RESULT_BAD_COPY;
    }
    if (bufLen == 0) {
        LOG_ERROR("no space for endl.");
        return RESULT_BAD_COPY;
    }

    LOG_INFO("GenerateFileName succ.");
    return RESULT_SUCCESS;
}

/* This is for example only, Should be implemented in trusted environment. */
static ResultCode ReadPinFile(uint8_t *data, uint32_t dataLen, uint64_t templateId, const char *suffix)
{
    FileOperator *fileOp = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOp)) {
        LOG_ERROR("fileOp invalid.");
        return RESULT_GENERAL_ERROR;
    }

    char fileName[MAX_FILE_NAME_LEN] = {'\0'};
    ResultCode ret = GenerateFileName(templateId, DEFAULT_FILE_HEAD, suffix, fileName, MAX_FILE_NAME_LEN);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ReadPinFile Generate Pin FileName fail.");
        return RESULT_GENERAL_ERROR;
    }
    ret = (ResultCode)fileOp->readFile(fileName, data, dataLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("read pin file fail.");
        return ret;
    }

    return RESULT_SUCCESS;
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

static ResultCode GetPinIndex(uint8_t *data, uint32_t dataLen)
{
    if (sizeof(PinInfo) * g_pinDbOp.pinIndexLen != dataLen) {
        LOG_ERROR("bad data length.");
        return RESULT_GENERAL_ERROR;
    }
    g_pinDbOp.pinIndex = (PinIndex *)Malloc(sizeof(PinIndex) * g_pinDbOp.pinIndexLen);
    if (g_pinDbOp.pinIndex == NULL) {
        LOG_ERROR("pinIndex malloc fail.");
        return RESULT_NO_MEMORY;
    }
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    for (uint32_t i = 0; i < g_pinDbOp.pinIndexLen; i++) {
        if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(g_pinDbOp.pinIndex[i].pinInfo)),
            sizeof(g_pinDbOp.pinIndex[i].pinInfo)) != RESULT_SUCCESS) {
            LOG_ERROR("read pinInfo fail.");
            Free(g_pinDbOp.pinIndex);
            g_pinDbOp.pinIndex = NULL;
            return RESULT_BAD_READ;
        }
        if (ReadPinFile((uint8_t *)(&(g_pinDbOp.pinIndex[i].antiBruteInfo)),
            sizeof(g_pinDbOp.pinIndex[i].antiBruteInfo),
            g_pinDbOp.pinIndex[i].pinInfo.templateId, ANTI_BRUTE_SUFFIX) != RESULT_SUCCESS) {
            LOG_ERROR("read AntiBruteInfo fail.");
            Free(g_pinDbOp.pinIndex);
            g_pinDbOp.pinIndex = NULL;
            return RESULT_BAD_READ;
        }
    }
    return RESULT_SUCCESS;
}

static ResultCode UnpackPinDb(uint8_t *data, uint32_t dataLen)
{
    if (data == NULL || dataLen == 0) {
        LOG_ERROR("param is invalid.");
        return RESULT_BAD_PARAM;
    }

    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(g_pinDbOp.version)),
        sizeof(g_pinDbOp.version)) != RESULT_SUCCESS) {
        LOG_ERROR("read version fail.");
        goto ERROR;
    }
    if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(g_pinDbOp.pinIndexLen)),
        sizeof(g_pinDbOp.pinIndexLen)) != RESULT_SUCCESS) {
        LOG_ERROR("read pinIndexLen fail.");
        goto ERROR;
    }
    if (g_pinDbOp.pinIndexLen > MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("pinIndexLen too large.");
        goto ERROR;
    }
    if (g_pinDbOp.pinIndexLen == 0) {
        g_pinDbOp.pinIndex = NULL;
        return RESULT_SUCCESS;
    }
    if (GetPinIndex(temp, tempLen) != RESULT_SUCCESS) {
        LOG_ERROR("GetPinIndex fail.");
        goto ERROR;
    }
    return RESULT_SUCCESS;

ERROR:
    DestroyPinDb();
    return RESULT_BAD_READ;
}

static ResultCode LoadPinDb(void)
{
    if (g_pinDbOp.isLoaded) {
        return RESULT_SUCCESS;
    }
    FileOperator *fileOp = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOp)) {
        LOG_ERROR("fileOp invalid.");
        return RESULT_GENERAL_ERROR;
    }

    if (!fileOp->isFileExist(PIN_INDEX_NAME)) {
        g_pinDbOp.isLoaded = true;
        return RESULT_SUCCESS;
    }

    uint32_t dataLen = 0;
    ResultCode ret = (ResultCode)(fileOp->getFileLen(PIN_INDEX_NAME, &dataLen));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get filelen failed");
        return RESULT_BAD_READ;
    }

    uint8_t *data = Malloc(dataLen);
    if (data == NULL) {
        LOG_ERROR("malloc data failed");
        return RESULT_GENERAL_ERROR;
    }
    ret = (ResultCode)fileOp->readFile(PIN_INDEX_NAME, data, dataLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("read_parcel_from_file failed.");
        goto EXIT;
    }

    ret = UnpackPinDb(data, dataLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("unpack db failed.");
        goto EXIT;
    }
    g_pinDbOp.isLoaded = true;
    LOG_INFO("LoadPinDb succ.");

EXIT:
    (void)memset_s(data, dataLen, 0, dataLen);
    Free(data);
    return ret;
}

void InitPinDb(void)
{
    ResultCode ret = LoadPinDb();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("LoadPinDb fail.");
        return;
    }
    LOG_INFO("InitPinDb succ.");
}

void DestroyPinDb(void)
{
    if (g_pinDbOp.pinIndex != NULL) {
        Free(g_pinDbOp.pinIndex);
    }
    g_pinDbOp.version = CURRENT_VERSION;
    g_pinDbOp.pinIndexLen = 0;
    g_pinDbOp.pinIndex = NULL;
    g_pinDbOp.isLoaded = false;
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
        for (; j < g_pinDbOp.pinIndexLen; j++) {
            if (templateId == g_pinDbOp.pinIndex[i].pinInfo.templateId) {
                break;
            }
        }
        if (j == g_pinDbOp.pinIndexLen) {
            return templateId;
        }
    }
    LOG_ERROR("fail generate pin templateid.");
    return INVALID_TEMPLATE_ID;
}

static uint32_t SearchPinById(uint64_t templateId)
{
    if (g_pinDbOp.pinIndexLen == 0) {
        LOG_ERROR("no pin exist.");
        return MAX_CRYPTO_INFO_SIZE;
    }
    for (uint32_t index = 0; index < g_pinDbOp.pinIndexLen; index++) {
        if (g_pinDbOp.pinIndex[index].pinInfo.templateId == templateId) {
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
    ResultCode ret = RemoveAllFile(g_pinDbOp.pinIndex[index].pinInfo.templateId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("Remove pin file fail.");
        return ret;
    }

    LOG_INFO("DelPin succ.");
    return RESULT_SUCCESS;
}

static bool IsPinDbValid(PinDb *pinDb)
{
    if (pinDb == NULL) {
        return false;
    }
    if (pinDb->version != CURRENT_VERSION) {
        return false;
    }
    if ((pinDb->pinIndexLen == 0) && (pinDb->pinIndex != NULL)) {
        return false;
    }
    if ((pinDb->pinIndexLen != 0) && (pinDb->pinIndex == NULL)) {
        return false;
    }
    if (pinDb->pinIndexLen > MAX_CRYPTO_INFO_SIZE) {
        return false;
    }
    return true;
}

static ResultCode GetBufFromData(uint8_t *src, uint32_t srcLen, uint8_t **dest, uint32_t *destLen)
{
    if (srcLen > *destLen) {
        LOG_ERROR("bad len.");
        return RESULT_BAD_PARAM;
    }
    if (memcpy_s(*dest, *destLen, src, srcLen) != EOK) {
        LOG_ERROR("copy fail.");
        return RESULT_BAD_COPY;
    }

    *dest = *dest + srcLen;
    *destLen = *destLen - srcLen;
    return RESULT_SUCCESS;
}

static ResultCode WritePinInfo(uint8_t *data, uint32_t dataLen)
{
    if (g_pinDbOp.pinIndexLen == 0) {
        return RESULT_SUCCESS;
    }
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    for (uint32_t i = 0; i < g_pinDbOp.pinIndexLen; i++) {
        if (GetBufFromData((uint8_t *)(&(g_pinDbOp.pinIndex[i].pinInfo)), sizeof(g_pinDbOp.pinIndex[i].pinInfo),
            &temp, &tempLen) != RESULT_SUCCESS) {
            LOG_ERROR("write pin info fail.");
            return RESULT_BAD_WRITE;
        }
    }
    return RESULT_SUCCESS;
}

static ResultCode WritePinDb(void)
{
    if (!IsPinDbValid(&g_pinDbOp)) {
        LOG_ERROR("get invalid params.");
        return RESULT_BAD_PARAM;
    }
    ResultCode ret = RESULT_SUCCESS;
    FileOperator *fileOp = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOp)) {
        LOG_ERROR("fileOp invalid.");
        return RESULT_GENERAL_ERROR;
    }

    uint32_t dataLen = sizeof(PinInfo) * g_pinDbOp.pinIndexLen + sizeof(uint32_t) * PIN_DB_TWO_PARAMS;
    uint8_t *data = Malloc(dataLen);
    if (data == NULL) {
        LOG_ERROR("malloc data fail.");
        return RESULT_GENERAL_ERROR;
    }
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    if (GetBufFromData((uint8_t *)(&(g_pinDbOp.version)), sizeof(g_pinDbOp.version),
        &temp, &tempLen)!= RESULT_SUCCESS) {
        ret = RESULT_BAD_WRITE;
        goto ERROR;
    }

    if (GetBufFromData((uint8_t *)(&(g_pinDbOp.pinIndexLen)), sizeof(g_pinDbOp.pinIndexLen),
        &temp, &tempLen) != RESULT_SUCCESS) {
        ret = RESULT_BAD_WRITE;
        goto ERROR;
    }
    ret = WritePinInfo(temp, tempLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinInfo failed.");
        goto ERROR;
    }

    if ((ResultCode)fileOp->writeFile(PIN_INDEX_NAME, data, dataLen) != RESULT_SUCCESS) {
        LOG_ERROR("write_parcel_into_file failed.");
        ret = RESULT_BAD_WRITE;
        goto ERROR;
    }
    LOG_INFO("WritePinDb succ.");

ERROR:
    (void)memset_s(data, dataLen, 0, dataLen);
    Free(data);
    return ret;
}

static ResultCode DelPinInDb(uint32_t index)
{
    uint32_t pinIndexLen = g_pinDbOp.pinIndexLen - 1;
    if (pinIndexLen == 0) {
        (void)memset_s(g_pinDbOp.pinIndex,
            g_pinDbOp.pinIndexLen * sizeof(PinIndex), 0, g_pinDbOp.pinIndexLen * sizeof(PinIndex));
        Free(g_pinDbOp.pinIndex);
        g_pinDbOp.pinIndex = NULL;
    } else {
        uint32_t size = pinIndexLen * sizeof(PinIndex);
        PinIndex *pinIndex = (PinIndex *)Malloc(size);
        if (pinIndex == NULL) {
            LOG_ERROR("PinIndex malloc fail.");
            return RESULT_NO_MEMORY;
        }
        (void)memset_s(pinIndex, size, 0, size);
        for (uint32_t i = 0, j = 0; i < g_pinDbOp.pinIndexLen; i++) {
            if (i != index) {
                pinIndex[j] = g_pinDbOp.pinIndex[i];
                j++;
            }
        }
        (void)memset_s(g_pinDbOp.pinIndex,
            g_pinDbOp.pinIndexLen * sizeof(PinIndex), 0, g_pinDbOp.pinIndexLen * sizeof(PinIndex));
        Free(g_pinDbOp.pinIndex);
        g_pinDbOp.pinIndex = pinIndex;
    }
    g_pinDbOp.pinIndexLen = pinIndexLen;
    ResultCode ret = WritePinDb();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinDb fail.");
    }

    LOG_INFO("DelPinInDb succ.");
    return ret;
}

ResultCode DelPinById(uint64_t templateId)
{
    ResultCode ret = LoadPinDb();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("LoadPinDb fail.");
        return ret;
    }
    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin match.");
        return RESULT_BAD_MATCH;
    }

    ret = DelPin(index);
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

static void InitPinInfo(PinInfo *pinInfo, uint64_t templateId, uint64_t subType)
{
    pinInfo->templateId = templateId;
    pinInfo->subType = subType;
}

static void InitAntiBruteInfo(AntiBruteInfo *info)
{
    info->authErrorCount = INIT_AUTH_ERROR_COUNT;
    info->startFreezeTime = INIT_START_FREEZE_TIMES;
}

static void InitPinIndex(PinIndex *pinIndex, uint64_t templateId, uint64_t subType)
{
    InitPinInfo(&(pinIndex->pinInfo), templateId, subType);
    InitAntiBruteInfo(&(pinIndex->antiBruteInfo));
}

static ResultCode AddPinInDb(uint64_t templateId, uint64_t subType)
{
    if (g_pinDbOp.pinIndexLen > MAX_CRYPTO_INFO_SIZE - 1) {
        LOG_ERROR("pinIndexLen too large.");
        return RESULT_BAD_PARAM;
    }
    uint32_t size = (g_pinDbOp.pinIndexLen + 1) * sizeof(PinIndex);
    PinIndex *pinIndex = (PinIndex *)Malloc(size);
    if (pinIndex == NULL) {
        LOG_ERROR("PinIndex malloc fail.");
        return RESULT_NO_MEMORY;
    }
    (void)memset_s(pinIndex, size, 0, size);
    if (g_pinDbOp.pinIndexLen != 0) {
        if (memcpy_s(pinIndex, size,
            g_pinDbOp.pinIndex, g_pinDbOp.pinIndexLen * sizeof(PinIndex)) != EOK) {
            LOG_ERROR("PinIndex copy fail.");
            (void)memset_s(pinIndex, size, 0, size);
            Free(pinIndex);
            return RESULT_NO_MEMORY;
        }
    }
    InitPinIndex(&pinIndex[g_pinDbOp.pinIndexLen], templateId, subType);
    if (g_pinDbOp.pinIndex != NULL) {
        Free(g_pinDbOp.pinIndex);
    }
    g_pinDbOp.pinIndex = pinIndex;
    g_pinDbOp.pinIndexLen++;
    ResultCode ret = WritePinDb();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinDb fail.");
        return ret;
    }

    LOG_INFO("AddPinInDb succ.");
    return RESULT_SUCCESS;
}

static ResultCode RefreshPinDb(uint64_t *templateId, uint64_t subType)
{
    ResultCode ret = LoadPinDb();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("LoadPinDb fail.");
        return ret;
    }
    *templateId = GeneratePinTemplateId();
    if (*templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("GeneratePinTemplateId fail.");
        return RESULT_UNKNOWN;
    }
    ret = AddPinInDb(*templateId, subType);
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
    AntiBruteInfo initAntiBrute = {};
    InitAntiBruteInfo(&initAntiBrute);
    ret = WritePinFile((uint8_t *)&initAntiBrute, sizeof(AntiBruteInfo), templateId, ANTI_BRUTE_SUFFIX);
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

/* This is for example only, Should be implemented in trusted environment. */
ResultCode AddPin(PinEnrollParam *pinEnrollParam, uint64_t *templateId, Buffer *outRootSecret)
{
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
    Buffer *secret = CreateBufferBySize(SECRET_SIZE);
    Buffer *deviceKey = NULL;
    if (!IsBufferValid(pinCredData) || !IsBufferValid(secret)) {
        LOG_ERROR("generate buffer fail.");
        ret = RESULT_NO_MEMORY;
        goto ERROR;
    }
    if (SecureRandom(secret->buf, secret->maxSize) != RESULT_SUCCESS) {
        LOG_ERROR("generate secure random number fail.");
        ret = RESULT_GENERAL_ERROR;
        goto ERROR;
    }
    secret->contentSize = secret->maxSize;
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

ResultCode DoGetSalt(uint64_t templateId, uint8_t *salt, uint32_t *saltLen)
{
    if (salt == NULL || saltLen == NULL || templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("get invalid salt params.");
        return RESULT_BAD_PARAM;
    }

    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR(" no pin match.");
        return RESULT_BAD_MATCH;
    }

    ResultCode ret = ReadPinFile(salt, *saltLen, templateId, SALT_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("salt file read fail.");
        return ret;
    }
    LOG_INFO("DoGetSalt succ.");
    return RESULT_SUCCESS;
}

static ResultCode GetAntiBruteCountById(uint64_t templateId, uint32_t *count)
{
    ResultCode ret = LoadPinDb();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("LoadPinDb fail.");
        return ret;
    }

    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin index match.");
        return RESULT_BAD_MATCH;
    }
    *count = g_pinDbOp.pinIndex[index].antiBruteInfo.authErrorCount;
    return RESULT_SUCCESS;
}

ResultCode RefreshAntiBruteInfoToFile(uint64_t templateId)
{
    ResultCode ret = LoadPinDb();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("LoadPinDb fail.");
        return ret;
    }
    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR(" no pin match.");
        return RESULT_BAD_MATCH;
    }
    ret = WritePinFile((uint8_t *)(&(g_pinDbOp.pinIndex[index].antiBruteInfo)), sizeof(AntiBruteInfo),
        templateId, ANTI_BRUTE_SUFFIX);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("write anti brute fail.");
    }

    return ret;
}

static ResultCode SetAntiBruteInfoById(uint64_t templateId, uint32_t count, uint64_t startFreezeTime)
{
    ResultCode ret = LoadPinDb();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("LoadPinDb fail.");
        return ret;
    }

    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR(" no pin match.");
        return RESULT_BAD_MATCH;
    }
    g_pinDbOp.pinIndex[index].antiBruteInfo.authErrorCount = count;
    g_pinDbOp.pinIndex[index].antiBruteInfo.startFreezeTime = startFreezeTime;
    ret = WritePinFile((uint8_t *)(&(g_pinDbOp.pinIndex[index].antiBruteInfo)), sizeof(AntiBruteInfo),
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

    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin match.");
        return RESULT_BAD_MATCH;
    }
    *subType = g_pinDbOp.pinIndex[index].pinInfo.subType;

    LOG_INFO("GetSubType succ.");
    return RESULT_SUCCESS;
}

ResultCode GetAntiBruteInfo(uint64_t templateId, uint32_t *authErrorCount, uint64_t *startFreezeTime)
{
    if (authErrorCount == NULL || startFreezeTime == NULL || templateId == INVALID_TEMPLATE_ID) {
        LOG_ERROR("check GetAntiBruteInfo param fail!");
        return RESULT_BAD_PARAM;
    }

    uint32_t index = SearchPinById(templateId);
    if (index == MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("no pin match.");
        return RESULT_BAD_MATCH;
    }
    *authErrorCount = g_pinDbOp.pinIndex[index].antiBruteInfo.authErrorCount;
    *startFreezeTime = g_pinDbOp.pinIndex[index].antiBruteInfo.startFreezeTime;

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
    InitAntiBruteInfo(&(g_pinDbOp.pinIndex[index].antiBruteInfo));
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
    uint32_t i = 0;
    for (; i < g_pinDbOp.pinIndexLen; i++) {
        if (FindTemplateIdFromList(g_pinDbOp.pinIndex[i].pinInfo.templateId, templateIdList, templateIdListLen)) {
            continue;
        }
        ResultCode ret = DelPinById(g_pinDbOp.pinIndex[i].pinInfo.templateId);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("delete pin file fail.");
            return RESULT_BAD_DEL;
        }
    }
    LOG_INFO("VerifyTemplateDataPin succ.");
    return RESULT_SUCCESS;
}
