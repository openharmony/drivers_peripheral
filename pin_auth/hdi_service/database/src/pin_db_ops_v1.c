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

#include "pin_db_ops_v1.h"

#include "securec.h"

#include "adaptor_file.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "file_operator.h"
#include "pin_db_ops_base.h"

#define PIN_DB_TWO_PARAMS 2

void *UpdatePinDbFrom0To1(void *pinDb)
{
    PinDbV0 *pinDbV0 = pinDb;
    if (pinDbV0 == NULL) {
        LOG_ERROR("bad parameter.");
        return NULL;
    }
    PinDbV1 *pinDbV1 = Malloc(sizeof(PinDbV1));
    if (pinDbV1 == NULL) {
        LOG_ERROR("get pinDbV1 fail.");
        return NULL;
    }
    (void)memset_s(pinDbV1, sizeof(PinDbV1), 0, sizeof(PinDbV1));
    pinDbV1->dbVersion = DB_VERSION_1;
    if (pinDbV0->pinIndex == NULL || pinDbV0->pinIndexLen == 0) {
        LOG_INFO("get empty pinDbV0.");
        pinDbV1->pinIndex = NULL;
        pinDbV1->pinIndexLen = 0;
        return pinDbV1;
    }

    pinDbV1->pinIndexLen = pinDbV0->pinIndexLen;
    pinDbV1->pinIndex = Malloc(sizeof(PinIndexV1) * pinDbV1->pinIndexLen);
    if (pinDbV1->pinIndex == NULL) {
        LOG_ERROR("get pinIndex fail.");
        Free(pinDbV1);
        return NULL;
    }
    (void)memset_s(pinDbV1->pinIndex,
        sizeof(PinIndexV1) * pinDbV1->pinIndexLen, 0, sizeof(PinIndexV1) * pinDbV1->pinIndexLen);
    for (uint32_t i = 0; i < pinDbV1->pinIndexLen; i++) {
        pinDbV1->pinIndex[i].antiBruteInfo = pinDbV0->pinIndex[i].antiBruteInfo;
        pinDbV1->pinIndex[i].pinInfo.subType = pinDbV0->pinIndex[i].pinInfo.subType;
        pinDbV1->pinIndex[i].pinInfo.templateId = pinDbV0->pinIndex[i].pinInfo.templateId;
        pinDbV1->pinIndex[i].pinInfo.algoVersion = ALGORITHM_VERSION_0;
        pinDbV1->pinIndex[i].pinInfo.pinLength = PIN_LENGTH_DEFAULT;
    }
    return pinDbV1;
}

static ResultCode GetPinIndexV1(uint8_t *data, uint32_t dataLen, PinDbV1 *pinDbV1)
{
    if (sizeof(PinInfoV1) * pinDbV1->pinIndexLen != dataLen) {
        LOG_ERROR("bad data length.");
        return RESULT_GENERAL_ERROR;
    }
    pinDbV1->pinIndex = (PinIndexV1 *)Malloc(sizeof(PinIndexV1) * pinDbV1->pinIndexLen);
    if (pinDbV1->pinIndex == NULL) {
        LOG_ERROR("pinIndex malloc fail.");
        return RESULT_NO_MEMORY;
    }
    (void)memset_s(pinDbV1->pinIndex,
        sizeof(PinIndexV1) * pinDbV1->pinIndexLen, 0, sizeof(PinIndexV1) * pinDbV1->pinIndexLen);
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    for (uint32_t i = 0; i < pinDbV1->pinIndexLen; i++) {
        if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(pinDbV1->pinIndex[i].pinInfo)),
            sizeof(pinDbV1->pinIndex[i].pinInfo)) != RESULT_SUCCESS) {
            LOG_ERROR("read pinInfo fail.");
            Free(pinDbV1->pinIndex);
            pinDbV1->pinIndex = NULL;
            return RESULT_BAD_READ;
        }
        if (ReadPinFile((uint8_t *)(&(pinDbV1->pinIndex[i].antiBruteInfo)),
            sizeof(pinDbV1->pinIndex[i].antiBruteInfo),
            pinDbV1->pinIndex[i].pinInfo.templateId, ANTI_BRUTE_SUFFIX) != RESULT_SUCCESS) {
            LOG_ERROR("read AntiBruteInfo fail.");
            GetMaxLockedAntiBruteInfo(&(pinDbV1->pinIndex[i].antiBruteInfo));
            (void)WritePinFile((uint8_t *)(&(pinDbV1->pinIndex[i].antiBruteInfo)),
                sizeof(pinDbV1->pinIndex[i].antiBruteInfo),
                pinDbV1->pinIndex[i].pinInfo.templateId, ANTI_BRUTE_SUFFIX);
        }
    }
    return RESULT_SUCCESS;
}

static bool UnpackPinDbV1(uint8_t *data, uint32_t dataLen, PinDbV1 *pinDbV1)
{
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(pinDbV1->dbVersion)),
        sizeof(pinDbV1->dbVersion)) != RESULT_SUCCESS) {
        LOG_ERROR("read dbVersion fail.");
        return false;
    }
    if (pinDbV1->dbVersion != DB_VERSION_1) {
        LOG_ERROR("read version %{public}u.", pinDbV1->dbVersion);
        return false;
    }
    if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(&(pinDbV1->pinIndexLen)),
        sizeof(pinDbV1->pinIndexLen)) != RESULT_SUCCESS) {
        LOG_ERROR("read pinIndexLen fail.");
        return false;
    }
    if (pinDbV1->pinIndexLen > MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("pinIndexLen too large.");
        return false;
    }
    if (pinDbV1->pinIndexLen == 0) {
        pinDbV1->pinIndex = NULL;
        return true;
    }
    if (GetPinIndexV1(temp, tempLen, pinDbV1) != RESULT_SUCCESS) {
        pinDbV1->pinIndexLen = 0;
        LOG_ERROR("GetPinIndexV1 fail.");
        return false;
    }
    return true;
}

void *GetPinDbV1(uint8_t *data, uint32_t dataLen)
{
    PinDbV1 *pinDbV1 = Malloc(sizeof(PinDbV1));
    if (pinDbV1 == NULL) {
        LOG_ERROR("get pinDbV1 fail");
        return NULL;
    }
    (void)memset_s(pinDbV1, sizeof(PinDbV1), 0, sizeof(PinDbV1));
    if (data == NULL || dataLen == 0) {
        LOG_INFO("no data provided");
        pinDbV1->dbVersion = DB_VERSION_1;
        return pinDbV1;
    }
    if (!UnpackPinDbV1(data, dataLen, pinDbV1)) {
        LOG_ERROR("UnpackPinDbV1 fail");
        FreePinDbV1((void **)(&pinDbV1));
        return NULL;
    }
    return pinDbV1;
}

void FreePinDbV1(void **pinDb)
{
    if (pinDb == NULL) {
        return;
    }
    PinDbV1 *pinDbV1 = *pinDb;
    if (pinDbV1 == NULL) {
        return;
    }
    if (pinDbV1->pinIndex != NULL) {
        Free(pinDbV1->pinIndex);
    }
    Free(*pinDb);
    *pinDb = NULL;
}

static ResultCode WritePinInfo(uint8_t *data, uint32_t dataLen, PinDbV1 *pinDbV1)
{
    if (pinDbV1->pinIndexLen == 0) {
        LOG_INFO("no pin data.");
        return RESULT_SUCCESS;
    }
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    for (uint32_t i = 0; i < pinDbV1->pinIndexLen; i++) {
        if (GetBufFromData((uint8_t *)(&(pinDbV1->pinIndex[i].pinInfo)), sizeof(pinDbV1->pinIndex[i].pinInfo),
            &temp, &tempLen) != RESULT_SUCCESS) {
            LOG_ERROR("write pin info fail.");
            return RESULT_BAD_WRITE;
        }
    }
    return RESULT_SUCCESS;
}

static bool IsPinDbValid(PinDbV1 *pinDb)
{
    if (pinDb == NULL) {
        LOG_ERROR("pinDb is NULL");
        return false;
    }
    if (pinDb->dbVersion != DB_VERSION_1) {
        LOG_ERROR("Db version is %{public}u.", pinDb->dbVersion);
        return false;
    }
    if ((pinDb->pinIndexLen == 0) && (pinDb->pinIndex != NULL)) {
        LOG_ERROR("pinIndexLen is 0");
        return false;
    }
    if ((pinDb->pinIndexLen != 0) && (pinDb->pinIndex == NULL)) {
        LOG_ERROR("pinIndex is NULL");
        return false;
    }
    if (pinDb->pinIndexLen > MAX_CRYPTO_INFO_SIZE) {
        LOG_ERROR("the number of current users exceeds the maximum number of users");
        return false;
    }
    return true;
}

ResultCode WritePinDbV1(void *pinDb)
{
    PinDbV1 *pinDbV1 = pinDb;
    if (!IsPinDbValid(pinDbV1)) {
        LOG_ERROR("get invalid params.");
        return RESULT_BAD_PARAM;
    }
    FileOperator *fileOp = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOp)) {
        LOG_ERROR("fileOp invalid.");
        return RESULT_GENERAL_ERROR;
    }

    uint32_t dataLen = sizeof(PinInfoV1) * pinDbV1->pinIndexLen + sizeof(uint32_t) * PIN_DB_TWO_PARAMS;
    uint8_t *data = Malloc(dataLen);
    if (data == NULL) {
        LOG_ERROR("malloc data fail.");
        return RESULT_GENERAL_ERROR;
    }
    (void)memset_s(data, dataLen, 0, dataLen);
    ResultCode ret = RESULT_BAD_WRITE;
    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    if (GetBufFromData((uint8_t *)(&(pinDbV1->dbVersion)), sizeof(pinDbV1->dbVersion),
        &temp, &tempLen) != RESULT_SUCCESS) {
        LOG_ERROR("get version fail.");
        goto EXIT;
    }

    if (GetBufFromData((uint8_t *)(&(pinDbV1->pinIndexLen)), sizeof(pinDbV1->pinIndexLen),
        &temp, &tempLen) != RESULT_SUCCESS) {
        LOG_ERROR("get index len fail.");
        goto EXIT;
    }
    ret = WritePinInfo(temp, tempLen, pinDbV1);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("WritePinInfo failed.");
        goto EXIT;
    }

    if ((ResultCode)fileOp->writeFile(PIN_INDEX_NAME, data, dataLen) != RESULT_SUCCESS) {
        LOG_ERROR("write_parcel_into_file failed.");
        ret = RESULT_BAD_WRITE;
        goto EXIT;
    }
    LOG_INFO("WritePinDb succ.");
    ret = RESULT_SUCCESS;

EXIT:
    (void)memset_s(data, dataLen, 0, dataLen);
    Free(data);
    return ret;
}