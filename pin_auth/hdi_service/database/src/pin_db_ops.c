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

#include "pin_db_ops.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "file_operator.h"

#include "pin_db_ops.h"

#define DB_VERSION_CURRENT DB_VERSION_1

typedef struct PinDbOps {
    void *(*getDb)(uint8_t *data, uint32_t dataLen);
    void *(*updateDb)(void *preDb);
    void (*freeDb)(void **pinDb);
} PinDbOps;

PinDbOps g_pinDbOps[] = {
    {
        .getDb = GetPinDbV0,
        .updateDb = NULL,
        .freeDb = FreePinDbV0,
    },
    {
        .getDb = GetPinDbV1,
        .updateDb = UpdatePinDbFrom0To1,
        .freeDb = FreePinDbV1,
    },
};

static ResultCode GetVersion(uint8_t *data, uint32_t dataLen, uint32_t *version)
{
    if (data == NULL || dataLen == 0) {
        *version = DB_VERSION_CURRENT;
        LOG_INFO("db file not exist current version:%{public}u.", DB_VERSION_CURRENT);
        return RESULT_SUCCESS;
    }

    uint8_t *temp = data;
    uint32_t tempLen = dataLen;
    if (GetDataFromBuf(&temp, &tempLen, (uint8_t *)(version), sizeof(uint32_t)) != RESULT_SUCCESS) {
        LOG_ERROR("read version fail.");
        return RESULT_GENERAL_ERROR;
    }

    LOG_INFO("read version:%{public}u, current version:%{public}u.", *version, DB_VERSION_CURRENT);
    return RESULT_SUCCESS;
}

static void *LoadAndUpdatePinDb(uint8_t *data, uint32_t dataLen)
{
    uint32_t version = DB_VERSION_CURRENT;
    if (GetVersion(data, dataLen, &version) != RESULT_SUCCESS) {
        LOG_ERROR("get version fail.");
        return NULL;
    }
    if (version > DB_VERSION_CURRENT) {
        LOG_ERROR("read version invalid.");
        return NULL;
    }
    void *pinDb = g_pinDbOps[version].getDb(data, dataLen);
    if (pinDb == NULL) {
        LOG_ERROR("get db fail.");
        return NULL;
    }
    if (version == DB_VERSION_CURRENT) {
        return pinDb;
    }
    while (version < DB_VERSION_CURRENT) {
        void *pinDbPre = pinDb;
        pinDb = g_pinDbOps[version + 1].updateDb(pinDbPre);
        g_pinDbOps[version].freeDb(&pinDbPre);
        if (pinDb == NULL) {
            LOG_ERROR("update db fail.");
            return NULL;
        }
        version++;
    }
    if (WritePinDb(pinDb) != RESULT_SUCCESS) {
        LOG_ERROR("WritePinDb fail.");
        g_pinDbOps[version].freeDb(&pinDb);
        return NULL;
    }

    return pinDb;
}

static ResultCode ReadPinDbData(uint8_t **data, uint32_t *dataLen)
{
    FileOperator *fileOp = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOp)) {
        LOG_ERROR("fileOp invalid.");
        return RESULT_GENERAL_ERROR;
    }

    if (!fileOp->isFileExist(PIN_INDEX_NAME)) {
        LOG_INFO("pin file not found.");
        *data = NULL;
        *dataLen = 0;
        return RESULT_SUCCESS;
    }

    ResultCode ret = (ResultCode)(fileOp->getFileLen(PIN_INDEX_NAME, dataLen));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("getFileLen failed");
        return RESULT_BAD_READ;
    }

    *data = Malloc(*dataLen);
    if ((*data) == NULL) {
        LOG_ERROR("malloc data failed");
        return RESULT_GENERAL_ERROR;
    }
    ret = (ResultCode)fileOp->readFile(PIN_INDEX_NAME, *data, *dataLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("readFile failed.");
        (void)memset_s(*data, *dataLen, 0, *dataLen);
        Free(*data);
        *data = NULL;
        *dataLen = 0;
        return RESULT_BAD_READ;
    }
    return RESULT_SUCCESS;
}

PinDbV1 *ReadPinDb(void)
{
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    ResultCode ret = ReadPinDbData(&data, &dataLen);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ReadPinDbData fail.");
        return NULL;
    }
    PinDbV1 *pinDb = LoadAndUpdatePinDb(data, dataLen);
    if (data != NULL) {
        (void)memset_s(data, dataLen, 0, dataLen);
        Free(data);
    }
    if (pinDb == NULL) {
        LOG_ERROR("LoadAndUpdatePinDb fail.");
    }

    return pinDb;
}

ResultCode WritePinDb(PinDbV1 *pinDbV1)
{
    return WritePinDbV1((void *)pinDbV1);
}

void FreePinDb(PinDbV1 **pinDbV1)
{
    FreePinDbV1((void **)(pinDbV1));
}
