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

#include "pin_db_ops_base.h"

#include <inttypes.h>
#include "securec.h"

#include "adaptor_file.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "file_operator.h"

#define MAX_UINT64_LEN 21

ResultCode GetDataFromBuf(uint8_t **src, uint32_t *srcLen, uint8_t *dest, uint32_t destLen)
{
    if (src == NULL || *src == NULL || srcLen == NULL || dest == NULL || destLen > *srcLen) {
        LOG_ERROR("bad parameter.");
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

ResultCode GetBufFromData(uint8_t *src, uint32_t srcLen, uint8_t **dest, uint32_t *destLen)
{
    if (src == NULL || dest == NULL || *dest == NULL || destLen == NULL || srcLen > *destLen) {
        LOG_ERROR("bad parameter.");
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

ResultCode GenerateFileName(uint64_t templateId, const char *prefix, const char *suffix,
    char *fileName, uint32_t fileNameLen)
{
    if (prefix == NULL || suffix == NULL || fileName == NULL) {
        LOG_ERROR("bad parameter.");
        return RESULT_BAD_PARAM;
    }
    if (memset_s(fileName, fileNameLen, 0, fileNameLen) != EOK) {
        LOG_ERROR("reset fileName fail.");
        return RESULT_PIN_FAIL;
    }
    char *buf = fileName;
    uint32_t bufLen = fileNameLen;
    if (GetBufFromData((uint8_t *)prefix, strlen(prefix), (uint8_t **)(&buf), &bufLen) != RESULT_SUCCESS) {
        LOG_ERROR("copy prefix fail.");
        return RESULT_BAD_COPY;
    }
    char templateIdStr[MAX_UINT64_LEN] = {'\0'};
    if (snprintf_s(templateIdStr, MAX_UINT64_LEN, MAX_UINT64_LEN - 1, "%" PRIu64, templateId) < 0) {
        LOG_ERROR("templateIdStr error.");
        return RESULT_UNKNOWN;
    }
    if (GetBufFromData((uint8_t *)templateIdStr, strlen(templateIdStr),
        (uint8_t **)(&buf), &bufLen) != RESULT_SUCCESS) {
        LOG_ERROR("copy templateIdStr fail.");
        return RESULT_BAD_COPY;
    }
    if (GetBufFromData((uint8_t *)suffix, strlen(suffix), (uint8_t **)&buf, &bufLen) != RESULT_SUCCESS) {
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
ResultCode ReadPinFile(uint8_t *data, uint32_t dataLen, uint64_t templateId, const char *suffix)
{
    if (data == NULL || suffix == NULL) {
        LOG_ERROR("bad parameter.");
        return RESULT_BAD_PARAM;
    }
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
ResultCode WritePinFile(const uint8_t *data, uint32_t dataLen, uint64_t templateId, const char *suffix)
{
    if (data == NULL || suffix == NULL) {
        LOG_ERROR("bad parameter.");
        return RESULT_BAD_PARAM;
    }
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