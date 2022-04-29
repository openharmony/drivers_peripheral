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

#include "file_operator.h"
#include <stdio.h>
#include "adaptor_log.h"
#include "defines.h"

static bool IsFileExist(const char *fileName)
{
    if (fileName == NULL) {
        LOG_ERROR("get null file name");
        return false;
    }
    FILE *fileOperator = fopen(fileName, "rb");
    if (fileOperator == NULL) {
        return false;
    }
    (void)fclose(fileOperator);
    return true;
}

static int32_t ReadFile(const char *fileName, uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        LOG_ERROR("get bad params");
        return RESULT_BAD_PARAM;
    }
    FILE *fileOperator = fopen(fileName, "rb");
    if (fileOperator == NULL) {
        LOG_ERROR("open file fail");
        return RESULT_BAD_PARAM;
    }
    size_t readLen = fread(buf, sizeof(uint8_t), len, fileOperator);
    if (readLen != len) {
        LOG_ERROR("read file fail");
        (void)fclose(fileOperator);
        return RESULT_BAD_READ;
    }
    (void)fclose(fileOperator);
    return RESULT_SUCCESS;
}

static int32_t WriteFile(const char *fileName, const uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        LOG_ERROR("get bad params");
        return RESULT_BAD_PARAM;
    }
    FILE *fileOperator = fopen(fileName, "wb");
    if (fileOperator == NULL) {
        LOG_ERROR("open file fail");
        return RESULT_BAD_PARAM;
    }
    size_t writeLen = fwrite(buf, sizeof(uint8_t), len, fileOperator);
    if (writeLen != len) {
        LOG_ERROR("write file fail");
        (void)fclose(fileOperator);
        return RESULT_BAD_WRITE;
    }
    (void)fclose(fileOperator);
    return RESULT_SUCCESS;
}

static int32_t GetFileLen(const char *fileName, uint32_t *len)
{
    if ((fileName == NULL) || (len == NULL)) {
        LOG_ERROR("get bad params");
        return RESULT_BAD_PARAM;
    }
    FILE *fileOperator = fopen(fileName, "rb");
    if (fileOperator == NULL) {
        LOG_ERROR("fopen file fail");
        return RESULT_BAD_PARAM;
    }
    if (fseek(fileOperator, 0L, SEEK_END) != 0) {
        LOG_ERROR("seek file fail");
        (void)fclose(fileOperator);
        return RESULT_GENERAL_ERROR;
    }
    long fileLen = ftell(fileOperator);
    if (fileLen < 0 || fileLen > UINT32_MAX) {
        LOG_ERROR("tell file fail");
        (void)fclose(fileOperator);
        return RESULT_GENERAL_ERROR;
    }
    *len = fileLen;
    (void)fclose(fileOperator);
    return RESULT_SUCCESS;
}

static int32_t DeleteFile(const char *fileName)
{
    if (fileName == NULL) {
        LOG_ERROR("get bad params");
        return RESULT_BAD_PARAM;
    }
    int ret = remove(fileName);
    if (ret != 0) {
        LOG_ERROR("delete file fail");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

FileOperator *GetDefaultFileOperator(void)
{
    static FileOperator fileOperator = {
        .isFileExist = IsFileExist,
        .getFileLen = GetFileLen,
        .readFile = ReadFile,
        .writeFile = WriteFile,
        .deleteFile = DeleteFile,
    };
    return &fileOperator;
}
