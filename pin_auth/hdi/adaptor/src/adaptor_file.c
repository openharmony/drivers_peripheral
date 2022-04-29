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

#include "adaptor_file.h"
#include <stddef.h>
#include "adaptor_log.h"
#include "file_operator.h"

bool IsFileOperatorValid(const FileOperator *fileOperator)
{
    if (fileOperator == NULL) {
        LOG_ERROR("get null file operator");
        return false;
    }
    if (fileOperator->isFileExist == NULL) {
        LOG_ERROR("get null exist file operator");
        return false;
    }
    if (fileOperator->getFileLen == NULL) {
        LOG_ERROR("get null size file operator");
        return false;
    }
    if (fileOperator->readFile == NULL) {
        LOG_ERROR("get null read file operator");
        return false;
    }
    if (fileOperator->writeFile == NULL) {
        LOG_ERROR("get null write file operator");
        return false;
    }
    if (fileOperator->deleteFile == NULL) {
        LOG_ERROR("get null delete file operator");
        return false;
    }
    return true;
}

FileOperator *GetFileOperator(const FileOperatorType type)
{
    if (type == DEFAULT_FILE_OPERATOR) {
        LOG_INFO("Get default file operator");
        return GetDefaultFileOperator();
    }
    return NULL;
}

