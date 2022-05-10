/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef ADAPTOR_FILE_H
#define ADAPTOR_FILE_H

#include <stdbool.h>
#include <stdint.h>

typedef enum FileOperatorType {
    DEFAULT_FILE_OPERATOR,
} FileOperatorType;

typedef struct FileOperator {
    bool (*isFileExist)(const char *fileName);
    int32_t (*getFileLen)(const char *fileName, uint32_t *len);
    int32_t (*readFile)(const char *fileName, uint8_t *buf, uint32_t len);
    int32_t (*writeFile)(const char *fileName, const uint8_t *buf, uint32_t len);
    int32_t (*deleteFile)(const char *fileName);
} FileOperator;

bool IsFileOperatorValid(const FileOperator *fileOperator);
FileOperator *GetFileOperator(const FileOperatorType type);

#endif
