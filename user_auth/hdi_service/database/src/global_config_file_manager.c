/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "global_config_file_manager.h"

#include "securec.h"

#include "adaptor_file.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "defines.h"
#include "file_manager_utils.h"

#define GLOBAL_CONFIG_INFO "/data/service/el1/public/userauth/globalConfigInfo"
#define VERSION 0

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

IAM_STATIC bool StreamWriteGlobalConfig(Buffer *parcel, GlobalConfigInfo *configInfo)
{
    if (StreamWrite(parcel, &(configInfo->type), sizeof(int32_t)) != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite global config type failed");
        return false;
    }
    switch (configInfo->type) {
        case PIN_EXPIRED_PERIOD:
            if (StreamWrite(parcel, &(configInfo->value.pinExpiredPeriod), sizeof(int64_t)) != RESULT_SUCCESS) {
                LOG_ERROR("StreamWrite pinExpiredPeriod failed");
                return false;
            }
            break;
        case ENABLE_STATUS:
            {
                uint8_t enableStatus = (uint8_t)configInfo->value.enableStatus;
                if (StreamWrite(parcel, &enableStatus, sizeof(uint8_t)) != RESULT_SUCCESS) {
                    LOG_ERROR("StreamWrite enableStatus failed");
                    return false;
                }
                break;
            }
        default:
            LOG_ERROR("globalConfigType not support, type:%{public}d.", configInfo->type);
            return false;
    }
    if (StreamWrite(parcel, &(configInfo->authType), sizeof(uint32_t)) != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite authType failed");
        return false;
    }
    if (StreamWrite(parcel, &(configInfo->userIdNum), sizeof(uint32_t)) != RESULT_SUCCESS ||
        configInfo->userIdNum > MAX_USER) {
        LOG_ERROR("StreamWrite userIdNum failed");
        return false;
    }
    if (configInfo->userIdNum != 0 &&
        StreamWrite(parcel, configInfo->userIds, (sizeof(int32_t) * configInfo->userIdNum)) != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite userIds failed");
        return false;
    }
    return true;
}

IAM_STATIC bool ShouldSkipGlobalConfig(int32_t type) {
    if (type != PIN_EXPIRED_PERIOD && type != ENABLE_STATUS) {
        LOG_ERROR("skip type %{public}d, and delete the globalConfig", type);
        return true;
    }
    return false;
}

ResultCode UpdateGlobalConfigFile(GlobalConfigInfo *globalConfigArray, uint32_t configInfoNum)
{
    LOG_INFO("start");
    if (globalConfigArray == NULL) {
        LOG_ERROR("globalConfigArray is null");
        return RESULT_BAD_PARAM;
    }
    FileOperator *fileOperator = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOperator)) {
        LOG_ERROR("invalid file operation");
        return RESULT_GENERAL_ERROR;
    }

    int32_t configInfoSize = sizeof(uint32_t) * 2 + sizeof(GlobalConfigInfo) * MAX_GLOBAL_CONFIG_NUM;
    Buffer *parcel = CreateBufferBySize(configInfoSize);
    if (parcel == NULL) {
        LOG_ERROR("parcel is null");
        return RESULT_BAD_PARAM;
    }
    uint32_t version = VERSION;
    ResultCode ret = StreamWrite(parcel, &version, sizeof(uint32_t));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite failed");
        DestoryBuffer(parcel);
        return RESULT_GENERAL_ERROR;
    }
    ret = StreamWrite(parcel, &configInfoNum, sizeof(uint32_t));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite failed");
        DestoryBuffer(parcel);
        return RESULT_GENERAL_ERROR;
    }
    for (uint32_t i = 0; i < configInfoNum; i++) {
        if (!ShouldSkipGlobalConfig(globalConfigArray[i].type) &&
            !StreamWriteGlobalConfig(parcel, &globalConfigArray[i])) {
            LOG_ERROR("StreamWriteGlobalConfig failed");
            DestoryBuffer(parcel);
            return RESULT_GENERAL_ERROR;
        }
    }
    // This is for example only. Should be implemented in trusted environment.
    ret = (ResultCode)fileOperator->writeFile(GLOBAL_CONFIG_INFO, parcel->buf, parcel->contentSize);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("write file failed, %{public}u", parcel->contentSize);
    }
    DestoryBuffer(parcel);
    return ret;
}

IAM_STATIC Buffer *ReadGlobalConfigFile(FileOperator *fileOperator)
{
    uint32_t fileSize;
    int32_t ret = fileOperator->getFileLen(GLOBAL_CONFIG_INFO, &fileSize);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("open file failed");
        return NULL;
    }
    Buffer *parcel = CreateBufferBySize(fileSize);
    if (parcel == NULL) {
        LOG_ERROR("parcel create failed");
        return NULL;
    }
    if (fileOperator->readFile(GLOBAL_CONFIG_INFO, parcel->buf, parcel->maxSize) != RESULT_SUCCESS) {
        LOG_ERROR("read failed");
        DestoryBuffer(parcel);
        return NULL;
    }
    parcel->contentSize = fileSize;
    return parcel;
}

IAM_STATIC bool StreamReadGlobalConfig(Buffer *parcel, uint32_t *index, GlobalConfigInfo *configInfo)
{
    if (StreamRead(parcel, index, &(configInfo->type), sizeof(int32_t)) != RESULT_SUCCESS) {
        LOG_ERROR("read globalConfig type failed");
        return false;
    }
    switch (configInfo->type) {
        case PIN_EXPIRED_PERIOD:
            if (StreamRead(parcel, index, &(configInfo->value.pinExpiredPeriod), sizeof(int64_t)) != RESULT_SUCCESS) {
                LOG_ERROR("read pinExpiredPeriod failed");
                return false;
            }
            break;
        case ENABLE_STATUS:
            {
                uint8_t enableStatus = 0;
                if (StreamRead(parcel, index, &enableStatus, sizeof(uint8_t)) != RESULT_SUCCESS) {
                    LOG_ERROR("read enableStatus failed");
                    return false;
                }
                configInfo->value.enableStatus = (bool)enableStatus;
            }
            break;
        default:
            LOG_ERROR("globalConfigType not support, type:%{public}d.", configInfo->type);
            return false;
    }
    if (StreamRead(parcel, index, &(configInfo->authType), sizeof(uint32_t)) != RESULT_SUCCESS) {
        LOG_ERROR("read authType failed");
        return false;
    }
    if (StreamRead(parcel, index, &(configInfo->userIdNum), sizeof(uint32_t)) != RESULT_SUCCESS ||
        configInfo->userIdNum > MAX_USER) {
        LOG_ERROR("read userIdNum failed");
        return false;
    }
    if (configInfo->userIdNum != 0 &&
        StreamRead(parcel, index, configInfo->userIds, (sizeof(int32_t) * configInfo->userIdNum)) != RESULT_SUCCESS) {
        LOG_ERROR("read userIds failed");
        return false;
    }
    return true;
}

IAM_STATIC ResultCode ReadGlobalConfigInfo(Buffer *parcel, GlobalConfigInfo *globalConfigInfo,
    uint32_t *configInfoNum, uint32_t maxNum)
{
    uint32_t index = 0;
    uint32_t version = 0;
    ResultCode result = StreamRead(parcel, &index, &version, sizeof(uint32_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("read version failed");
        return RESULT_GENERAL_ERROR;
    }
    result = StreamRead(parcel, &index, configInfoNum, sizeof(uint32_t));
    if (result != RESULT_SUCCESS || (*configInfoNum) > maxNum) {
        LOG_ERROR("read configInfoNum failed");
        return RESULT_GENERAL_ERROR;
    }
    for (uint32_t i = 0; i < (*configInfoNum); i++) {
        if (!StreamReadGlobalConfig(parcel, &index, &globalConfigInfo[i])) {
            LOG_ERROR("read StreamReadExpiredPeriod failed");
            return RESULT_GENERAL_ERROR;
        }
    }
    return RESULT_SUCCESS;
}

ResultCode LoadGlobalConfigInfo(GlobalConfigInfo *globalConfigArray, uint32_t len, uint32_t *configInfoNum)
{
    LOG_INFO("start");
    if (globalConfigArray == NULL || configInfoNum == NULL) {
        LOG_ERROR("bad param");
        return RESULT_BAD_PARAM;
    }
    (void)memset_s(globalConfigArray, sizeof(GlobalConfigInfo) * len, 0, sizeof(GlobalConfigInfo) * len);
    *configInfoNum = 0;
    FileOperator *fileOperator = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOperator)) {
        LOG_ERROR("invalid file operation");
        return RESULT_GENERAL_ERROR;
    }
    if (!fileOperator->isFileExist(GLOBAL_CONFIG_INFO)) {
        LOG_ERROR("file is not exist");
        *configInfoNum = 0;
        return RESULT_SUCCESS;
    }
    Buffer *parcel = ReadGlobalConfigFile(fileOperator);
    if (parcel == NULL) {
        LOG_ERROR("ReadGlobalConfigFile failed");
        return RESULT_GENERAL_ERROR;
    }
    ResultCode ret = ReadGlobalConfigInfo(parcel, globalConfigArray, configInfoNum, len);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ReadGlobalConfigInfo failed");
        DestoryBuffer(parcel);
        (void)memset_s(globalConfigArray, sizeof(GlobalConfigInfo) * len, 0, sizeof(GlobalConfigInfo) * len);
        *configInfoNum = 0;
        return ret;
    }
    DestoryBuffer(parcel);
    return RESULT_SUCCESS;
}
