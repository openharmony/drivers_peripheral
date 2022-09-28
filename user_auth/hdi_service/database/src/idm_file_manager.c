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

#include "idm_file_manager.h"

#include "securec.h"

#include "adaptor_file.h"
#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "buffer.h"
#include "idm_common.h"

#define IDM_USER_INFO "/data/service/el1/public/userauth/userinfo"
#define MAX_BUFFER_LEN 512000
#define DEFAULT_EXPANSION_RATIO 2
#define PRE_APPLY_LEN 2048
#define VERSION 0

static uint32_t GetRemainSpace(const Buffer *object)
{
    return object->maxSize - object->contentSize;
}

static uint8_t *GetStreamAddress(const Buffer *object)
{
    return object->buf + object->contentSize;
}

static ResultCode CapacityExpansion(Buffer *object, uint32_t targetCapacity)
{
    if (!IsBufferValid(object) || object->maxSize > MAX_BUFFER_LEN / DEFAULT_EXPANSION_RATIO) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    uint32_t targetSize = object->maxSize;
    while (targetSize < targetCapacity && targetSize <= MAX_BUFFER_LEN / DEFAULT_EXPANSION_RATIO) {
        targetSize = targetSize * DEFAULT_EXPANSION_RATIO;
    }
    if (targetSize < targetCapacity) {
        LOG_ERROR("target capacity can not reach");
        return RESULT_BAD_PARAM;
    }
    uint8_t *buf = Malloc(targetSize);
    if (buf == NULL) {
        LOG_ERROR("malloc failed");
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(buf, targetSize, object->buf, object->contentSize) != EOK) {
        LOG_ERROR("copy failed");
        Free(buf);
        return RESULT_NO_MEMORY;
    }
    Free(object->buf);
    object->buf = buf;
    object->maxSize = targetSize;
    return RESULT_SUCCESS;
}

static ResultCode StreamWrite(Buffer *parcel, void *from, uint32_t size)
{
    if (!IsBufferValid(parcel) || from == NULL) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    if (GetRemainSpace(parcel) < size) {
        ResultCode result = CapacityExpansion(parcel, size);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("CapacityExpansion failed");
            return result;
        }
    }
    if (memcpy_s(GetStreamAddress(parcel), GetRemainSpace(parcel), from, size) != EOK) {
        LOG_ERROR("copy failed");
        return RESULT_NO_MEMORY;
    }
    parcel->contentSize += size;
    return RESULT_SUCCESS;
}

static ResultCode StreamWriteEnrolledInfo(Buffer *parcel, LinkedList *enrolledList)
{
    if (!IsBufferValid(parcel) || enrolledList == NULL) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    uint32_t size = enrolledList->getSize(enrolledList);
    ResultCode ret = StreamWrite(parcel, &size, sizeof(uint32_t));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite failed");
        return ret;
    }
    LinkedListNode *temp = enrolledList->head;
    for (uint32_t i = 0; i < size; ++i) {
        if (temp == NULL) {
            LOG_ERROR("listSize is invalid");
            return RESULT_BAD_PARAM;
        }
        if (StreamWrite(parcel, temp->data, sizeof(EnrolledInfoHal)) != RESULT_SUCCESS) {
            LOG_ERROR("enrolledInfo streamWrite failed");
            return RESULT_GENERAL_ERROR;
        }
        temp = temp->next;
    }
    return RESULT_SUCCESS;
}

static ResultCode StreamWriteCredentialList(Buffer *parcel, LinkedList *credentialList)
{
    if (!IsBufferValid(parcel) || credentialList == NULL) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    uint32_t size = credentialList->getSize(credentialList);
    ResultCode ret = StreamWrite(parcel, &size, sizeof(uint32_t));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite failed");
        return ret;
    }
    LinkedListNode *temp = credentialList->head;
    for (uint32_t i = 0; i < size; ++i) {
        if (temp == NULL) {
            LOG_ERROR("listSize is invalid");
            return RESULT_BAD_PARAM;
        }
        if (StreamWrite(parcel, temp->data, sizeof(CredentialInfoHal)) != RESULT_SUCCESS) {
            LOG_ERROR("credentialInfo streamWrite failed");
            return RESULT_GENERAL_ERROR;
        }
        temp = temp->next;
    }
    return RESULT_SUCCESS;
}

static ResultCode StreamWriteUserInfo(Buffer *parcel, UserInfo *userInfo)
{
    if (!IsBufferValid(parcel) || userInfo == NULL) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    ResultCode result;
    result = StreamWrite(parcel, &userInfo->userId, sizeof(int32_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("userId streamWrite failed");
        return result;
    }
    result = StreamWrite(parcel, &userInfo->secUid, sizeof(uint64_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("secUid streamWrite failed");
        return result;
    }
    result = StreamWriteCredentialList(parcel, userInfo->credentialInfoList);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("credentialInfoList streamWrite failed");
        return result;
    }
    result = StreamWriteEnrolledInfo(parcel, userInfo->enrolledInfoList);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("enrolledInfoList streamWrite failed");
        return result;
    }
    return RESULT_SUCCESS;
}

ResultCode UpdateFileInfo(LinkedList *userInfoList)
{
    LOG_INFO("start");
    if (userInfoList == NULL) {
        LOG_ERROR("userInfo list is null");
        return RESULT_BAD_PARAM;
    }
    Buffer *parcel = CreateBufferBySize(PRE_APPLY_LEN);
    if (parcel == NULL) {
        LOG_ERROR("parcel is null");
        return RESULT_BAD_PARAM;
    }
    uint32_t version = VERSION;
    ResultCode ret = StreamWrite(parcel, &version, sizeof(uint32_t));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite failed");
        goto EXIT;
    }

    uint32_t size = userInfoList->getSize(userInfoList);
    ret = StreamWrite(parcel, &size, sizeof(uint32_t));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("StreamWrite failed");
        goto EXIT;
    }

    LinkedListNode *temp = userInfoList->head;
    for (uint32_t i = 0; i < size; ++i) {
        if (temp == NULL || temp->data == NULL) {
            LOG_ERROR("temp is null");
            ret = RESULT_NEED_INIT;
            goto EXIT;
        }
        if (StreamWriteUserInfo(parcel, (UserInfo *)temp->data) != RESULT_SUCCESS) {
            LOG_ERROR("StreamWriteUserInfo failed");
            ret = RESULT_GENERAL_ERROR;
            goto EXIT;
        }
        temp = temp->next;
    }

    FileOperator *fileOperator = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOperator)) {
        LOG_ERROR("invalid file operation");
        ret = RESULT_BAD_WRITE;
        goto EXIT;
    }

    // This is for example only. Should be implemented in trusted environment.
    ret = fileOperator->writeFile(IDM_USER_INFO, parcel->buf, parcel->contentSize);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("write file failed, %{public}u", parcel->contentSize);
    }

EXIT:
    DestoryBuffer(parcel);
    return ret;
}

static ResultCode StreamRead(Buffer *parcel, uint32_t *index, void *to, uint32_t size)
{
    if (parcel->contentSize <= *index || parcel->contentSize - *index < size) {
        LOG_ERROR("the buffer length is insufficient");
        return RESULT_BAD_PARAM;
    }
    if (memcpy_s(to, size, parcel->buf + *index, size) != EOK) {
        LOG_ERROR("copy failed");
        return RESULT_NO_MEMORY;
    }
    *index += size;
    return RESULT_SUCCESS;
}

static ResultCode StreamReadCredentialList(Buffer *parcel, uint32_t *index, LinkedList *credentialList)
{
    if (!IsBufferValid(parcel) || credentialList == NULL) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    uint32_t credentialNum;
    ResultCode result = StreamRead(parcel, index, &credentialNum, sizeof(uint32_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("stream read failed");
        return RESULT_BAD_READ;
    }
    if (credentialNum > MAX_CREDENTIAL) {
        LOG_ERROR("Bad credential num");
        return RESULT_BAD_READ;
    }
    for (uint32_t i = 0; i < credentialNum; ++i) {
        CredentialInfoHal *credentialInfo = Malloc(sizeof(CredentialInfoHal));
        if (credentialInfo == NULL) {
            LOG_ERROR("credentialInfo malloc failed");
            return RESULT_NO_MEMORY;
        }
        result = StreamRead(parcel, index, credentialInfo, sizeof(CredentialInfoHal));
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("StreamRead failed");
            Free(credentialInfo);
            return result;
        }
        result = credentialList->insert(credentialList, credentialInfo);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("credentialList insert failed");
            Free(credentialInfo);
            return result;
        }
    }
    return RESULT_SUCCESS;
}

static ResultCode StreamReadEnrolledList(Buffer *parcel, uint32_t *index, LinkedList *enrolledList)
{
    if (!IsBufferValid(parcel) || enrolledList == NULL) {
        LOG_ERROR("invalid params");
        return RESULT_BAD_PARAM;
    }
    uint32_t enrolledNum;
    ResultCode result = StreamRead(parcel, index, &enrolledNum, sizeof(uint32_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("stream read failed");
        return RESULT_BAD_READ;
    }
    if (enrolledNum > MAX_CREDENTIAL) {
        LOG_ERROR("bad enrolled num");
        return RESULT_BAD_READ;
    }
    for (uint32_t i = 0; i < enrolledNum; ++i) {
        EnrolledInfoHal *enrolledInfo = Malloc(sizeof(EnrolledInfoHal));
        if (enrolledInfo == NULL) {
            LOG_ERROR("enrolledInfo malloc failed");
            return RESULT_NO_MEMORY;
        }
        result = StreamRead(parcel, index, enrolledInfo, sizeof(EnrolledInfoHal));
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("StreamRead failed");
            Free(enrolledInfo);
            return result;
        }
        result = enrolledList->insert(enrolledList, enrolledInfo);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("enrolledList insert failed");
            Free(enrolledInfo);
            return result;
        }
    }
    return RESULT_SUCCESS;
}

static ResultCode StreamReadUserInfo(Buffer *parcel, uint32_t *index, UserInfo *userInfo)
{
    ResultCode result = StreamRead(parcel, index, &userInfo->userId, sizeof(int32_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("Read userId failed");
        return RESULT_GENERAL_ERROR;
    }
    result = StreamRead(parcel, index, &userInfo->secUid, sizeof(uint64_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("Read secUid failed");
        return RESULT_GENERAL_ERROR;
    }
    result = StreamReadCredentialList(parcel, index, userInfo->credentialInfoList);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("Read credentialInfoList failed");
        return RESULT_GENERAL_ERROR;
    }
    result = StreamReadEnrolledList(parcel, index, userInfo->enrolledInfoList);
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("Read enrolledInfoList failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

static Buffer *ReadFileInfo()
{
    FileOperator *fileOperator = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOperator)) {
        LOG_ERROR("invalid file operation");
        return NULL;
    }
    uint32_t fileSize;
    int32_t ret = fileOperator->getFileLen(IDM_USER_INFO, &fileSize);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("open file failed");
        return NULL;
    }
    Buffer *parcel = CreateBufferBySize(fileSize);
    if (parcel == NULL) {
        LOG_ERROR("parcel create failed");
        return NULL;
    }
    if (fileOperator->readFile(IDM_USER_INFO, parcel->buf, parcel->maxSize) != RESULT_SUCCESS) {
        LOG_ERROR("read failed");
        DestoryBuffer(parcel);
        return NULL;
    }
    parcel->contentSize = fileSize;
    return parcel;
}

static bool StreamReadFileInfo(Buffer *parcel, LinkedList *userInfoList)
{
    uint32_t index = 0;
    uint32_t userNum;
    uint32_t version;
    ResultCode result = StreamRead(parcel, &index, &version, sizeof(uint32_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("read version failed");
        return false;
    }
    result = StreamRead(parcel, &index, &userNum, sizeof(uint32_t));
    if (result != RESULT_SUCCESS) {
        LOG_ERROR("read userNum failed");
        return false;
    }
    if (userNum > MAX_USER) {
        LOG_ERROR("bad user num");
        return false;
    }
    for (uint32_t i = 0; i < userNum; ++i) {
        UserInfo *userInfo = InitUserInfoNode();
        if (userInfo == NULL) {
            LOG_ERROR("userInfoNode init failed");
            return false;
        }
        result = StreamReadUserInfo(parcel, &index, userInfo);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("StreamRead failed");
            DestroyUserInfoNode(userInfo);
            return false;
        }
        result = userInfoList->insert(userInfoList, userInfo);
        if (result != RESULT_SUCCESS) {
            LOG_ERROR("userInfoList insert failed");
            DestroyUserInfoNode(userInfo);
            return false;
        }
    }
    return true;
}

LinkedList *LoadFileInfo(void)
{
    LOG_INFO("start");
    FileOperator *fileOperator = GetFileOperator(DEFAULT_FILE_OPERATOR);
    if (!IsFileOperatorValid(fileOperator)) {
        LOG_ERROR("invalid file operation");
        return NULL;
    }
    if (!fileOperator->isFileExist(IDM_USER_INFO)) {
        LOG_ERROR("file is not exist");
        return CreateLinkedList(DestroyUserInfoNode);
    }
    Buffer *parcel = ReadFileInfo();
    if (parcel == NULL) {
        LOG_ERROR("read file info failed");
        return NULL;
    }

    LinkedList *userInfoList = CreateLinkedList(DestroyUserInfoNode);
    if (userInfoList == NULL) {
        LOG_ERROR("list create failed");
        DestoryBuffer(parcel);
        return NULL;
    }
    if (!StreamReadFileInfo(parcel, userInfoList)) {
        LOG_ERROR("StreamReadFileInfo failed");
        DestoryBuffer(parcel);
        DestroyLinkedList(userInfoList);
        return NULL;
    }
    DestoryBuffer(parcel);
    return userInfoList;
}