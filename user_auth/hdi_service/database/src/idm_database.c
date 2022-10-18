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

#include "idm_database.h"

#include "securec.h"

#include "adaptor_algorithm.h"
#include "adaptor_log.h"
#include "idm_file_manager.h"

#define MAX_DUPLICATE_CHECK 100
#define PRE_APPLY_NUM 5
#define MEM_GROWTH_FACTOR 2
#define MAX_CREDENTIAL_RETURN 5000

// Caches IDM user information.
static LinkedList *g_userInfoList = NULL;

// Caches the current user to reduce the number of user list traversal times.
static UserInfo *g_currentUser = NULL;

typedef bool (*DuplicateCheckFunc)(LinkedList *collection, uint64_t value);

static UserInfo *QueryUserInfo(int32_t userId);
static ResultCode GetAllEnrolledInfoFromUser(UserInfo *userInfo, EnrolledInfoHal **enrolledInfos, uint32_t *num);
static ResultCode DeleteUser(int32_t userId);
static CredentialInfoHal *QueryCredentialById(uint64_t credentialId, LinkedList *credentialList);
static CredentialInfoHal *QueryCredentialByAuthType(uint32_t authType, LinkedList *credentialList);
static bool MatchCredentialById(const void *data, const void *condition);
static ResultCode GenerateDeduplicateUint64(LinkedList *collection, uint64_t *destValue, DuplicateCheckFunc func);

ResultCode InitUserInfoList(void)
{
    if (g_userInfoList != NULL) {
        DestroyUserInfoList();
        g_userInfoList = NULL;
    }
    g_userInfoList = LoadFileInfo();
    if (g_userInfoList == NULL) {
        LOG_ERROR("load file info failed");
        return RESULT_NEED_INIT;
    }
    LOG_INFO("InitUserInfoList done");
    return RESULT_SUCCESS;
}

void DestroyUserInfoList(void)
{
    DestroyLinkedList(g_userInfoList);
    g_userInfoList = NULL;
}

static bool MatchUserInfo(const void *data, const void *condition)
{
    if (data == NULL || condition == NULL) {
        LOG_ERROR("please check invalid node");
        return false;
    }
    UserInfo *userInfo = (UserInfo *)data;
    int32_t userId = *(int32_t *)condition;
    if (userInfo->userId == userId) {
        return true;
    }
    return false;
}

static bool IsUserInfoValid(UserInfo *userInfo)
{
    if (userInfo == NULL) {
        LOG_ERROR("userInfo is null");
        return false;
    }
    if (userInfo->credentialInfoList == NULL) {
        LOG_ERROR("credentialInfoList is null");
        return false;
    }
    if (userInfo->enrolledInfoList == NULL) {
        LOG_ERROR("enrolledInfoList is null");
        return false;
    }
    return true;
}

ResultCode GetSecureUid(int32_t userId, uint64_t *secUid)
{
    if (secUid == NULL) {
        LOG_ERROR("secUid is null");
        return RESULT_BAD_PARAM;
    }
    UserInfo *user = QueryUserInfo(userId);
    if (user == NULL) {
        LOG_ERROR("can't find this user");
        return RESULT_NOT_FOUND;
    }
    *secUid = user->secUid;
    return RESULT_SUCCESS;
}

ResultCode GetEnrolledInfoAuthType(int32_t userId, uint32_t authType, EnrolledInfoHal *enrolledInfo)
{
    if (enrolledInfo == NULL) {
        LOG_ERROR("enrolledInfo is null");
        return RESULT_BAD_PARAM;
    }
    UserInfo *user = QueryUserInfo(userId);
    if (user == NULL) {
        LOG_ERROR("can't find this user");
        return RESULT_NOT_FOUND;
    }
    if (user->enrolledInfoList == NULL) {
        LOG_ERROR("enrolledInfoList is null");
        return RESULT_UNKNOWN;
    }

    LinkedListNode *temp = user->enrolledInfoList->head;
    while (temp != NULL) {
        EnrolledInfoHal *nodeInfo = temp->data;
        if (nodeInfo != NULL && nodeInfo->authType == authType) {
            *enrolledInfo = *nodeInfo;
            return RESULT_SUCCESS;
        }
        temp = temp->next;
    }

    return RESULT_NOT_FOUND;
}

ResultCode GetEnrolledInfo(int32_t userId, EnrolledInfoHal **enrolledInfos, uint32_t *num)
{
    if (enrolledInfos == NULL || num == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    UserInfo *user = QueryUserInfo(userId);
    if (!IsUserInfoValid(user)) {
        LOG_ERROR("can't find this user");
        return RESULT_NOT_FOUND;
    }
    return GetAllEnrolledInfoFromUser(user, enrolledInfos, num);
}

ResultCode DeleteUserInfo(int32_t userId, LinkedList **creds)
{
    if (creds == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    UserInfo *user = QueryUserInfo(userId);
    if (!IsUserInfoValid(user)) {
        LOG_ERROR("can't find this user");
        return RESULT_NOT_FOUND;
    }
    CredentialCondition condition = {};
    SetCredentialConditionUserId(&condition, userId);
    *creds = QueryCredentialLimit(&condition);
    if (*creds == NULL) {
        LOG_ERROR("query credential failed");
        return RESULT_UNKNOWN;
    }
    g_currentUser = NULL;

    ResultCode ret = DeleteUser(userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("deleteUser failed");
        DestroyLinkedList(*creds);
        *creds = NULL;
        return ret;
    }
    ret = UpdateFileInfo(g_userInfoList);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("update file info failed");
        DestroyLinkedList(*creds);
        *creds = NULL;
        return ret;
    }
    return ret;
}

static UserInfo *QueryUserInfo(int32_t userId)
{
    UserInfo *user = g_currentUser;
    if (user != NULL && user->userId == userId) {
        return user;
    }
    if (g_userInfoList == NULL) {
        return NULL;
    }
    LinkedListNode *temp = g_userInfoList->head;
    while (temp != NULL) {
        user = (UserInfo *)temp->data;
        if (user != NULL && user->userId == userId) {
            break;
        }
        temp = temp->next;
    }
    if (temp == NULL) {
        return NULL;
    }
    if (IsUserInfoValid(user)) {
        g_currentUser = user;
        return user;
    }
    return NULL;
}

static ResultCode GetAllEnrolledInfoFromUser(UserInfo *userInfo, EnrolledInfoHal **enrolledInfos, uint32_t *num)
{
    LinkedList *enrolledInfoList = userInfo->enrolledInfoList;
    uint32_t size = enrolledInfoList->getSize(enrolledInfoList);
    *enrolledInfos = Malloc(sizeof(EnrolledInfoHal) * size);
    if (*enrolledInfos == NULL) {
        LOG_ERROR("enrolledInfos malloc failed");
        return RESULT_NO_MEMORY;
    }
    (void)memset_s(*enrolledInfos, sizeof(EnrolledInfoHal) * size, 0, sizeof(EnrolledInfoHal) * size);
    LinkedListNode *temp = enrolledInfoList->head;
    ResultCode result = RESULT_SUCCESS;
    for (*num = 0; *num < size; (*num)++) {
        if (temp == NULL) {
            LOG_ERROR("temp node is null, something wrong");
            result = RESULT_BAD_PARAM;
            goto EXIT;
        }
        EnrolledInfoHal *tempInfo = (EnrolledInfoHal *)temp->data;
        if (memcpy_s(*enrolledInfos + *num, sizeof(EnrolledInfoHal) * (size - *num),
            tempInfo, sizeof(EnrolledInfoHal)) != EOK) {
            LOG_ERROR("copy the %u information failed", *num);
            result = RESULT_NO_MEMORY;
            goto EXIT;
        }
        temp = temp->next;
    }

EXIT:
    if (result != RESULT_SUCCESS) {
        Free(*enrolledInfos);
        *enrolledInfos = NULL;
        *num = 0;
    }
    return result;
}

static bool IsSecureUidDuplicate(LinkedList *userInfoList, uint64_t secureUid)
{
    if (userInfoList == NULL) {
        LOG_ERROR("the user list is empty, and the branch is abnormal");
        return false;
    }

    LinkedListNode *temp = userInfoList->head;
    UserInfo *userInfo = NULL;
    while (temp != NULL) {
        userInfo = (UserInfo *)temp->data;
        if (userInfo != NULL && userInfo->secUid == secureUid) {
            return true;
        }
        temp = temp->next;
    }

    return false;
}

static UserInfo *CreateUser(int32_t userId)
{
    UserInfo *user = InitUserInfoNode();
    if (!IsUserInfoValid(user)) {
        LOG_ERROR("user is invalid");
        DestroyUserInfoNode(user);
        return NULL;
    }
    user->userId = userId;
    ResultCode ret = GenerateDeduplicateUint64(g_userInfoList, &user->secUid, IsSecureUidDuplicate);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("generate secureUid failed");
        DestroyUserInfoNode(user);
        return NULL;
    }
    return user;
}

static ResultCode DeleteUser(int32_t userId)
{
    if (g_userInfoList == NULL) {
        return RESULT_BAD_PARAM;
    }
    return g_userInfoList->remove(g_userInfoList, &userId, MatchUserInfo, true);
}

static bool IsCredentialIdDuplicate(LinkedList *userInfoList, uint64_t credentialId)
{
    (void)userInfoList;
    CredentialCondition condition = {};
    SetCredentialConditionCredentialId(&condition, credentialId);
    LinkedList *credList = QueryCredentialLimit(&condition);
    if (credList == NULL) {
        LOG_ERROR("query failed");
        return true;
    }
    if (credList->getSize(credList) != 0) {
        LOG_ERROR("duplicate credential id");
        DestroyLinkedList(credList);
        return true;
    }
    DestroyLinkedList(credList);
    return false;
}

static bool IsEnrolledIdDuplicate(LinkedList *enrolledList, uint64_t enrolledId)
{
    LinkedListNode *temp = enrolledList->head;
    EnrolledInfoHal *enrolledInfo = NULL;
    while (temp != NULL) {
        enrolledInfo = (EnrolledInfoHal *)temp->data;
        if (enrolledInfo != NULL && enrolledInfo->enrolledId == enrolledId) {
            return true;
        }
        temp = temp->next;
    }

    return false;
}

static ResultCode GenerateDeduplicateUint64(LinkedList *collection, uint64_t *destValue, DuplicateCheckFunc func)
{
    if (collection == NULL || destValue == NULL || func == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }

    for (uint32_t i = 0; i < MAX_DUPLICATE_CHECK; ++i) {
        uint64_t tempRandom;
        if (SecureRandom((uint8_t *)&tempRandom, sizeof(uint64_t)) != RESULT_SUCCESS) {
            LOG_ERROR("get random failed");
            return RESULT_GENERAL_ERROR;
        }
        if (!func(collection, tempRandom)) {
            *destValue = tempRandom;
            return RESULT_SUCCESS;
        }
    }

    LOG_ERROR("generate random failed");
    return RESULT_GENERAL_ERROR;
}

static ResultCode UpdateEnrolledId(LinkedList *enrolledList, uint32_t authType)
{
    LinkedListNode *temp = enrolledList->head;
    EnrolledInfoHal *enrolledInfo = NULL;
    while (temp != NULL) {
        EnrolledInfoHal *nodeData = (EnrolledInfoHal *)temp->data;
        if (nodeData != NULL && nodeData->authType == authType) {
            enrolledInfo = nodeData;
            break;
        }
        temp = temp->next;
    }

    if (enrolledInfo != NULL) {
        return GenerateDeduplicateUint64(enrolledList, &enrolledInfo->enrolledId, IsEnrolledIdDuplicate);
    }

    enrolledInfo = Malloc(sizeof(EnrolledInfoHal));
    if (enrolledInfo == NULL) {
        LOG_ERROR("enrolledInfo malloc failed");
        return RESULT_NO_MEMORY;
    }
    enrolledInfo->authType = authType;
    ResultCode ret = GenerateDeduplicateUint64(enrolledList, &enrolledInfo->enrolledId, IsEnrolledIdDuplicate);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("generate enrolledId failed");
        Free(enrolledInfo);
        return ret;
    }
    ret = enrolledList->insert(enrolledList, enrolledInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("enrolledInfo insert failed");
        Free(enrolledInfo);
    }
    return ret;
}

static ResultCode AddCredentialToUser(UserInfo *user, CredentialInfoHal *credentialInfo)
{
    if (g_userInfoList == NULL) {
        LOG_ERROR("g_userInfoList is uninitialized");
        return RESULT_NEED_INIT;
    }
    LinkedList *credentialList = user->credentialInfoList;
    LinkedList *enrolledList = user->enrolledInfoList;
    if (credentialList->getSize(credentialList) >= MAX_CREDENTIAL) {
        LOG_ERROR("the number of credentials reaches the maximum");
        return RESULT_EXCEED_LIMIT;
    }

    ResultCode ret = UpdateEnrolledId(enrolledList, credentialInfo->authType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("update enrolledId failed");
        return ret;
    }
    ret = GenerateDeduplicateUint64(g_userInfoList, &credentialInfo->credentialId, IsCredentialIdDuplicate);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GenerateDeduplicateUint64 failed");
        return ret;
    }
    CredentialInfoHal *credential = Malloc(sizeof(CredentialInfoHal));
    if (credential == NULL) {
        LOG_ERROR("credential malloc failed");
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(credential, sizeof(CredentialInfoHal), credentialInfo, sizeof(CredentialInfoHal)) != EOK) {
        LOG_ERROR("credential copy failed");
        Free(credential);
        return RESULT_BAD_COPY;
    }
    ret = credentialList->insert(credentialList, credential);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("insert credential failed");
        Free(credential);
    }
    return ret;
}

static ResultCode AddUser(int32_t userId, CredentialInfoHal *credentialInfo)
{
    if (g_userInfoList == NULL) {
        LOG_ERROR("please init");
        return RESULT_NEED_INIT;
    }
    if (g_userInfoList->getSize(g_userInfoList) >= MAX_USER) {
        LOG_ERROR("the number of users reaches the maximum");
        return RESULT_EXCEED_LIMIT;
    }

    UserInfo *user = QueryUserInfo(userId);
    if (user != NULL) {
        LOG_ERROR("Please check pin");
        return RESULT_BAD_PARAM;
    }

    user = CreateUser(userId);
    if (user == NULL) {
        LOG_ERROR("create user failed");
        return RESULT_UNKNOWN;
    }

    ResultCode ret = AddCredentialToUser(user, credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("add credential to user failed");
        goto FAIL;
    }

    ret = g_userInfoList->insert(g_userInfoList, user);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("insert failed");
        goto FAIL;
    }
    return ret;

FAIL:
    DestroyUserInfoNode(user);
    return ret;
}

ResultCode AddCredentialInfo(int32_t userId, CredentialInfoHal *credentialInfo)
{
    if (credentialInfo == NULL) {
        LOG_ERROR("credentialInfo is null");
        return RESULT_BAD_PARAM;
    }
    UserInfo *user = QueryUserInfo(userId);
    if (user == NULL && credentialInfo->authType == PIN_AUTH) {
        ResultCode ret = AddUser(userId, credentialInfo);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("add user failed");
            return ret;
        }
        ret = UpdateFileInfo(g_userInfoList);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("updateFileInfo failed");
        }
        return ret;
    }
    if (user == NULL) {
        LOG_ERROR("user is null");
        return RESULT_BAD_PARAM;
    }
    if (credentialInfo->authType == PIN_AUTH) {
        CredentialCondition condition = {};
        SetCredentialConditionAuthType(&condition, PIN_AUTH);
        SetCredentialConditionUserId(&condition, userId);
        LinkedList *credList = QueryCredentialLimit(&condition);
        if (credList == NULL) {
            LOG_ERROR("query credential failed");
            return RESULT_UNKNOWN;
        }
        if (credList->getSize(credList) != 0) {
            LOG_ERROR("double pin");
            DestroyLinkedList(credList);
            return RESULT_BAD_PARAM;
        }
        DestroyLinkedList(credList);
    }
    ResultCode ret = AddCredentialToUser(user, credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("add credential to user failed");
        return ret;
    }
    ret = UpdateFileInfo(g_userInfoList);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("updateFileInfo failed");
    }
    return ret;
}

static bool MatchCredentialById(const void *data, const void *condition)
{
    if (data == NULL || condition == NULL) {
        return false;
    }
    CredentialInfoHal *credentialInfo = (CredentialInfoHal*)data;
    uint64_t credentialId = *(uint64_t *)condition;
    if (credentialInfo->credentialId == credentialId) {
        return true;
    }
    return false;
}

static bool MatchEnrolledInfoByType(const void *data, const void *condition)
{
    if (data == NULL || condition == NULL) {
        return false;
    }
    EnrolledInfoHal *enrolledInfo = (EnrolledInfoHal *)data;
    uint32_t authType = *(uint32_t *)condition;
    if (enrolledInfo->authType == authType) {
        return true;
    }
    return false;
}

ResultCode DeleteCredentialInfo(int32_t userId, uint64_t credentialId, CredentialInfoHal *credentialInfo)
{
    if (credentialInfo == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }

    UserInfo *user = QueryUserInfo(userId);
    if (user == NULL) {
        LOG_ERROR("can't find this user");
        return RESULT_BAD_PARAM;
    }

    LinkedList *credentialList = user->credentialInfoList;
    CredentialInfoHal *credentialQuery = QueryCredentialById(credentialId, credentialList);
    if (credentialQuery == NULL) {
        LOG_ERROR("credentialQuery is null");
        return RESULT_UNKNOWN;
    }
    if (memcpy_s(credentialInfo, sizeof(CredentialInfoHal), credentialQuery, sizeof(CredentialInfoHal)) != EOK) {
        LOG_ERROR("copy failed");
        return RESULT_BAD_COPY;
    }
    ResultCode ret = credentialList->remove(credentialList, &credentialId, MatchCredentialById, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("remove credential failed");
        return ret;
    }
    credentialQuery = QueryCredentialByAuthType(credentialInfo->authType, credentialList);
    if (credentialQuery != NULL) {
        return RESULT_SUCCESS;
    }

    LinkedList *enrolledInfoList = user->enrolledInfoList;
    if (enrolledInfoList == NULL) {
        LOG_ERROR("enrolledInfoList is null");
        return RESULT_UNKNOWN;
    }
    ret = enrolledInfoList->remove(enrolledInfoList, &credentialInfo->authType, MatchEnrolledInfoByType, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("remove enrolledInfo failed");
        return ret;
    }

    return UpdateFileInfo(g_userInfoList);
}

static CredentialInfoHal *QueryCredentialById(uint64_t credentialId, LinkedList *credentialList)
{
    if (credentialList == NULL) {
        return NULL;
    }
    LinkedListNode *temp = credentialList->head;
    CredentialInfoHal *credentialInfo = NULL;
    while (temp != NULL) {
        CredentialInfoHal *nodeData = (CredentialInfoHal *)temp->data;
        if (nodeData != NULL && nodeData->credentialId == credentialId) {
            credentialInfo = nodeData;
            break;
        }
        temp = temp->next;
    }
    return credentialInfo;
}

static CredentialInfoHal *QueryCredentialByAuthType(uint32_t authType, LinkedList *credentialList)
{
    if (credentialList == NULL) {
        return NULL;
    }
    LinkedListNode *temp = credentialList->head;
    CredentialInfoHal *credentialInfo = NULL;
    while (temp != NULL) {
        CredentialInfoHal *nodeData = (CredentialInfoHal*)temp->data;
        if (nodeData != NULL && nodeData->authType == authType) {
            credentialInfo = nodeData;
            break;
        }
        temp = temp->next;
    }
    return credentialInfo;
}

static bool IsCredMatch(const CredentialCondition *limit, const CredentialInfoHal *credentialInfo)
{
    if ((limit->conditionFactor & CREDENTIAL_CONDITION_CREDENTIAL_ID) != 0 &&
        limit->credentialId != credentialInfo->credentialId) {
        return false;
    }
    if ((limit->conditionFactor & CREDENTIAL_CONDITION_AUTH_TYPE) != 0 && limit->authType != credentialInfo->authType) {
        return false;
    }
    if ((limit->conditionFactor & CREDENTIAL_CONDITION_TEMPLATE_ID) != 0 &&
        limit->templateId != credentialInfo->templateId) {
        return false;
    }
    if ((limit->conditionFactor & CREDENTIAL_CONDITION_SENSOR_HINT) != 0 &&
        limit->executorSensorHint != INVALID_SENSOR_HINT &&
        limit->executorSensorHint != credentialInfo->executorSensorHint) {
        return false;
    }
    if ((limit->conditionFactor & CREDENTIAL_CONDITION_EXECUTOR_MATCHER) != 0 &&
        limit->executorMatcher != credentialInfo->executorMatcher) {
        return false;
    }
    return true;
}

static bool IsUserMatch(const CredentialCondition *limit, const UserInfo *user)
{
    if ((limit->conditionFactor & CREDENTIAL_CONDITION_USER_ID) != 0 && limit->userId != user->userId) {
        return false;
    }
    return true;
}

static ResultCode TraverseCredentialList(const CredentialCondition *limit, const LinkedList *credentialList,
    LinkedList *credListGet)
{
    if (credentialList == NULL) {
        LOG_ERROR("credentialList is null");
        return RESULT_GENERAL_ERROR;
    }
    LinkedListNode *temp = credentialList->head;
    while (temp != NULL) {
        CredentialInfoHal *nodeData = (CredentialInfoHal*)temp->data;
        if (nodeData == NULL) {
            LOG_ERROR("nodeData is null");
            return RESULT_UNKNOWN;
        }
        if (!IsCredMatch(limit, nodeData)) {
            temp = temp->next;
            continue;
        }
        CredentialInfoHal *copy = (CredentialInfoHal *)Malloc(sizeof(CredentialInfoHal));
        if (copy == NULL) {
            LOG_ERROR("copy malloc failed");
            return RESULT_NO_MEMORY;
        }
        *copy = *nodeData;
        ResultCode ret = credListGet->insert(credListGet, copy);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("insert failed");
            Free(copy);
            return ret;
        }
        temp = temp->next;
    }
    return RESULT_SUCCESS;
}

LinkedList *QueryCredentialLimit(const CredentialCondition *limit)
{
    if (limit == NULL) {
        LOG_ERROR("limit is null");
        return NULL;
    }
    if (g_userInfoList == NULL) {
        LOG_ERROR("g_userInfoList is null");
        return NULL;
    }
    LinkedList *credList = CreateLinkedList(DestroyCredentialNode);
    if (credList == NULL) {
        LOG_ERROR("credList is null");
        return NULL;
    }
    LinkedListNode *temp = g_userInfoList->head;
    while (temp != NULL) {
        UserInfo *user = (UserInfo *)temp->data;
        if (user == NULL) {
            LOG_ERROR("node data is null");
            DestroyLinkedList(credList);
            return NULL;
        }
        if (IsUserMatch(limit, user)) {
            ResultCode ret = TraverseCredentialList(limit, user->credentialInfoList, credList);
            if (ret != RESULT_SUCCESS) {
                LOG_ERROR("TraverseCredentialList failed");
                DestroyLinkedList(credList);
                return NULL;
            }
        }
        temp = temp->next;
    }
    return credList;
}

ResultCode QueryCredentialUserId(uint64_t credentialId, int32_t *userId)
{
    if (userId == NULL) {
        LOG_ERROR("userId is null");
        return RESULT_BAD_PARAM;
    }
    if (g_userInfoList == NULL) {
        LOG_ERROR("g_userInfoList is null");
        return RESULT_NEED_INIT;
    }
    LinkedList *credList = CreateLinkedList(DestroyCredentialNode);
    if (credList == NULL) {
        LOG_ERROR("credList is null");
        return RESULT_NO_MEMORY;
    }
    LinkedListNode *temp = g_userInfoList->head;
    CredentialCondition condition = {};
    SetCredentialConditionCredentialId(&condition, credentialId);
    while (temp != NULL) {
        UserInfo *user = (UserInfo *)temp->data;
        if (user == NULL) {
            LOG_ERROR("user is null");
            DestroyLinkedList(credList);
            return RESULT_UNKNOWN;
        }
        ResultCode ret = TraverseCredentialList(&condition, user->credentialInfoList, credList);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("TraverseCredentialList failed");
            DestroyLinkedList(credList);
            return RESULT_UNKNOWN;
        }
        if (credList->getSize(credList) != 0) {
            DestroyLinkedList(credList);
            *userId = user->userId;
            return RESULT_SUCCESS;
        }
        temp = temp->next;
    }
    DestroyLinkedList(credList);
    LOG_ERROR("can't find this credential");
    return RESULT_NOT_FOUND;
}

ResultCode SetPinSubType(int32_t userId, uint64_t pinSubType)
{
    UserInfo *user = QueryUserInfo(userId);
    if (user == NULL) {
        LOG_ERROR("can't find this user");
        return RESULT_NOT_FOUND;
    }
    user->pinSubType = pinSubType;
    return RESULT_SUCCESS;
}

ResultCode GetPinSubType(int32_t userId, uint64_t *pinSubType)
{
    if (pinSubType == NULL) {
        LOG_ERROR("pinSubType is null");
        return RESULT_BAD_PARAM;
    }
    UserInfo *user = QueryUserInfo(userId);
    if (user == NULL) {
        LOG_ERROR("can't find this user");
        return RESULT_NOT_FOUND;
    }
    *pinSubType = user->pinSubType;
    return RESULT_SUCCESS;
}

void SetCredentialConditionCredentialId(CredentialCondition *condition, uint64_t credentialId)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->credentialId = credentialId;
    condition->conditionFactor |= CREDENTIAL_CONDITION_CREDENTIAL_ID;
}

void SetCredentialConditionTemplateId(CredentialCondition *condition, uint64_t templateId)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->templateId = templateId;
    condition->conditionFactor |= CREDENTIAL_CONDITION_TEMPLATE_ID;
}

void SetCredentialConditionAuthType(CredentialCondition *condition, uint32_t authType)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->authType = authType;
    condition->conditionFactor |= CREDENTIAL_CONDITION_AUTH_TYPE;
}

void SetCredentialConditionExecutorSensorHint(CredentialCondition *condition, uint32_t executorSensorHint)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->executorSensorHint = executorSensorHint;
    condition->conditionFactor |= CREDENTIAL_CONDITION_SENSOR_HINT;
}

void SetCredentialConditionExecutorMatcher(CredentialCondition *condition, uint32_t executorMatcher)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->executorMatcher = executorMatcher;
    condition->conditionFactor |= CREDENTIAL_CONDITION_EXECUTOR_MATCHER;
}

void SetCredentialConditionUserId(CredentialCondition *condition, int32_t userId)
{
    if (condition == NULL) {
        LOG_ERROR("condition is null");
        return;
    }
    condition->userId = userId;
    condition->conditionFactor |= CREDENTIAL_CONDITION_USER_ID;
}
