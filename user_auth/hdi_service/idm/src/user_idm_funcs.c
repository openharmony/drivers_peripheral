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

#include "user_idm_funcs.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "coauth.h"
#include "executor_message.h"
#include "idm_database.h"
#include "enroll_specification_check.h"

static CoAuthSchedule *GenerateIdmSchedule(const PermissionCheckParam *param)
{
    ScheduleParam scheduleParam = {};
    scheduleParam.associateId.userId = param->userId;
    scheduleParam.authType = param->authType;
    scheduleParam.scheduleMode = SCHEDULE_MODE_ENROLL;
    scheduleParam.collectorSensorHint = param->executorSensorHint;
    if (scheduleParam.collectorSensorHint != INVALID_SENSOR_HINT) {
        int32_t ret = QueryCollecterMatcher(scheduleParam.authType, scheduleParam.collectorSensorHint,
            &scheduleParam.executorMatcher);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("QueryCollecterMatcher failed");
            return NULL;
        }
    }
    return GenerateSchedule(&scheduleParam);
}

int32_t CheckEnrollPermission(PermissionCheckParam param, uint64_t *scheduleId)
{
    if (scheduleId == NULL) {
        LOG_ERROR("scheduleId is null");
        return RESULT_BAD_PARAM;
    }
    if (!IsSessionValid(param.userId)) {
        LOG_ERROR("session is invalid");
        return RESULT_BAD_PARAM;
    }
    UserAuthTokenHal *authToken = (UserAuthTokenHal *)param.token;
    int32_t ret = CheckSpecification(param.userId, param.authType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("check specification failed, authType is %{public}u, ret is %{public}d", param.authType, ret);
        return ret;
    }
    if (param.authType != PIN_AUTH) {
        ret = CheckIdmOperationToken(param.userId, authToken);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("a valid token is required");
            return ret;
        }
    }
    CoAuthSchedule *enrollSchedule = GenerateIdmSchedule(&param);
    if (enrollSchedule == NULL) {
        LOG_ERROR("enrollSchedule malloc failed");
        return RESULT_NO_MEMORY;
    }
    ret = AddCoAuthSchedule(enrollSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("add coauth schedule failed");
        goto EXIT;
    }
    ret = AssociateCoauthSchedule(enrollSchedule->scheduleId, param.authType, false);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("idm associate coauth schedule failed");
        RemoveCoAuthSchedule(enrollSchedule->scheduleId);
        goto EXIT;
    }
    *scheduleId = enrollSchedule->scheduleId;

EXIT:
    DestroyCoAuthSchedule(enrollSchedule);
    return ret;
}

int32_t CheckUpdatePermission(PermissionCheckParam param, uint64_t *scheduleId)
{
    if (scheduleId == NULL || param.authType != PIN_AUTH) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    if (!IsSessionValid(param.userId)) {
        LOG_ERROR("session is invalid");
        return RESULT_BAD_PARAM;
    }
    int32_t ret = CheckSpecification(param.userId, param.authType);
    if (ret != RESULT_EXCEED_LIMIT) {
        LOG_ERROR("no pin or exception, authType is %{public}u, ret is %{public}d", param.authType, ret);
        return ret;
    }
    CoAuthSchedule *enrollSchedule = GenerateIdmSchedule(&param);
    if (enrollSchedule == NULL) {
        LOG_ERROR("enrollSchedule malloc failed");
        return RESULT_NO_MEMORY;
    }
    ret = AddCoAuthSchedule(enrollSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("add coauth schedule failed");
        goto EXIT;
    }
    ret = AssociateCoauthSchedule(enrollSchedule->scheduleId, param.authType, true);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("idm associate coauth schedule failed");
        RemoveCoAuthSchedule(enrollSchedule->scheduleId);
        goto EXIT;
    }
    *scheduleId = enrollSchedule->scheduleId;

EXIT:
    DestroyCoAuthSchedule(enrollSchedule);
    return ret;
}

static void GetInfoFromResult(CredentialInfoHal *credentialInfo, const ExecutorResultInfo *result,
    const CoAuthSchedule *schedule)
{
    credentialInfo->authType = schedule->authType;
    credentialInfo->templateId = result->templateId;
    credentialInfo->capabilityLevel = result->capabilityLevel;
    credentialInfo->executorSensorHint = GetScheduleVeriferSensorHint(schedule);
    credentialInfo->executorMatcher = schedule->executors[0].executorMatcher;
}

static int32_t GetCredentialInfoFromSchedule(const ExecutorResultInfo *executorInfo, CredentialInfoHal *credentialInfo)
{
    uint64_t currentScheduleId;
    uint32_t scheduleAuthType;
    int32_t ret = GetEnrollScheduleInfo(&currentScheduleId, &scheduleAuthType);
    if (ret != RESULT_SUCCESS || executorInfo->scheduleId != currentScheduleId || IsSessionTimeout()) {
        LOG_ERROR("schedule is mismatch");
        return RESULT_REACH_LIMIT;
    }
    const CoAuthSchedule *schedule = GetCoAuthSchedule(executorInfo->scheduleId);
    if (schedule == NULL) {
        LOG_ERROR("schedule is null");
        return RESULT_GENERAL_ERROR;
    }
    GetInfoFromResult(credentialInfo, executorInfo, schedule);
    return RESULT_SUCCESS;
}

int32_t AddCredentialFunc(int32_t userId, const Buffer *scheduleResult, uint64_t *credentialId, Buffer **rootSecret)
{
    if (!IsBufferValid(scheduleResult) || credentialId == NULL || rootSecret == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    int32_t sessionUserId;
    int32_t ret = GetUserId(&sessionUserId);
    if (ret != RESULT_SUCCESS || sessionUserId != userId) {
        LOG_ERROR("userId mismatch");
        return RESULT_UNKNOWN;
    }
    ExecutorResultInfo *executorResultInfo = CreateExecutorResultInfo(scheduleResult);
    if (executorResultInfo == NULL) {
        LOG_ERROR("executorResultInfo is null");
        return RESULT_UNKNOWN;
    }
    CredentialInfoHal credentialInfo;
    ret = GetCredentialInfoFromSchedule(executorResultInfo, &credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to get credential info result");
        goto EXIT;
    }
    ret = AddCredentialInfo(userId, &credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("add credential failed");
        goto EXIT;
    }
    *credentialId = credentialInfo.credentialId;
    if (credentialInfo.authType != PIN_AUTH) {
        goto EXIT;
    }
    ret = SetPinSubType(userId, executorResultInfo->authSubType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("set pin sub type failed");
        goto EXIT;
    }
    *rootSecret = CopyBuffer(executorResultInfo->rootSecret);
    if (!IsBufferValid(*rootSecret)) {
        LOG_ERROR("rootSecret is invalid");
        ret = RESULT_NO_MEMORY;
    }

EXIT:
    DestoryExecutorResultInfo(executorResultInfo);
    return ret;
}

int32_t DeleteCredentialFunc(CredentialDeleteParam param, CredentialInfoHal *credentialInfo)
{
    if (credentialInfo == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    UserAuthTokenHal token;
    if (memcpy_s(&token, sizeof(UserAuthTokenHal), param.token, AUTH_TOKEN_LEN) != EOK) {
        LOG_ERROR("token copy failed");
        return RESULT_BAD_COPY;
    }
    int32_t ret = CheckIdmOperationToken(param.userId, &token);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("token is invalid");
        return ret;
    }

    ret = DeleteCredentialInfo(param.userId, param.credentialId, credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete database info failed");
        return RESULT_BAD_SIGN;
    }
    return ret;
}

int32_t QueryCredentialFunc(int32_t userId, uint32_t authType, LinkedList **creds)
{
    if (creds == NULL) {
        LOG_ERROR("creds is null");
        return RESULT_BAD_PARAM;
    }
    CredentialCondition condition = {};
    SetCredentialConditionUserId(&condition, userId);
    if (authType != DEFAULT_AUTH_TYPE) {
        SetCredentialConditionAuthType(&condition, authType);
    }
    *creds = QueryCredentialLimit(&condition);
    if (*creds == NULL) {
        LOG_ERROR("query credential failed");
        return RESULT_UNKNOWN;
    }
    LOG_INFO("query credential success");
    return RESULT_SUCCESS;
}

int32_t GetUserInfoFunc(int32_t userId, uint64_t *secureUid, uint64_t *pinSubType, EnrolledInfoHal **enrolledInfoArray,
    uint32_t *enrolledNum)
{
    if (secureUid == NULL || pinSubType == NULL || enrolledInfoArray == NULL || enrolledNum == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    int32_t ret = GetSecureUid(userId, secureUid);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get secureUid failed");
        return ret;
    }
    ret = GetPinSubType(userId, pinSubType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get pinSubType failed");
        return ret;
    }
    return GetEnrolledInfo(userId, enrolledInfoArray, enrolledNum);
}

static int32_t GetDeletedCredential(int32_t userId, CredentialInfoHal *deletedCredential)
{
    CredentialCondition condition = {};
    SetCredentialConditionAuthType(&condition, PIN_AUTH);
    SetCredentialConditionUserId(&condition, userId);
    LinkedList *credList = QueryCredentialLimit(&condition);
    if (credList == NULL || credList->head == NULL || credList->head->data == NULL) {
        LOG_ERROR("query credential failed");
        DestroyLinkedList(credList);
        return RESULT_UNKNOWN;
    }
    if (credList->getSize(credList) != MAX_NUMBER_OF_PIN_PER_USER) {
        LOG_ERROR("pin num is invalid");
        DestroyLinkedList(credList);
        return RESULT_UNKNOWN;
    }
    *deletedCredential = *((CredentialInfoHal *)credList->head->data);
    DestroyLinkedList(credList);
    return RESULT_SUCCESS;
}

static int32_t CheckResultValid(uint64_t scheduleId, int32_t userId)
{
    uint64_t currentScheduleId;
    uint32_t scheduleAuthType;
    int32_t ret = GetEnrollScheduleInfo(&currentScheduleId, &scheduleAuthType);
    if (ret != RESULT_SUCCESS || scheduleId != currentScheduleId || IsSessionTimeout()) {
        LOG_ERROR("schedule is mismatch");
        return RESULT_REACH_LIMIT;
    }
    int32_t userIdGet;
    ret = GetUserId(&userIdGet);
    if (ret != RESULT_SUCCESS || userId != userIdGet) {
        LOG_ERROR("check userId failed");
        return RESULT_REACH_LIMIT;
    }
    if (scheduleAuthType != PIN_AUTH) {
        LOG_ERROR("only pin is allowed to be updated");
        return RESULT_UNKNOWN;
    }
    return RESULT_SUCCESS;
}

int32_t UpdateCredentialFunc(int32_t userId, const Buffer *scheduleResult, uint64_t *credentialId,
    CredentialInfoHal *deletedCredential, Buffer **rootSecret)
{
    if (!IsBufferValid(scheduleResult) || credentialId == NULL || deletedCredential == NULL || rootSecret == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    ExecutorResultInfo *executorResultInfo = CreateExecutorResultInfo(scheduleResult);
    if (executorResultInfo == NULL) {
        LOG_ERROR("executorResultInfo is null");
        return RESULT_UNKNOWN;
    }
    int32_t ret = CheckResultValid(executorResultInfo->scheduleId, userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("check result failed");
        goto EXIT;
    }
    ret = GetDeletedCredential(userId, deletedCredential);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get old credential failed");
        goto EXIT;
    }
    ret = DeleteCredentialInfo(userId, deletedCredential->credentialId, deletedCredential);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete failed");
        goto EXIT;
    }
    const CoAuthSchedule *schedule = GetCoAuthSchedule(executorResultInfo->scheduleId);
    if (schedule == NULL) {
        LOG_ERROR("schedule is null");
        ret = RESULT_UNKNOWN;
        goto EXIT;
    }
    CredentialInfoHal credentialInfo;
    GetInfoFromResult(&credentialInfo, executorResultInfo, schedule);
    ret = AddCredentialInfo(userId, &credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to add credential");
        goto EXIT;
    }
    *credentialId = credentialInfo.credentialId;
    *rootSecret = CopyBuffer(executorResultInfo->rootSecret);
    if (!IsBufferValid(*rootSecret)) {
        LOG_ERROR("rootSecret is invalid");
        ret = RESULT_NO_MEMORY;
    }

EXIT:
    DestoryExecutorResultInfo(executorResultInfo);
    return ret;
}
