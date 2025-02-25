/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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
#include "adaptor_time.h"
#include "coauth.h"
#include "enroll_specification_check.h"
#include "executor_message.h"
#include "idm_database.h"
#include "udid_manager.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

IAM_STATIC ResultCode SetScheduleParam(const PermissionCheckParam *param, ScheduleParam *scheduleParam)
{
    scheduleParam->associateId.userId = param->userId;
    scheduleParam->authType = param->authType;
    scheduleParam->userType = param->userType;
    scheduleParam->scheduleMode = SCHEDULE_MODE_ENROLL;
    scheduleParam->collectorSensorHint = param->executorSensorHint;

    Uint8Array localUdid = { scheduleParam->localUdid, UDID_LEN };
    bool getLocalUdidRet = GetLocalUdid(&localUdid);
    Uint8Array collectorUdid = { scheduleParam->collectorUdid, UDID_LEN };
    bool getCollectorUdidRet = GetLocalUdid(&collectorUdid);
    if (!getLocalUdidRet || !getCollectorUdidRet) {
        LOG_ERROR("get udid failed");
        return RESULT_GENERAL_ERROR;
    }
    return RESULT_SUCCESS;
}

IAM_STATIC CoAuthSchedule *GenerateIdmSchedule(const PermissionCheckParam *param)
{
    ScheduleParam scheduleParam = {};
    if (SetScheduleParam(param, &scheduleParam) != RESULT_SUCCESS) {
        LOG_ERROR("SetScheduleParam failed");
        return NULL;
    }
    
    if (scheduleParam.collectorSensorHint != INVALID_SENSOR_HINT) {
        ResultCode ret = QueryCollecterMatcher(scheduleParam.authType, scheduleParam.collectorSensorHint,
            &scheduleParam.executorMatcher);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("QueryCollecterMatcher failed");
            return NULL;
        }
    }

    LinkedList *credList = NULL;
    if (QueryCredentialFunc(param->userId, param->authType, &credList) != RESULT_SUCCESS) {
        LOG_ERROR("query credential failed");
        return NULL;
    }
    uint64_t templateIdsBuffer[MAX_CREDENTIAL_OUTPUT];
    uint32_t len = 0;
    LinkedListNode *temp = credList->head;
    while (temp != NULL) {
        if (temp->data == NULL) {
            LOG_ERROR("list node is invalid");
            DestroyLinkedList(credList);
            return NULL;
        }
        CredentialInfoHal *credentialHal = (CredentialInfoHal *)(temp->data);
        if (len >= MAX_CREDENTIAL_OUTPUT) {
            LOG_ERROR("len out of bound");
            DestroyLinkedList(credList);
            return NULL;
        }
        templateIdsBuffer[len] = credentialHal->templateId;
        ++len;
        temp = temp->next;
    }

    Uint64Array templateIds = { templateIdsBuffer, len };
    scheduleParam.templateIds = &templateIds;

    DestroyLinkedList(credList);
    return GenerateSchedule(&scheduleParam);
}

IAM_STATIC ResultCode GenerateCoAuthSchedule(PermissionCheckParam *param, bool isUpdate, uint64_t *scheduleId)
{
    CoAuthSchedule *enrollSchedule = GenerateIdmSchedule(param);
    if (enrollSchedule == NULL) {
        LOG_ERROR("enrollSchedule malloc failed");
        return RESULT_NO_MEMORY;
    }
    ResultCode ret = AddCoAuthSchedule(enrollSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("add coauth schedule failed");
        goto EXIT;
    }
    ret = AssociateCoauthSchedule(enrollSchedule->scheduleId, param->authType, isUpdate);
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

ResultCode CheckEnrollPermission(PermissionCheckParam param, uint64_t *scheduleId)
{
    if (scheduleId == NULL) {
        LOG_ERROR("scheduleId is null");
        return RESULT_BAD_PARAM;
    }
    if (!GetEnableStatus(param.userId, param.authType)) {
        LOG_ERROR("authType is not support %{public}d", param.authType);
        return RESULT_TYPE_NOT_SUPPORT;
    }
    ResultCode ret = IsValidUserType(param.userType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("userType is invalid");
        return ret;
    }
    ret = CheckSessionValid(param.userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid");
        return ret;
    }
    UserAuthTokenHal *authToken = (UserAuthTokenHal *)param.token;
    ret = CheckSpecification(param.userId, param.authType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("check specification failed, authType is %{public}u, ret is %{public}d", param.authType, ret);
        return ret;
    }
    if (param.authType != PIN_AUTH) {
        ret = CheckIdmOperationToken(param.userId, authToken);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("a valid token is required");
            return RESULT_VERIFY_TOKEN_FAIL;
        }
    }

    return GenerateCoAuthSchedule(&param, false, scheduleId);
}

ResultCode CheckUpdatePermission(PermissionCheckParam param, uint64_t *scheduleId)
{
    if (scheduleId == NULL || param.authType != PIN_AUTH) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    if (!GetEnableStatus(param.userId, param.authType)) {
        LOG_ERROR("authType is not support %{public}d", param.authType);
        return RESULT_TYPE_NOT_SUPPORT;
    }
    ResultCode ret = CheckSessionValid(param.userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("session is invalid");
        return ret;
    }
    ret = CheckSpecification(param.userId, param.authType);
    if (ret != RESULT_EXCEED_LIMIT) {
        LOG_ERROR("no pin or exception, authType is %{public}u, ret is %{public}d", param.authType, ret);
        return ret;
    }
    UserAuthTokenHal *authToken = (UserAuthTokenHal *)param.token;
    ret = CheckIdmOperationToken(param.userId, authToken);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("a valid token is required");
        return RESULT_VERIFY_TOKEN_FAIL;
    }

    return GenerateCoAuthSchedule(&param, true, scheduleId);
}

IAM_STATIC void GetInfoFromResult(CredentialInfoHal *credentialInfo, const ExecutorResultInfo *result,
    const CoAuthSchedule *schedule)
{
    credentialInfo->authType = schedule->authType;
    credentialInfo->templateId = result->templateId;
    credentialInfo->capabilityLevel = result->capabilityLevel;
    credentialInfo->executorSensorHint = GetScheduleVerifierSensorHint(schedule);
    credentialInfo->executorMatcher = schedule->executors[0].executorMatcher;
    credentialInfo->credentialType = result->authSubType;
}

IAM_STATIC ResultCode GetCredentialInfoFromSchedule(const ExecutorResultInfo *executorInfo,
    CredentialInfoHal *credentialInfo, const CoAuthSchedule *schedule)
{
    uint64_t currentScheduleId;
    uint32_t scheduleAuthType;
    ResultCode ret = GetEnrollScheduleInfo(&currentScheduleId, &scheduleAuthType);
    if (ret != RESULT_SUCCESS || executorInfo->scheduleId != currentScheduleId) {
        LOG_ERROR("schedule is mismatch");
        return RESULT_GENERAL_ERROR;
    }
    ret = CheckSessionTimeout();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("idm session is time out");
        return ret;
    }
    GetInfoFromResult(credentialInfo, executorInfo, schedule);
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetEnrollTokenDataPlain(const CredentialInfoHal *credentialInfo, TokenDataPlain *dataPlain)
{
    ResultCode ret = GetChallenge(dataPlain->challenge, CHALLENGE_LEN);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get challenge fail");
        return ret;
    }

    dataPlain->time = GetSystemTime();
    dataPlain->authTrustLevel = ATL3;
    dataPlain->authType = credentialInfo->authType;
    dataPlain->authMode = SCHEDULE_MODE_ENROLL;
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetEnrollTokenDataToEncrypt(const CredentialInfoHal *credentialInfo, int32_t userId,
    TokenDataToEncrypt *data)
{
    data->userId = userId;
    uint64_t secureUid;
    ResultCode ret = GetSecureUid(userId, &secureUid);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get secure uid failed");
        return ret;
    }
    data->secureUid = secureUid;
    EnrolledInfoHal enrolledInfo = {};
    ret = GetEnrolledInfoAuthType(userId, credentialInfo->authType, &enrolledInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get enrolled info failed");
        return ret;
    }
    data->enrolledId = enrolledInfo.enrolledId;
    data->credentialId = credentialInfo->credentialId;
    return RESULT_SUCCESS;
}

IAM_STATIC Buffer *GetAuthTokenForPinEnroll(const CredentialInfoHal *credentialInfo, int32_t userId)
{
    UserAuthTokenPlainHal tokenPlain = {};
    ResultCode ret = GetEnrollTokenDataPlain(credentialInfo, &(tokenPlain.tokenDataPlain));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetEnrollTokenDataPlain fail");
        return NULL;
    }
    ret = GetEnrollTokenDataToEncrypt(credentialInfo, userId, &(tokenPlain.tokenDataToEncrypt));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetEnrollTokenDataToEncrypt fail");
        return NULL;
    }

    UserAuthTokenHal authTokenHal = {};
    ret = UserAuthTokenSign(&tokenPlain, &authTokenHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("generate pin enroll authToken fail");
        return NULL;
    }
    Buffer *authToken = CreateBufferByData((uint8_t *)(&authTokenHal), sizeof(UserAuthTokenHal));
    if (!IsBufferValid(authToken)) {
        LOG_ERROR("create authToken buffer fail");
        return NULL;
    }

    return authToken;
}

IAM_STATIC ResultCode ProcessAddPinCredential(int32_t userId, const CredentialInfoHal *credentialInfo,
    const ExecutorResultInfo *executorResultInfo, Buffer **rootSecret, Buffer **authToken)
{
    ResultCode ret = SetPinSubType(userId, executorResultInfo->authSubType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("set pin sub type failed");
        return ret;
    }
    *rootSecret = CopyBuffer(executorResultInfo->rootSecret);
    if ((*rootSecret) == NULL) {
        LOG_ERROR("copy rootSecret fail");
        return RESULT_NO_MEMORY;
    }
    *authToken = GetAuthTokenForPinEnroll(credentialInfo, userId);
    if (!IsBufferValid(*authToken)) {
        LOG_ERROR("authToken is invalid");
        DestoryBuffer(*rootSecret);
        *rootSecret = NULL;
        return RESULT_NO_MEMORY;
    }

    return RESULT_SUCCESS;
}

ResultCode AddCredentialFunc(
    int32_t userId, const Buffer *scheduleResult, uint64_t *credentialId, Buffer **rootSecret, Buffer **authToken)
{
    if (!IsBufferValid(scheduleResult) || credentialId == NULL || rootSecret == NULL || authToken == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    int32_t sessionUserId;
    ResultCode ret = GetUserId(&sessionUserId);
    if (ret != RESULT_SUCCESS || sessionUserId != userId) {
        LOG_ERROR("userId mismatch");
        return RESULT_UNKNOWN;
    }
    ExecutorResultInfo *executorResultInfo = CreateExecutorResultInfo(scheduleResult);
    if (executorResultInfo == NULL) {
        LOG_ERROR("executorResultInfo is null");
        return RESULT_UNKNOWN;
    }
    const CoAuthSchedule *schedule = GetCoAuthSchedule(executorResultInfo->scheduleId);
    if (schedule == NULL) {
        LOG_ERROR("schedule is null");
        ret = RESULT_GENERAL_ERROR;
        goto EXIT;
    }
    CredentialInfoHal credentialInfo;
    ret = GetCredentialInfoFromSchedule(executorResultInfo, &credentialInfo, schedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to get credential info result");
        goto EXIT;
    }
    ret = AddCredentialInfo(userId, &credentialInfo, schedule->userType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("add credential failed");
        goto EXIT;
    }
    *credentialId = credentialInfo.credentialId;
    if (credentialInfo.authType != PIN_AUTH) {
        goto EXIT;
    }
    ret = ProcessAddPinCredential(userId, &credentialInfo, executorResultInfo, rootSecret, authToken);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("ProcessAddPinCredential fail");
        goto EXIT;
    }

EXIT:
    DestroyExecutorResultInfo(executorResultInfo);
    return ret;
}

ResultCode DeleteCredentialFunc(CredentialDeleteParam param, CredentialInfoHal *credentialInfo)
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
    ResultCode ret = CheckIdmOperationToken(param.userId, &token);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("token is invalid");
        return RESULT_VERIFY_TOKEN_FAIL;
    }

    ret = DeleteCredentialInfo(param.userId, param.credentialId, credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete database info failed");
        return RESULT_BAD_SIGN;
    }
    return ret;
}

ResultCode QueryCredentialFunc(int32_t userId, uint32_t authType, LinkedList **creds)
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

ResultCode GetUserInfoFunc(int32_t userId, uint64_t *secureUid, uint64_t *pinSubType,
    EnrolledInfoHal **enrolledInfoArray, uint32_t *enrolledNum)
{
    if (secureUid == NULL || pinSubType == NULL || enrolledInfoArray == NULL || enrolledNum == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    ResultCode ret = GetSecureUid(userId, secureUid);
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

IAM_STATIC ResultCode GetDeletedCredential(int32_t userId, CredentialInfoHal *deletedCredential)
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

IAM_STATIC ResultCode CheckResultValid(uint64_t scheduleId, int32_t userId)
{
    uint64_t currentScheduleId;
    uint32_t scheduleAuthType;
    ResultCode ret = GetEnrollScheduleInfo(&currentScheduleId, &scheduleAuthType);
    if (ret != RESULT_SUCCESS || scheduleId != currentScheduleId) {
        LOG_ERROR("schedule is mismatch");
        return RESULT_GENERAL_ERROR;
    }
    ret = CheckSessionTimeout();
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("idm session is time out");
        return ret;
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

IAM_STATIC ResultCode GetUpdateCredentialOutput(int32_t userId, const Buffer *rootSecret,
    const CredentialInfoHal *credentialInfo, UpdateCredentialOutput *output)
{
    if (credentialInfo->authType != PIN_AUTH && credentialInfo->authType != DEFAULT_AUTH_TYPE) {
        LOG_ERROR("bad authType");
        return RESULT_GENERAL_ERROR;
    }
    CredentialInfoHal credInfo = (*credentialInfo);
    credInfo.authType = PIN_AUTH;

    output->credentialId = credInfo.credentialId;
    output->rootSecret = CopyBuffer(rootSecret);
    if (!IsBufferValid(output->rootSecret)) {
        LOG_ERROR("copy rootSecret fail");
        goto ERROR;
    }
    output->oldRootSecret = GetCacheRootSecret(userId);
    if (!IsBufferValid(output->oldRootSecret)) {
        LOG_ERROR("GetCacheRootSecret fail");
        goto ERROR;
    }
    output->authToken = GetAuthTokenForPinEnroll(&credInfo, userId);
    if (!IsBufferValid(output->authToken)) {
        LOG_ERROR("authToken is invalid");
        goto ERROR;
    }
    return RESULT_SUCCESS;

ERROR:
    DestoryBuffer(output->rootSecret);
    output->rootSecret = NULL;
    DestoryBuffer(output->oldRootSecret);
    output->oldRootSecret = NULL;
    DestoryBuffer(output->authToken);
    output->authToken = NULL;
    return RESULT_NO_MEMORY;
}

ResultCode UpdateCredentialFunc(int32_t userId, const Buffer *scheduleResult, UpdateCredentialOutput *output)
{
    if (!IsBufferValid(scheduleResult) || output == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    ExecutorResultInfo *executorResultInfo = CreateExecutorResultInfo(scheduleResult);
    if (executorResultInfo == NULL) {
        LOG_ERROR("executorResultInfo is null");
        return RESULT_UNKNOWN;
    }
    ResultCode ret = CheckResultValid(executorResultInfo->scheduleId, userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("check result failed");
        goto EXIT;
    }
    ret = GetDeletedCredential(userId, &(output->deletedCredential));
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get old credential failed");
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
    ret = AddCredentialInfo(userId, &credentialInfo, schedule->userType);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to add credential");
        goto EXIT;
    }
    ret = GetUpdateCredentialOutput(userId, executorResultInfo->rootSecret, &credentialInfo, output);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetUpdateCredentialOutputRootSecret fail");
        goto EXIT;
    }

EXIT:
    DestroyExecutorResultInfo(executorResultInfo);
    return ret;
}

ResultCode QueryAllExtUserInfoFunc(UserInfoResult *userInfos, uint32_t userInfolen, uint32_t *userInfoCount)
{
    ResultCode ret = GetAllExtUserInfo(userInfos, userInfolen, userInfoCount);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("GetAllExtUserInfo failed");
        return RESULT_BAD_PARAM;
    }

    return RESULT_SUCCESS;
}
ResultCode QueryCredentialByIdFunc(uint64_t credentialId, LinkedList **creds)
{
    if (creds == NULL) {
        LOG_ERROR("creds is null");
        return RESULT_BAD_PARAM;
    }
    CredentialCondition condition = {};
    SetCredentialConditionCredentialId(&condition, credentialId);
    SetCredentiaConditionNeedCachePin(&condition);
    *creds = QueryCredentialLimit(&condition);
    if (*creds == NULL) {
        LOG_ERROR("query credential failed");
        return RESULT_UNKNOWN;
    }
    LOG_INFO("query credential success");
    return RESULT_SUCCESS;
}