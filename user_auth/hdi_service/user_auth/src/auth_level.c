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

#include "adaptor_log.h"
#include "auth_level.h"
#include "defines.h"
#include "idm_database.h"
#include "pool.h"

#ifdef IAM_TEST_ENABLE
#define IAM_STATIC
#else
#define IAM_STATIC static
#endif

typedef struct {
    Atl atl;
    Acl acl;
    Asl asl;
} AtlGeneration;

// Used to map the authentication capability level and authentication security level to the authentication trust level.
IAM_STATIC AtlGeneration g_generationAtl[] = {
    {ATL4, ACL3, ASL2}, {ATL3, ACL2, ASL2}, {ATL2, ACL2, ASL1},
    {ATL2, ACL1, ASL2}, {ATL1, ACL1, ASL0}, {ATL0, ACL0, ASL0},
};

uint32_t GetAtl(uint32_t acl, uint32_t asl)
{
    for (uint32_t i = 0; i < sizeof(g_generationAtl) / sizeof(AtlGeneration); ++i) {
        if (asl >= g_generationAtl[i].asl && acl >= g_generationAtl[i].acl) {
            return g_generationAtl[i].atl;
        }
    }
    return ATL0;
}

IAM_STATIC ResultCode QueryScheduleAsl(const CoAuthSchedule *coAuthSchedule, uint32_t *asl)
{
    if (coAuthSchedule == NULL || asl == NULL || coAuthSchedule->executorSize == 0) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }

    *asl = MAX_ASL;
    for (uint32_t i = 0; i < coAuthSchedule->executorSize; ++i) {
        uint32_t esl = coAuthSchedule->executors[i].esl;
        if (*asl > esl) {
            *asl = esl;
        }
    }
    return RESULT_SUCCESS;
}

ResultCode QueryScheduleAtl(const CoAuthSchedule *coAuthSchedule, uint32_t acl, uint32_t *atl)
{
    if (coAuthSchedule == NULL || atl == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    uint32_t asl;
    ResultCode ret = QueryScheduleAsl(coAuthSchedule, &asl);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("QueryScheduleAsl failed");
        return ret;
    }
    *atl = GetAtl(acl, asl);
    return RESULT_SUCCESS;
}

IAM_STATIC ResultCode GetAslAndAcl(uint32_t authType, uint32_t *asl, uint32_t *acl)
{
    uint32_t allInOneMaxEsl = 0;
    uint32_t allInOneMaxAcl = 0;
    ExecutorCondition condition = {};
    SetExecutorConditionAuthType(&condition, authType);
    LinkedList *executorList = QueryExecutor(&condition);
    if (executorList == NULL) {
        LOG_ERROR("query executor failed");
        return RESULT_UNKNOWN;
    }
    if (executorList->getSize(executorList) == 0) {
        LOG_ERROR("executor is unregistered");
        DestroyLinkedList(executorList);
        return RESULT_TYPE_NOT_SUPPORT;
    }
    LinkedListNode *temp = executorList->head;
    while (temp != NULL) {
        ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)temp->data;

        // currently only all in one is supported
        if (executorInfo == NULL || executorInfo->executorRole != ALL_IN_ONE) {
            *asl = 0;
            LOG_ERROR("executorInfo is invalid");
            DestroyLinkedList(executorList);
            return RESULT_GENERAL_ERROR;
        }
        if (executorInfo->executorRole == ALL_IN_ONE && allInOneMaxEsl < executorInfo->esl) {
            allInOneMaxEsl = executorInfo->esl;
        }
        if (executorInfo->executorRole == ALL_IN_ONE && allInOneMaxAcl < executorInfo->maxTemplateAcl) {
            allInOneMaxAcl = executorInfo->maxTemplateAcl;
        }
        temp = temp->next;
    }
    *asl = allInOneMaxEsl;
    *acl = allInOneMaxAcl;
    DestroyLinkedList(executorList);

    LOG_INFO("allInOneMaxEsl:%{public}d, allInOneMaxAcl:%{public}u", allInOneMaxEsl, allInOneMaxAcl);
    return RESULT_SUCCESS;
}

ResultCode GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t atl)
{
    uint32_t authSecureLevel;
    uint32_t maxTemplateAcl;
    ResultCode ret = GetAslAndAcl(authType, &authSecureLevel, &maxTemplateAcl);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get asl failed");
        return ret;
    }

    uint32_t supportedAtl = 0;
    for (uint32_t i = 0; i < sizeof(g_generationAtl) / sizeof(AtlGeneration); ++i) {
        if (authSecureLevel >= g_generationAtl[i].asl && maxTemplateAcl >= g_generationAtl[i].acl) {
            supportedAtl = g_generationAtl[i].atl;
            break;
        }
    }
    if (supportedAtl == 0) {
        LOG_ERROR("no match atl");
        return RESULT_NOT_FOUND;
    }
    if (atl > supportedAtl) {
        LOG_ERROR("atl does not support, authType:%{public}d, supportedAtl:%{public}u", authType, supportedAtl);
        return RESULT_TRUST_LEVEL_NOT_SUPPORT;
    }

    return RESULT_SUCCESS;
}