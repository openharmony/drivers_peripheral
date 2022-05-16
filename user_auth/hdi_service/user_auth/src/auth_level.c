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

#include "auth_level.h"

#include "adaptor_log.h"
#include "defines.h"
#include "idm_database.h"
#include "pool.h"

typedef enum Asl {
    ASL0 = 0,
    ASL1 = 1,
    ASL2 = 2,
    ASL3 = 3,
    MAX_ASL = 4,
} Asl;

typedef enum Acl {
    ACL0 = 0,
    ACL1 = 1,
    ACL2 = 2,
    ACL3 = 3,
} Acl;

typedef enum Atl {
    ATL0 = 0,
    ATL1 = 10000,
    ATL2 = 20000,
    ATL3 = 30000,
    ATL4 = 40000,
} Atl;

typedef struct {
    Atl atl;
    Acl acl;
    Asl asl;
} AtlGeneration;

// Used to map the authentication capability level and authentication security level to the authentication trust level.
static AtlGeneration g_generationAtl[] = {
    {ATL4, ACL3, ASL2}, {ATL3, ACL2, ASL2}, {ATL2, ACL2, ASL1},
    {ATL2, ACL1, ASL2}, {ATL1, ACL1, ASL0}, {ATL0, ACL0, ASL0},
};

static ResultCode GetAsl(uint32_t authType, uint32_t *asl)
{
    LinkedList *executorList = NULL;
    ResultCode ret = QueryExecutor(authType, &executorList);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query executor failed");
        return ret;
    }
    if (executorList->getSize(executorList) == 0) {
        LOG_ERROR("executor is unregistered");
        DestroyLinkedList(executorList);
        return RESULT_NEED_INIT;
    }

    *asl = MAX_ASL;
    LinkedListNode *temp = executorList->head;
    while (temp != NULL) {
        ExecutorInfoHal *executorInfo = (ExecutorInfoHal *)temp->data;
        if (executorInfo == NULL) {
            *asl = 0;
            LOG_ERROR("executorList data is null");
            DestroyLinkedList(executorList);
            return RESULT_UNKNOWN;
        }
        if (*asl > executorInfo->esl) {
            *asl = executorInfo->esl;
        }
        temp = temp->next;
    }
    DestroyLinkedList(executorList);
    return ret;
}

static ResultCode GetAcl(uint32_t userId, uint32_t authType, uint32_t *acl)
{
    CredentialInfoHal credentialInfo;
    ResultCode ret = QueryCredentialInfo(userId, authType, &credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query credential failed");
        return ret;
    }

    *acl = credentialInfo.capabilityLevel;
    return ret;
}

ResultCode SingleAuthTrustLevel(uint32_t userId, uint32_t authType, uint32_t *atl)
{
    if (atl == NULL) {
        LOG_ERROR("atl is null");
        return RESULT_BAD_PARAM;
    }
    uint32_t authSecureLevel;
    ResultCode ret = GetAsl(authType, &authSecureLevel);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get asl failed");
        return ret;
    }

    uint32_t authCapabilityLevel;
    ret = GetAcl(userId, authType, &authCapabilityLevel);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get acl failed");
        return ret;
    }

    for (uint32_t i = 0; i < sizeof(g_generationAtl) / sizeof(AtlGeneration); i++) {
        if (authSecureLevel >= g_generationAtl[i].asl && authCapabilityLevel >= g_generationAtl[i].acl) {
            *atl = g_generationAtl[i].atl;
            return RESULT_SUCCESS;
        }
    }

    return RESULT_NOT_FOUND;
}