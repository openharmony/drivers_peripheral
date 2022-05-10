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

#include "idm_common.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"

void DestroyUserInfoNode(void *userInfo)
{
    if (userInfo == NULL) {
        LOG_ERROR("userInfo is null");
        return;
    }
    UserInfo *node = (UserInfo*)userInfo;
    DestroyLinkedList(node->credentialInfoList);
    DestroyLinkedList(node->enrolledInfoList);
    Free(node);
}

void DestroyCredentialNode(void *credential)
{
    if (credential == NULL) {
        LOG_ERROR("credential is null");
        return;
    }
    Free(credential);
}

void DestroyEnrolledNode(void *enrolled)
{
    if (enrolled == NULL) {
        LOG_ERROR("enrolled is null");
        return;
    }
    Free(enrolled);
}

UserInfo *InitUserInfoNode(void)
{
    UserInfo *userInfo = Malloc(sizeof(UserInfo));
    if (userInfo == NULL) {
        LOG_ERROR("userInfo malloc failed");
        return NULL;
    }
    (void)memset_s(userInfo, sizeof(UserInfo), 0, sizeof(UserInfo));

    userInfo->credentialInfoList = CreateLinkedList(DestroyCredentialNode);
    if (userInfo->credentialInfoList == NULL) {
        LOG_ERROR("create credentialInfoList failed");
        Free(userInfo);
        return NULL;
    }
    userInfo->enrolledInfoList = CreateLinkedList(DestroyEnrolledNode);
    if (userInfo->enrolledInfoList == NULL) {
        LOG_ERROR("create enrolledInfoList failed");
        DestroyLinkedList(userInfo->enrolledInfoList);
        Free(userInfo);
        return NULL;
    }
    return userInfo;
}