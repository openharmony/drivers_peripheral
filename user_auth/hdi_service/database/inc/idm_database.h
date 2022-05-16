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

#ifndef IDM_DATABASE_H
#define IDM_DATABASE_H

#include <stdint.h>

#include "defines.h"
#include "adaptor_memory.h"
#include "idm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

ResultCode InitUserInfoList(void);
void DestroyUserInfoList(void);
UserInfo *InitUserInfoNode(void);

ResultCode GetSecureUid(int32_t userId, uint64_t *secUid);
ResultCode GetEnrolledInfo(int32_t userId, EnrolledInfoHal **enrolledInfos, uint32_t *num);
ResultCode GetEnrolledInfoAuthType(int32_t userId, uint32_t authType, EnrolledInfoHal *enrolledInfo);
ResultCode DeleteUserInfo(int32_t userId, CredentialInfoHal **credentialInfos, uint32_t *num);

ResultCode AddCredentialInfo(int32_t userId, CredentialInfoHal *credentialInfo);
ResultCode QueryCredentialInfoAll(int32_t userId, CredentialInfoHal **credentialInfos, uint32_t *num);
ResultCode QueryCredentialInfo(int32_t userId, uint32_t authType, CredentialInfoHal *credentialInfo);
ResultCode DeleteCredentialInfo(int32_t userId, uint64_t credentialId, CredentialInfoHal *credentialInfo);
ResultCode QueryCredentialFromExecutor(uint32_t authType, CredentialInfoHal **credentialInfos, uint32_t *num);

#ifdef __cplusplus
}
#endif

#endif // IDM_DATABASE_H