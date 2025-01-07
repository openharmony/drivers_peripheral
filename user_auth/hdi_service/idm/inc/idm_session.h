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

#ifndef USER_IDM_SESSION_H
#define USER_IDM_SESSION_H

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "defines.h"
#include "idm_common.h"

#ifdef __cplusplus
extern "C" {
#endif

ResultCode OpenEditSession(int32_t userId, uint8_t *challenge, uint32_t challengeLen);
ResultCode CloseEditSession(void);

ResultCode AssociateCoauthSchedule(uint64_t scheduleId, uint32_t authType, bool isUpdate);
void BreakOffCoauthSchedule(void);

ResultCode CheckSessionTimeout(void);
ResultCode CheckSessionValid(int32_t userId);
ResultCode GetUserId(int32_t *userId);
ResultCode CheckChallenge(const uint8_t *challenge, uint32_t challengeLen);
ResultCode GetIsUpdate(bool *isUpdate);
ResultCode GetEnrollScheduleInfo(uint64_t *scheduleId, uint32_t *authType);
ResultCode IsValidUserType(int32_t userType);

void RefreshValidTokenTime(void);
bool IsValidTokenTime(uint64_t tokenTime);

ResultCode GetChallenge(uint8_t *challenge, uint32_t challengeLen);
void CacheRootSecret(int32_t userId, Buffer *rootSecret);
Buffer *GetCacheRootSecret(int32_t userId);

#ifdef __cplusplus
}
#endif

#endif // USER_IDM_SESSION_H