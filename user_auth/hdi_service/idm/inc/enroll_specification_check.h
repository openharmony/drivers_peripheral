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

#ifndef USER_IDM_ENROLL_SPECIFICATION_CHECK
#define USER_IDM_ENROLL_SPECIFICATION_CHECK

#include <stdint.h>

#include "defines.h"
#include "user_sign_centre.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NUMBER_OF_PIN_PER_USER 1
#define MAX_NUMBER_OF_FACE_PER_USER 1
#define MAX_NUMBER_OF_FINGERS_PER_USER 10
#define INVALID_AUTH_TYPE_EROLL_NUMBER 0

ResultCode CheckSpecification(int32_t userId, uint32_t authType);
ResultCode CheckIdmOperationToken(int32_t userId, UserAuthTokenHal *authToken);

#ifdef __cplusplus
}
#endif

#endif // USER_IDM_ENROLL_SPECIFICATION_CHECK