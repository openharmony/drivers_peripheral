/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef USER_AUTH_HDI
#define USER_AUTH_HDI

#include "v1_2/iuser_auth_interface.h"
#include "v1_2/user_auth_types.h"
#include "v1_2/user_auth_interface_service.h"

namespace OHOS {
namespace HDI {
namespace UserAuth {
using IUserAuthInterface = OHOS::HDI::UserAuth::V1_2::IUserAuthInterface;
using UserAuthInterfaceService = OHOS::HDI::UserAuth::V1_2::UserAuthInterfaceService;

using AuthType = OHOS::HDI::UserAuth::V1_2::AuthType;
using ExecutorRole = OHOS::HDI::UserAuth::V1_2::ExecutorRole;
using ExecutorSecureLevel = OHOS::HDI::UserAuth::V1_2::ExecutorSecureLevel;
using PinSubType = OHOS::HDI::UserAuth::V1_2::PinSubType;
using ScheduleMode = OHOS::HDI::UserAuth::V1_2::ScheduleMode;
using ExecutorRegisterInfo = OHOS::HDI::UserAuth::V1_2::ExecutorRegisterInfo;
using ExecutorInfo = OHOS::HDI::UserAuth::V1_2::ExecutorInfo;
using ScheduleInfo = OHOS::HDI::UserAuth::V1_2::ScheduleInfo;
using AuthSolution = OHOS::HDI::UserAuth::V1_2::AuthSolution;
using ExecutorSendMsg = OHOS::HDI::UserAuth::V1_2::ExecutorSendMsg;
using AuthResultInfo = OHOS::HDI::UserAuth::V1_2::AuthResultInfo;
using IdentifyResultInfo = OHOS::HDI::UserAuth::V1_2::IdentifyResultInfo;
using EnrollParam = OHOS::HDI::UserAuth::V1_2::EnrollParam;
using CredentialInfo = OHOS::HDI::UserAuth::V1_2::CredentialInfo;
using EnrolledInfo = OHOS::HDI::UserAuth::V1_2::EnrolledInfo;
using EnrollResultInfo = OHOS::HDI::UserAuth::V1_2::EnrollResultInfo;

using ScheduleInfoV1_1 = OHOS::HDI::UserAuth::V1_2::ScheduleInfoV1_1;
using AuthSolutionV1_2 = OHOS::HDI::UserAuth::V1_2::AuthSolutionV1_2;
using EnrollParamV1_2 = OHOS::HDI::UserAuth::V1_2::EnrollParamV1_2;
using UserInfo = OHOS::HDI::UserAuth::V1_2::UserInfo;
using ExtUserInfo = OHOS::HDI::UserAuth::V1_2::ExtUserInfo;
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS

#endif // USER_AUTH_HDI