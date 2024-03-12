/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "v1_3/iuser_auth_interface.h"
#include "v1_3/user_auth_types.h"
#include "v1_3/user_auth_interface_service.h"

namespace OHOS {
namespace HDI {
namespace UserAuth {
using IUserAuthInterface = OHOS::HDI::UserAuth::V1_3::IUserAuthInterface;
using UserAuthInterfaceService = OHOS::HDI::UserAuth::V1_3::UserAuthInterfaceService;

using AuthType = OHOS::HDI::UserAuth::V1_3::AuthType;
using ExecutorRole = OHOS::HDI::UserAuth::V1_3::ExecutorRole;
using ExecutorSecureLevel = OHOS::HDI::UserAuth::V1_3::ExecutorSecureLevel;
using PinSubType = OHOS::HDI::UserAuth::V1_3::PinSubType;
using ScheduleMode = OHOS::HDI::UserAuth::V1_3::ScheduleMode;
using ExecutorRegisterInfo = OHOS::HDI::UserAuth::V1_3::ExecutorRegisterInfo;
using ExecutorInfo = OHOS::HDI::UserAuth::V1_3::ExecutorInfo;
using ScheduleInfo = OHOS::HDI::UserAuth::V1_3::ScheduleInfo;
using AuthSolution = OHOS::HDI::UserAuth::V1_3::AuthSolution;
using ExecutorSendMsg = OHOS::HDI::UserAuth::V1_3::ExecutorSendMsg;
using AuthResultInfo = OHOS::HDI::UserAuth::V1_3::AuthResultInfo;
using IdentifyResultInfo = OHOS::HDI::UserAuth::V1_3::IdentifyResultInfo;
using EnrollParam = OHOS::HDI::UserAuth::V1_3::EnrollParam;
using CredentialInfo = OHOS::HDI::UserAuth::V1_3::CredentialInfo;
using EnrolledInfo = OHOS::HDI::UserAuth::V1_3::EnrolledInfo;
using EnrollResultInfo = OHOS::HDI::UserAuth::V1_3::EnrollResultInfo;

using ScheduleInfoV1_1 = OHOS::HDI::UserAuth::V1_3::ScheduleInfoV1_1;
using AuthSolutionV1_2 = OHOS::HDI::UserAuth::V1_3::AuthSolutionV1_2;
using EnrollParamV1_2 = OHOS::HDI::UserAuth::V1_3::EnrollParamV1_2;
using UserInfo = OHOS::HDI::UserAuth::V1_3::UserInfo;
using ExtUserInfo = OHOS::HDI::UserAuth::V1_3::ExtUserInfo;
using EnrolledState = OHOS::HDI::UserAuth::V1_3::EnrolledState;
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS

#endif // USER_AUTH_HDI