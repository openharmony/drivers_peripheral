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

#include "v4_0/iuser_auth_interface.h"
#include "v4_0/user_auth_types.h"
#include "v4_0/user_auth_interface_service.h"

namespace OHOS {
namespace HDI {
namespace UserAuth {
using IUserAuthInterface = OHOS::HDI::UserAuth::V4_0::IUserAuthInterface;
using UserAuthInterfaceService = OHOS::HDI::UserAuth::V4_0::UserAuthInterfaceService;

using HdiAuthType = OHOS::HDI::UserAuth::V4_0::AuthType;
using HdiExecutorRole = OHOS::HDI::UserAuth::V4_0::ExecutorRole;
using HdiExecutorSecureLevel = OHOS::HDI::UserAuth::V4_0::ExecutorSecureLevel;
using HdiPinSubType = OHOS::HDI::UserAuth::V4_0::PinSubType;
using HdiScheduleMode = OHOS::HDI::UserAuth::V4_0::ScheduleMode;
using HdiExecutorRegisterInfo = OHOS::HDI::UserAuth::V4_0::ExecutorRegisterInfo;
using HdiExecutorInfo = OHOS::HDI::UserAuth::V4_0::ExecutorInfo;
using HdiScheduleInfo = OHOS::HDI::UserAuth::V4_0::ScheduleInfo;
using HdiAuthParam = OHOS::HDI::UserAuth::V4_0::AuthParam;
using HdiExecutorSendMsg = OHOS::HDI::UserAuth::V4_0::ExecutorSendMsg;
using HdiAuthResultInfo = OHOS::HDI::UserAuth::V4_0::AuthResultInfo;
using HdiIdentifyResultInfo = OHOS::HDI::UserAuth::V4_0::IdentifyResultInfo;
using HdiEnrollParam = OHOS::HDI::UserAuth::V4_0::EnrollParam;
using HdiCredentialInfo = OHOS::HDI::UserAuth::V4_0::CredentialInfo;
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V4_0::EnrolledInfo;
using HdiEnrollResultInfo = OHOS::HDI::UserAuth::V4_0::EnrollResultInfo;
using HdiEnrolledState = OHOS::HDI::UserAuth::V4_0::EnrolledState;
using HdiReuseUnlockInfo = OHOS::HDI::UserAuth::V4_0::ReuseUnlockInfo;
using HdiReuseUnlockParam = OHOS::HDI::UserAuth::V4_0::ReuseUnlockParam;
using HdiIMessageCallback = OHOS::HDI::UserAuth::V4_0::IMessageCallback;
using HdiUserInfo = OHOS::HDI::UserAuth::V4_0::UserInfo;
using HdiExtUserInfo = OHOS::HDI::UserAuth::V4_0::ExtUserInfo;
using HdiAuthIntent = OHOS::HDI::UserAuth::V4_0::AuthIntent;
using HdiGlobalConfigType = OHOS::HDI::UserAuth::V4_0::GlobalConfigType;
using HdiGlobalConfigValue= OHOS::HDI::UserAuth::V4_0::GlobalConfigValue;
using HdiGlobalConfigParam = OHOS::HDI::UserAuth::V4_0::GlobalConfigParam;
using HdiUserAuthTokenPlain = OHOS::HDI::UserAuth::V4_0::UserAuthTokenPlain;
using HdiCredentialOperateType = OHOS::HDI::UserAuth::V4_0::CredentialOperateType;
using HdiCredentialOperateResult = OHOS::HDI::UserAuth::V4_0::CredentialOperateResult;
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS

#endif // USER_AUTH_HDI