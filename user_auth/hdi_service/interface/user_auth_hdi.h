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

#include "v4_1/iuser_auth_interface.h"
#include "v4_1/user_auth_types.h"
#include "v4_1/user_auth_interface_service.h"

namespace OHOS {
namespace HDI {
namespace UserAuth {
using IUserAuthInterface = OHOS::HDI::UserAuth::V4_1::IUserAuthInterface;
using UserAuthInterfaceService = OHOS::HDI::UserAuth::V4_1::UserAuthInterfaceService;

using HdiAuthType = OHOS::HDI::UserAuth::V4_1::AuthType;
using HdiExecutorRole = OHOS::HDI::UserAuth::V4_1::ExecutorRole;
using HdiExecutorSecureLevel = OHOS::HDI::UserAuth::V4_1::ExecutorSecureLevel;
using HdiPinSubType = OHOS::HDI::UserAuth::V4_1::PinSubType;
using HdiScheduleMode = OHOS::HDI::UserAuth::V4_1::ScheduleMode;
using HdiExecutorRegisterInfo = OHOS::HDI::UserAuth::V4_1::ExecutorRegisterInfo;
using HdiExecutorInfo = OHOS::HDI::UserAuth::V4_1::ExecutorInfo;
using HdiScheduleInfo = OHOS::HDI::UserAuth::V4_1::ScheduleInfo;
using HdiAuthParam = OHOS::HDI::UserAuth::V4_1::AuthParam;
using HdiAuthParamExt = OHOS::HDI::UserAuth::V4_1::AuthParamExt;
using HdiExecutorSendMsg = OHOS::HDI::UserAuth::V4_1::ExecutorSendMsg;
using HdiAuthResultInfo = OHOS::HDI::UserAuth::V4_1::AuthResultInfo;
using HdiIdentifyResultInfo = OHOS::HDI::UserAuth::V4_1::IdentifyResultInfo;
using HdiEnrollParam = OHOS::HDI::UserAuth::V4_1::EnrollParam;
using HdiEnrollParamExt = OHOS::HDI::UserAuth::V4_1::EnrollParamExt;
using HdiCredentialInfo = OHOS::HDI::UserAuth::V4_1::CredentialInfo;
using HdiEnrolledInfo = OHOS::HDI::UserAuth::V4_1::EnrolledInfo;
using HdiEnrollResultInfo = OHOS::HDI::UserAuth::V4_1::EnrollResultInfo;
using HdiEnrolledState = OHOS::HDI::UserAuth::V4_1::EnrolledState;
using HdiReuseUnlockInfo = OHOS::HDI::UserAuth::V4_1::ReuseUnlockInfo;
using HdiReuseUnlockParam = OHOS::HDI::UserAuth::V4_1::ReuseUnlockParam;
using HdiIMessageCallback = OHOS::HDI::UserAuth::V4_1::IMessageCallback;
using HdiUserInfo = OHOS::HDI::UserAuth::V4_1::UserInfo;
using HdiExtUserInfo = OHOS::HDI::UserAuth::V4_1::ExtUserInfo;
using HdiAuthIntent = OHOS::HDI::UserAuth::V4_1::AuthIntent;
using HdiGlobalConfigType = OHOS::HDI::UserAuth::V4_1::GlobalConfigType;
using HdiGlobalConfigValue= OHOS::HDI::UserAuth::V4_1::GlobalConfigValue;
using HdiGlobalConfigParam = OHOS::HDI::UserAuth::V4_1::GlobalConfigParam;
using HdiUserAuthTokenPlain = OHOS::HDI::UserAuth::V4_1::UserAuthTokenPlain;
using HdiCredentialOperateType = OHOS::HDI::UserAuth::V4_1::CredentialOperateType;
using HdiCredentialOperateResult = OHOS::HDI::UserAuth::V4_1::CredentialOperateResult;
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS

#endif // USER_AUTH_HDI