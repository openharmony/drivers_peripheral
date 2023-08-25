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

#ifndef PIN_AUTH_HDI
#define PIN_AUTH_HDI

#include "v1_0/pin_auth_types.h"
#include "v1_0/iexecutor_callback.h"
#include "v1_1/pin_auth_types.h"
#include "v1_1/iexecutor.h"
#include "v1_1/iexecutor_callback.h"
#include "v1_1/ipin_auth_interface.h"
#include "v1_1/pin_auth_interface_service.h"

namespace OHOS {
namespace HDI {
namespace PinAuth {
using IPinAuthInterface = OHOS::HDI::PinAuth::V1_1::IPinAuthInterface;
using PinAuthInterfaceService = OHOS::HDI::PinAuth::V1_1::PinAuthInterfaceService;

using IExecutorV1_0 = OHOS::HDI::PinAuth::V1_0::IExecutor;
using IExecutor = OHOS::HDI::PinAuth::V1_1::IExecutor;

using IExecutorCallbackV1_0 = OHOS::HDI::PinAuth::V1_0::IExecutorCallback;
using IExecutorCallback = OHOS::HDI::PinAuth::V1_1::IExecutorCallback;

using AuthType = OHOS::HDI::PinAuth::V1_0::AuthType;
using ExecutorRole = OHOS::HDI::PinAuth::V1_0::ExecutorRole;
using ExecutorSecureLevel = OHOS::HDI::PinAuth::V1_0::ExecutorSecureLevel;
using CommandId = OHOS::HDI::PinAuth::V1_0::CommandId;
using ExecutorInfo = OHOS::HDI::PinAuth::V1_0::ExecutorInfo;
using TemplateInfo = OHOS::HDI::PinAuth::V1_0::TemplateInfo;

using GetPropertyType = OHOS::HDI::PinAuth::V1_1::GetPropertyType;
using Property = OHOS::HDI::PinAuth::V1_1::Property;
} // namespace PinAuth
} // namespace HDI
} // namespace OHOS

#endif // PIN_AUTH_HDI