/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "v2_1/iall_in_one_executor.h"
#include "v2_1/icollector.h"
#include "v2_1/iexecutor_callback.h"
#include "v2_1/pin_auth_interface_service.h"
#include "v2_1/iverifier.h"
#include "v2_1/pin_auth_types.h"

namespace OHOS {
namespace HDI {
namespace PinAuth {
using IPinAuthInterface = OHOS::HDI::PinAuth::V2_1::IPinAuthInterface;
using PinAuthInterfaceService = OHOS::HDI::PinAuth::V2_1::PinAuthInterfaceService;

using HdiIAllInOneExecutor = OHOS::HDI::PinAuth::V2_1::IAllInOneExecutor;
using HdiICollector = OHOS::HDI::PinAuth::V2_1::ICollector;
using HdiIVerifier = OHOS::HDI::PinAuth::V2_1::IVerifier;
using HdiIExecutorCallback = OHOS::HDI::PinAuth::V2_1::IExecutorCallback;

using HdiAuthType = OHOS::HDI::PinAuth::V2_1::AuthType;
using HdiExecutorRole = OHOS::HDI::PinAuth::V2_1::ExecutorRole;
using HdiExecutorSecureLevel = OHOS::HDI::PinAuth::V2_1::ExecutorSecureLevel;
using HdiExecutorInfo = OHOS::HDI::PinAuth::V2_1::ExecutorInfo;
using HdiGetPropertyType = OHOS::HDI::PinAuth::V2_1::GetPropertyType;
using HdiProperty = OHOS::HDI::PinAuth::V2_1::Property;
} // namespace PinAuth
} // namespace HDI
} // namespace OHOS

#endif // PIN_AUTH_HDI