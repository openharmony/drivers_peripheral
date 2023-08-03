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

#ifndef FACE_AUTH_HDI
#define FACE_AUTH_HDI

#include "v1_0/face_auth_types.h"
#include "v1_0/iexecutor_callback.h"
#include "v1_1/face_auth_types.h"
#include "v1_1/iexecutor.h"
#include "v1_1/iface_auth_interface.h"
#include "v1_1/isa_command_callback.h"

namespace OHOS {
namespace HDI {
namespace FaceAuth {
using IFaceAuthInterface = OHOS::HDI::FaceAuth::V1_1::IFaceAuthInterface;

using IExecutorCallback = OHOS::HDI::FaceAuth::V1_1::IExecutorCallback;

using IExecutorV1_0 = OHOS::HDI::FaceAuth::V1_0::IExecutor;
using IExecutor = OHOS::HDI::FaceAuth::V1_1::IExecutor;

using AuthType = OHOS::HDI::FaceAuth::V1_0::AuthType;
using ExecutorRole = OHOS::HDI::FaceAuth::V1_0::ExecutorRole;
using ExecutorSecureLevel = OHOS::HDI::FaceAuth::V1_0::ExecutorSecureLevel;
using CommandId = OHOS::HDI::FaceAuth::V1_1::CommandId;
using FaceTipsCode = OHOS::HDI::FaceAuth::V1_0::FaceTipsCode;
using ExecutorInfo = OHOS::HDI::FaceAuth::V1_0::ExecutorInfo;
using TemplateInfo = OHOS::HDI::FaceAuth::V1_0::TemplateInfo;

using GetPropertyType = OHOS::HDI::FaceAuth::V1_1::GetPropertyType;
using Property = OHOS::HDI::FaceAuth::V1_1::Property;
using SaCommandId = OHOS::HDI::FaceAuth::V1_1::SaCommandId;
using SaCommandParamNone = OHOS::HDI::FaceAuth::V1_1::SaCommandParamNone;
using SaCommandParam = OHOS::HDI::FaceAuth::V1_1::SaCommandParam;
using SaCommand = OHOS::HDI::FaceAuth::V1_1::SaCommand;

using ISaCommandCallback = OHOS::HDI::FaceAuth::V1_1::ISaCommandCallback;
} // namespace FaceAuth
} // namespace HDI
} // namespace OHOS

#endif // FACE_AUTH_HDI