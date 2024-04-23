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

#include "v2_0/all_in_one_executor_stub.h"
#include "v2_0/face_auth_interface_stub.h"
#include "v2_0/face_auth_types.h"
#include "v2_0/iall_in_one_executor.h"
#include "v2_0/iexecutor_callback.h"
#include "v2_0/iface_auth_interface.h"
#include "v2_0/isa_command_callback.h"

namespace OHOS {
namespace HDI {
namespace FaceAuth {
using IFaceAuthInterface = OHOS::HDI::FaceAuth::V2_0::IFaceAuthInterface;
using FaceAuthInterfaceStub = OHOS::HDI::FaceAuth::V2_0::FaceAuthInterfaceStub;
using AllInOneExecutorStub = OHOS::HDI::FaceAuth::V2_0::AllInOneExecutorStub;

using IExecutorCallback = OHOS::HDI::FaceAuth::V2_0::IExecutorCallback;

using IAllInOneExecutor = OHOS::HDI::FaceAuth::V2_0::IAllInOneExecutor;

using AuthType = OHOS::HDI::FaceAuth::V2_0::AuthType;
using ExecutorRole = OHOS::HDI::FaceAuth::V2_0::ExecutorRole;
using ExecutorSecureLevel = OHOS::HDI::FaceAuth::V2_0::ExecutorSecureLevel;
using DriverCommandId = OHOS::HDI::FaceAuth::V2_0::DriverCommandId;
using FaceTipsCode = OHOS::HDI::FaceAuth::V2_0::FaceTipsCode;
using ExecutorInfo = OHOS::HDI::FaceAuth::V2_0::ExecutorInfo;

using GetPropertyType = OHOS::HDI::FaceAuth::V2_0::GetPropertyType;
using Property = OHOS::HDI::FaceAuth::V2_0::Property;
using SaCommandId = OHOS::HDI::FaceAuth::V2_0::SaCommandId;
using SaCommandParamNone = OHOS::HDI::FaceAuth::V2_0::SaCommandParamNone;
using SaCommandParam = OHOS::HDI::FaceAuth::V2_0::SaCommandParam;
using SaCommand = OHOS::HDI::FaceAuth::V2_0::SaCommand;

using ISaCommandCallback = OHOS::HDI::FaceAuth::V2_0::ISaCommandCallback;

using BufferProducerSequenceable = OHOS::HDI::Camera::V1_0::BufferProducerSequenceable;
} // namespace FaceAuth
} // namespace HDI
} // namespace OHOS

#endif // FACE_AUTH_HDI