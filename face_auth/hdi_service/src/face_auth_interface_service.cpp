/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "v1_0/face_auth_interface_service.h"
#include <hdf_base.h>
#include "executor_impl.h"
#include "iam_logger.h"

#define LOG_LABEL OHOS::UserIAM::Common::LABEL_FACE_AUTH_IMPL

namespace OHOS {
namespace HDI {
namespace FaceAuth {
namespace V1_0 {
static constexpr uint16_t SENSOR_ID = 123;
static constexpr uint32_t EXECUTOR_TYPE = 123;
static constexpr size_t PUBLIC_KEY_LEN = 32;

extern "C" IFaceAuthInterface *FaceAuthInterfaceImplGetInstance(void)
{
    auto faceAuthInterfaceService = new (std::nothrow) FaceAuthInterfaceService();
    if (faceAuthInterfaceService == nullptr) {
        IAM_LOGE("faceAuthInterfaceService is nullptr");
        return nullptr;
    }
    return faceAuthInterfaceService;
}

int32_t FaceAuthInterfaceService::GetExecutorList(std::vector<sptr<IExecutor>> &executorList)
{
    IAM_LOGI("interface mock start");
    executorList.clear();
    struct ExecutorInfo executorInfoExample = {
        .sensorId = SENSOR_ID,
        .executorType = EXECUTOR_TYPE,
        .executorRole = ExecutorRole::ALL_IN_ONE,
        .authType = AuthType::FACE,
        .esl = ExecutorSecureLevel::ESL0,
        .publicKey = std::vector<uint8_t>(PUBLIC_KEY_LEN, 0),
        .extraInfo = {},
    };
    auto executor = new (std::nothrow) ExecutorImpl(executorInfoExample);
    if (executor == nullptr) {
        IAM_LOGE("executor is nullptr");
        return HDF_FAILURE;
    }
    executorList.push_back(sptr<IExecutor>(executor));
    IAM_LOGI("interface mock success");
    return HDF_SUCCESS;
}
} // V1_0
} // FaceAuth
} // HDI
} // OHOS

