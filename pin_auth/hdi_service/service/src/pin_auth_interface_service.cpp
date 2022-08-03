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

#include "v1_0/pin_auth_interface_service.h"
#include <hdf_base.h>
#include "iam_logger.h"
#include "iam_ptr.h"
#include "pin_auth.h"
#include "executor_impl.h"

#define LOG_LABEL OHOS::UserIam::Common::LABEL_PIN_AUTH_HDI

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace V1_0 {
extern "C" IPinAuthInterface *PinAuthInterfaceImplGetInstance(void)
{
    auto pinAuthInterfaceService = new (std::nothrow) PinAuthInterfaceService();
    if (pinAuthInterfaceService == nullptr) {
        IAM_LOGE("pinAuthInterfaceService is nullptr");
        return nullptr;
    }
    return pinAuthInterfaceService;
}

int32_t PinAuthInterfaceService::GetExecutorList(std::vector<sptr<IExecutor>> &executorList)
{
    IAM_LOGI("start");
    std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi =
        OHOS::UserIam::Common::MakeShared<OHOS::UserIam::PinAuth::PinAuth>();
    if (pinHdi == nullptr) {
        IAM_LOGE("Generate pinHdi failed");
        return HDF_FAILURE;
    }
    sptr<IExecutor> executor = new (std::nothrow) ExecutorImpl(pinHdi);
    if (executor == nullptr) {
        IAM_LOGE("Generate executor failed");
        return HDF_FAILURE;
    }
    executorList.push_back(executor);
    IAM_LOGI("end");
    return HDF_SUCCESS;
}
} // V1_0
} // PinAuth
} // HDI
} // OHOS