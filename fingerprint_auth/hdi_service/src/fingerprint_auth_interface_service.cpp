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

#include "fingerprint_auth_interface_service.h"

#include <hdf_base.h>

#include "all_in_one_executor_impl.h"
#include "iam_logger.h"

#undef LOG_TAG
#define LOG_TAG "FINGERPRINT_AUTH_IMPL"

namespace OHOS {
namespace HDI {
namespace FingerprintAuth {
extern "C" IFingerprintAuthInterface *FingerprintAuthInterfaceImplGetInstance(void)
{
    auto fingerprintAuthInterfaceService = new (std::nothrow) FingerprintAuthInterfaceService();
    if (fingerprintAuthInterfaceService == nullptr) {
        IAM_LOGE("fingerprintAuthInterfaceService is nullptr");
        return nullptr;
    }
    return fingerprintAuthInterfaceService;
}

FingerprintAuthInterfaceService::FingerprintAuthInterfaceService()
{
    auto executor = new (std::nothrow) AllInOneExecutorImpl();
    if (executor == nullptr) {
        IAM_LOGE("executor is nullptr");
        return;
    }
    executorList_.push_back(sptr<IAllInOneExecutor>(executor));
}

int32_t FingerprintAuthInterfaceService::GetExecutorList(std::vector<sptr<IAllInOneExecutor>> &executorList)
{
    IAM_LOGI("interface mock start");
    for (auto executor : executorList_) {
        executorList.push_back(executor);
    }
    IAM_LOGI("interface mock success");
    return HDF_SUCCESS;
}
} // namespace FingerprintAuth
} // namespace HDI
} // namespace OHOS
