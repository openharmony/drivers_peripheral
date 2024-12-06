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

#include "v2_1/pin_auth_interface_service.h"

#include <hdf_base.h>

#include "iam_logger.h"
#include "iam_ptr.h"

#include "pin_auth_hdi.h"
#include "pin_auth.h"
#include "all_in_one_impl.h"
#include "collector_impl.h"
#include "verifier_impl.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_HDI"

namespace OHOS {
namespace HDI {
namespace PinAuth {
extern "C" IPinAuthInterface *PinAuthInterfaceImplGetInstance(void)
{
    auto pinAuthInterfaceService = new (std::nothrow) PinAuthInterfaceService();
    if (pinAuthInterfaceService == nullptr) {
        IAM_LOGE("pinAuthInterfaceService is nullptr");
        return nullptr;
    }
    return pinAuthInterfaceService;
}

int32_t PinAuthInterfaceService::GetExecutorList(std::vector<sptr<HdiIAllInOneExecutor>>& allInOneExecutors,
    std::vector<sptr<HdiIVerifier>>& verifiers, std::vector<sptr<HdiICollector>>& collectors)
{
    IAM_LOGI("start");
    static_cast<void>(verifiers);
    static_cast<void>(collectors);
    std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi =
        OHOS::UserIam::Common::MakeShared<OHOS::UserIam::PinAuth::PinAuth>();
    if (pinHdi == nullptr) {
        IAM_LOGE("Generate pinHdi failed");
        return HDF_FAILURE;
    }
    sptr<HdiIAllInOneExecutor> allInOneImpl(new (std::nothrow) AllInOneImpl(pinHdi));
    if (allInOneImpl == nullptr) {
        IAM_LOGE("Generate all in one executor failed");
        return HDF_FAILURE;
    }
    allInOneExecutors.push_back(allInOneImpl);
    sptr<HdiIVerifier> verifierImpl(new (std::nothrow) VerifierImpl(pinHdi));
    if (verifierImpl == nullptr) {
        IAM_LOGE("Generate verifierImpl failed");
        return HDF_FAILURE;
    }
    verifiers.push_back(verifierImpl);
    sptr<HdiICollector> collectorImpl(new (std::nothrow) CollectorImpl(pinHdi));
    if (collectorImpl == nullptr) {
        IAM_LOGE("Generate collectorImpl failed");
        return HDF_FAILURE;
    }
    collectors.push_back(collectorImpl);
    IAM_LOGI("end");
    return HDF_SUCCESS;
}
} // PinAuth
} // HDI
} // OHOS