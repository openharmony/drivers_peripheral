/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "executor_impl_common.h"

#include "defines.h"
#include "iam_logger.h"

#undef LOG_TAG
#define LOG_TAG "PIN_AUTH_IMPL"

namespace OHOS {
namespace HDI {
namespace PinAuth {
void CallError(const sptr<HdiIExecutorCallback> &callback, uint32_t errorCode)
{
    IAM_LOGI("start");
    if (callback == nullptr) {
        return;
    }
    std::vector<uint8_t> ret(0);
    if (callback->OnResult(errorCode, ret) != SUCCESS) {
        IAM_LOGE("callback failed");
    }
}
} // PinAuth
} // HDI
} // OHOS
