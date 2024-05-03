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

#include "attributes.h"
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

bool GetAuthExpiredSysTime(const std::vector<uint8_t> &extraInfo, uint64_t &authExpiredSysTime)
{
    Attributes attribute = Attributes(extraInfo);
    std::vector<uint8_t> authRoot;
    if (!attribute.GetUint8ArrayValue(Attributes::AUTH_ROOT, authRoot)) {
        IAM_LOGE("GetUint8ArrayValue AUTH_ROOT failes");
        return false;
    }
    Attributes authRootAttr = Attributes(authRoot);
    std::vector<uint8_t> authData;
    if (!authRootAttr.GetUint8ArrayValue(Attributes::AUTH_DATA, authData)) {
        IAM_LOGE("GetUint8ArrayValue AUTH_DATA failes");
        return false;
    }
    Attributes authDataAttr = Attributes(authData);
    if (!authDataAttr.GetUint64Value(Attributes::AUTH_EXPIRED_SYS_TIME, authExpiredSysTime)) {
        IAM_LOGE("GetUint64Value AUTH_EXPIRED_SYS_TIME failes");
        return false;
    }
    return true;
}

bool CheckAuthExpired(uint64_t authExpiredSysTime)
{
    if (authExpiredSysTime <= 0) {
        IAM_LOGE("no need check auth expired");
        return true;
    }
    uint64_t nowTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (authExpiredSysTime < nowTime) {
        IAM_LOGE("pin auth expired");
        return false;
    }
    return true;
}
} // PinAuth
} // HDI
} // OHOS
