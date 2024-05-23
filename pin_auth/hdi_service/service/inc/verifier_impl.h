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

#ifndef OHOS_HDI_PIN_AUTH_VERIFIER_IMPL_H
#define OHOS_HDI_PIN_AUTH_VERIFIER_IMPL_H

#include <vector>

#include "nocopyable.h"
#include "thread_pool.h"

#include "defines.h"
#include "pin_auth_hdi.h"
#include "pin_auth.h"

namespace OHOS {
namespace HDI {
namespace PinAuth {
class VerifierImpl : public HdiIVerifier, public NoCopyable {
public:
    explicit VerifierImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi);
    ~VerifierImpl() override;

    int32_t GetExecutorInfo(OHOS::HDI::PinAuth::V2_0::ExecutorInfo &executorInfo) override;
    int32_t OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;
    int32_t Cancel(uint64_t scheduleId) override;
    int32_t SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg) override;
    int32_t Authenticate(uint64_t scheduleId, const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &extraInfo, const sptr<HdiIExecutorCallback> &callbackObj) override;
    int32_t NotifyCollectorReady(uint64_t scheduleId) override;

private:
    bool IsCurrentSchedule(uint64_t scheduleId);
    void CancelCurrentAuth(int32_t errorCode = CANCELED);
    void HandleSchedulerMsg(const std::vector<uint8_t> &msg);
    void HandleVerifierMsg(uint64_t scheduleId, const std::vector<uint8_t> &msg);

    std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi_;
    OHOS::ThreadPool threadPool_;
    std::optional<uint64_t> scheduleId_;
    sptr<HdiIExecutorCallback> callback_;
};
} // PinAuth
} // HDI
} // OHOS

#endif // OHOS_HDI_PIN_AUTH_VERIFIER_IMPL_H
