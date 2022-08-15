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

#ifndef OHOS_HDI_PIN_AUTH_V1_0_EXECUTOR_IMPL_H
#define OHOS_HDI_PIN_AUTH_V1_0_EXECUTOR_IMPL_H

#include <map>
#include <mutex>
#include <set>
#include <vector>
#include "v1_0/iexecutor.h"
#include "pin_auth.h"
#include "nocopyable.h"

namespace OHOS {
namespace HDI {
namespace PinAuth {
namespace V1_0 {
class ExecutorImpl : public IExecutor, public NoCopyable {
public:
    explicit ExecutorImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi);
    virtual ~ExecutorImpl() {}
    int32_t GetExecutorInfo(ExecutorInfo &info) override;
    int32_t GetTemplateInfo(uint64_t templateId, TemplateInfo &info) override;
    int32_t OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;
    int32_t OnSetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data) override;
    int32_t Enroll(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override;
    int32_t Authenticate(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override;
    int32_t Delete(uint64_t templateId) override;
    int32_t Cancel(uint64_t scheduleId) override;
    int32_t SendCommand(int32_t commandId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override;

private:
    class ScheduleMap {
    public:
        uint32_t AddScheduleInfo(const uint64_t scheduleId, const uint32_t commandId,
            const sptr<IExecutorCallback> callback, const uint64_t templateId, const std::vector<uint8_t> salt);
        uint32_t GetScheduleInfo(const uint64_t scheduleId, uint32_t &commandId, sptr<IExecutorCallback> &callback,
            uint64_t &templateId, std::vector<uint8_t> &salt);
        uint32_t DeleteScheduleId(const uint64_t scheduleId);

    private:
        struct ScheduleInfo {
            uint32_t commandId;
            sptr<IExecutorCallback> callback;
            uint64_t templateId;
            std::vector<uint8_t> salt;
        };

        std::mutex mutex_;
        std::map<uint64_t, struct ScheduleInfo> scheduleInfo_;
    };

private:
    uint32_t NewSalt(std::vector<uint8_t> &salt);
    void CallError(const sptr<IExecutorCallback> &callbackObj, const uint32_t errorCode);
    std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi_;
    ScheduleMap scheduleMap_;
};
} // V1_0
} // PinAuth
} // HDI
} // OHOS

#endif // OHOS_HDI_PIN_AUTH_V1_0_EXECUTOR_IMPL_H
