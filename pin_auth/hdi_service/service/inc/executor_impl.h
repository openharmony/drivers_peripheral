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

#ifndef OHOS_HDI_PIN_AUTH_EXECUTOR_IMPL_H
#define OHOS_HDI_PIN_AUTH_EXECUTOR_IMPL_H

#include <map>
#include <mutex>
#include <set>
#include <vector>

#include "nocopyable.h"
#include "thread_pool.h"

#include "pin_auth_hdi.h"
#include "pin_auth.h"

namespace OHOS {
namespace HDI {
namespace PinAuth {
class ExecutorImpl : public IExecutor, public NoCopyable {
public:
    explicit ExecutorImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi);
    ~ExecutorImpl() override;
    int32_t GetExecutorInfo(ExecutorInfo &info) override;
    int32_t GetTemplateInfo(uint64_t templateId, TemplateInfo &info) override;
    int32_t OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;
    int32_t OnSetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data) override;
    int32_t Enroll(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallbackV1_0> &callbackObj) override;
    int32_t EnrollV1_1(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override;
    int32_t Authenticate(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallbackV1_0> &callbackObj) override;
    int32_t AuthenticateV1_1(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override;
    int32_t Delete(uint64_t templateId) override;
    int32_t Cancel(uint64_t scheduleId) override;
    int32_t SendCommand(int32_t commandId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallbackV1_0> &callbackObj) override;
    int32_t GetProperty(const std::vector<uint64_t> &templateIdList, const std::vector<GetPropertyType> &propertyTypes,
        Property &property) override;

private:
    class ScheduleMap {
    public:
        uint32_t AddScheduleInfo(const uint64_t scheduleId, const uint32_t commandId,
            const sptr<IExecutorCallbackV1_0> callback, const uint64_t templateId,
            const std::vector<uint8_t> algoParameter);
        uint32_t GetScheduleInfo(const uint64_t scheduleId, uint32_t &commandId, sptr<IExecutorCallbackV1_0> &callback,
            uint64_t &templateId, std::vector<uint8_t> &algoParameter);
        uint32_t DeleteScheduleId(const uint64_t scheduleId);

    private:
        struct ScheduleInfo {
            uint32_t commandId;
            sptr<IExecutorCallbackV1_0> callback;
            uint64_t templateId;
            std::vector<uint8_t> algoParameter;
        };

        std::mutex mutex_;
        std::map<uint64_t, struct ScheduleInfo> scheduleInfo_;
    };

private:
    void CallError(const sptr<IExecutorCallbackV1_0> &callbackObj, uint32_t errorCode);
    int32_t AuthPin(uint64_t scheduleId, uint64_t templateId,
        const std::vector<uint8_t> &data, std::vector<uint8_t> &resultTlv);
    int32_t AuthenticateInner(uint64_t scheduleId, uint64_t templateId, std::vector<uint8_t> &algoParameter,
        const sptr<IExecutorCallbackV1_0> &callbackObj);
    int32_t EnrollInner(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallbackV1_0> &callbackObj, std::vector<uint8_t> &algoParameter, uint32_t &algoVersion);
    std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi_;
    ScheduleMap scheduleMap_;
    OHOS::ThreadPool threadPool_;
};
} // PinAuth
} // HDI
} // OHOS

#endif // OHOS_HDI_PIN_AUTH_EXECUTOR_IMPL_H
