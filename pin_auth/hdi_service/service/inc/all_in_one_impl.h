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

#ifndef OHOS_HDI_PIN_AUTH_ALL_IN_ONE_IMPL_H
#define OHOS_HDI_PIN_AUTH_ALL_IN_ONE_IMPL_H

#include <list>
#include <mutex>
#include <vector>

#include "nocopyable.h"
#include "thread_pool.h"

#include "pin_auth_hdi.h"
#include "pin_auth.h"

namespace OHOS {
namespace HDI {
namespace PinAuth {
class AllInOneImpl : public HdiIAllInOneExecutor, public NoCopyable {
public:
    explicit AllInOneImpl(std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi);
    ~AllInOneImpl() override;

    int32_t GetExecutorInfo(HdiExecutorInfo &info) override;
    int32_t OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;
    int32_t Cancel(uint64_t scheduleId) override;
    int32_t SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t>& msg) override;
    int32_t SetData(uint64_t scheduleId, uint64_t authSubType, const std::vector<uint8_t> &data,
        int32_t resultCode) override;
    int32_t Enroll(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
        const sptr<HdiIExecutorCallback> &callbackObj) override;
    int32_t Authenticate(uint64_t scheduleId, const std::vector<uint64_t>& templateIdList,
        const std::vector<uint8_t> &extraInfo, const sptr<HdiIExecutorCallback> &callbackObj) override;
    int32_t Delete(uint64_t templateId) override;
    int32_t GetProperty(const std::vector<uint64_t> &templateIdList, const std::vector<int32_t> &propertyTypes,
        HdiProperty &property) override;
    int32_t SendCommand(int32_t commandId, const std::vector<uint8_t> &extraInfo,
        const sptr<HdiIExecutorCallback> &callbackObj) override;

private:
    struct ScheduleInfo {
        uint64_t scheduleId{0};
        uint32_t commandId{0};
        sptr<HdiIExecutorCallback> callback;
        uint64_t templateId{0};
        std::vector<uint8_t> algoParameter;
    };

    class ScheduleList {
    public:
        bool AddScheduleInfo(const ScheduleInfo &scheduleInfo);
        bool GetAndDelScheduleInfo(uint64_t scheduleId, ScheduleInfo &scheduleInfo);
        void DelScheduleInfo(uint64_t scheduleId);
    private:
        std::mutex mutex_;
        std::list<struct ScheduleInfo> scheduleInfoList_;
    };

private:
    int32_t AuthPin(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &data,
        std::vector<uint8_t> &resultTlv);
    int32_t AuthenticateInner(uint64_t scheduleId, uint64_t templateId, std::vector<uint8_t> &algoParameter,
        const sptr<HdiIExecutorCallback> &callbackObj);
    int32_t EnrollInner(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
        const sptr<HdiIExecutorCallback> &callbackObj, std::vector<uint8_t> &algoParameter, uint32_t &algoVersion);

    std::shared_ptr<OHOS::UserIam::PinAuth::PinAuth> pinHdi_;
    ScheduleList scheduleList_;
    OHOS::ThreadPool threadPool_;
};
} // PinAuth
} // HDI
} // OHOS

#endif // OHOS_HDI_PIN_AUTH_ALL_IN_ONE_IMPL_H
