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

#ifndef EXECUTOR_IMPL_H
#define EXECUTOR_IMPL_H

#include <vector>

#include "v1_0/iexecutor.h"

namespace OHOS {
namespace HDI {
namespace FingerprintAuth {
namespace V1_0 {
class ExecutorImpl : public IExecutor {
public:
    ExecutorImpl();

    virtual ~ExecutorImpl() = default;

    int32_t GetExecutorInfo(ExecutorInfo &info) override;

    int32_t GetTemplateInfo(uint64_t templateId, TemplateInfo &info) override;

    int32_t OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;

    int32_t Enroll(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override;

    int32_t Authenticate(uint64_t scheduleId, const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &extraInfo, const sptr<IExecutorCallback> &callbackObj) override;

    int32_t Identify(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override;

    int32_t Delete(const std::vector<uint64_t> &templateIdList) override;

    int32_t Cancel(uint64_t scheduleId) override;

    int32_t SendCommand(int32_t commandId, const std::vector<uint8_t> &extraInfo,
        const sptr<IExecutorCallback> &callbackObj) override;

private:
    struct ExecutorInfo executorInfo_;
};
} // namespace V1_0
} // namespace FingerprintAuth
} // namespace HDI
} // namespace OHOS
#endif // EXECUTOR_IMPL_H
