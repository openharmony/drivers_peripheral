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

#ifndef PIN_AUTH_H
#define PIN_AUTH_H

#include <cstdint>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
struct PinCredentialInfo {
    uint64_t subType;
    uint32_t remainTimes;
    uint32_t freezingTime;
};

class PinAuth {
public:
    DISALLOW_COPY_AND_MOVE(PinAuth);
    explicit PinAuth();
    ~PinAuth() = default;
    int32_t Init();
    int32_t Close();
    int32_t EnrollPin(uint64_t scheduleId, uint64_t subType, std::vector<uint8_t> &salt,
        const std::vector<uint8_t> &pinData, std::vector<uint8_t> &result);
    int32_t GetSalt(uint64_t templateId, std::vector<uint8_t> &salt);
    int32_t AuthPin(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &pinData,
        std::vector<uint8_t> &result);
    int32_t QueryPinInfo(uint64_t templateId, PinCredentialInfo &pinCredentialInfoRet);
    int32_t DeleteTemplate(uint64_t templateId);
    int32_t GetExecutorInfo(std::vector<uint8_t> &pubKey, uint32_t &esl);
    int32_t VerifyTemplateData(std::vector<uint64_t> templateIdList);

private:
    int32_t PinResultToCoAuthResult(int resultCode);
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // PIN_AUTH_H
