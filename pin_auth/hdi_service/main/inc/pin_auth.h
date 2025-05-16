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

#ifndef PIN_AUTH_H
#define PIN_AUTH_H

#include <cstdint>
#include <mutex>
#include <vector>
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace PinAuth {
struct PinCredentialInfo {
    uint64_t subType;
    uint32_t remainTimes;
    uint32_t freezingTime;
    int32_t nextFailLockoutDuration;
};

struct PinAlgoParam {
    uint32_t algoVersion;
    uint64_t subType;
    std::vector<uint8_t> algoParameter;
    std::vector<uint8_t> challenge;
};

class PinAuth {
public:
    DISALLOW_COPY_AND_MOVE(PinAuth);
    PinAuth() = default;
    ~PinAuth() = default;
    int32_t Init();
    int32_t Close();

    int32_t GetExecutorInfo(int32_t executorRole, std::vector<uint8_t> &pubKey, uint32_t &esl,
        uint32_t &maxTemplateAcl);

    // for all in one executor
    int32_t SetAllInOneFwkParam(
        const std::vector<uint64_t> &templateIdList, const std::vector<uint8_t> &frameworkPublicKey);
    int32_t EnrollPin(uint64_t scheduleId, uint64_t subType, std::vector<uint8_t> &salt,
        const std::vector<uint8_t> &pinData, std::vector<uint8_t> &result);
    int32_t AuthPin(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &pinData,
        const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &resultTlv);
    void WriteAntiBrute(uint64_t templateId);
    int32_t QueryPinInfo(uint64_t templateId, PinCredentialInfo &pinCredentialInfoRet);
    int32_t DeleteTemplate(uint64_t templateId);
    int32_t GenerateAlgoParameter(std::vector<uint8_t> &algoParameter, uint32_t &algoVersion);
    int32_t AllInOneAuth(
        uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo, PinAlgoParam &pinAlgoParam);
    int32_t Abandon(uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo,
            std::vector<uint8_t> &resultTlv);

    // for collector executor
    int32_t SetCollectorFwkParam(const std::vector<uint8_t> &frameworkPublicKey);
    int32_t Collect(uint64_t scheduleId, const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &msg);
    int32_t CancelCollect();
    int32_t SendMessageToCollector(uint64_t scheduleId, const std::vector<uint8_t> &msg, PinAlgoParam &pinAlgoParam);
    int32_t SetDataToCollector(uint64_t scheduleId, const std::vector<uint8_t> &data, std::vector<uint8_t> &msg);

    // for collector executor
    int32_t SetVerifierFwkParam(const std::vector<uint8_t> &frameworkPublicKey);
    int32_t VerifierAuth(
        uint64_t scheduleId, uint64_t templateId, const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &msgOut);
    int32_t CancelVerifierAuth();
    int32_t SendMessageToVerifier(uint64_t scheduleId,
        const std::vector<uint8_t> &msgIn, std::vector<uint8_t> &msgOut, bool &isAuthEnd, int32_t &compareResult);

private:
    int32_t SetVectorByBuffer(std::vector<uint8_t> &vec, const uint8_t *buf, uint32_t bufSize);
    int32_t PinResultToCoAuthResult(int32_t resultCode);
    std::mutex mutex_;
};
} // namespace PinAuth
} // namespace UserIam
} // namespace OHOS
#endif // PIN_AUTH_H
