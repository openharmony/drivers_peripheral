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

#ifndef SIGNATURE_OPERATION_H
#define SIGNATURE_OPERATION_H

#include <vector>

#include "defines.h"

namespace OHOS {
namespace HDI {
namespace UserAuth {
namespace V1_0 {
struct TlvRequiredPara {
    uint32_t result;
    uint32_t remainAttempts;
    uint64_t scheduleId;
    uint64_t subType;
    uint64_t templateId;
};

ResultCode GenerateExecutorKeyPair();
ResultCode GetExecutorResultTlv(const TlvRequiredPara &para, std::vector<uint8_t> &resultTlv);
ResultCode GetExecutorPublicKey(std::vector<uint8_t> &vPubKey);
} // namespace V1_0
} // namespace UserAuth
} // namespace HDI
} // namespace OHOS
#endif // SIGNATURE_OPERATION_H
