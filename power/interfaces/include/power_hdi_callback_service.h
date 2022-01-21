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

#ifndef HDI_POWER_V1_0_POWERHDICALLBACKSERVICE_H
#define HDI_POWER_V1_0_POWERHDICALLBACKSERVICE_H

#include "power_hdi_callback_stub.h"

namespace hdi {
namespace power {
namespace v1_0 {
class PowerHdiCallbackService : public PowerHdiCallbackStub {
public:
    virtual ~PowerHdiCallbackService() {}

    int32_t OnSuspend() override;

    int32_t OnWakeup() override;
};
} // v1_0
} // power
} // hdi

#endif // HDI_POWER_V1_0_POWERHDICALLBACKSERVICE_H

