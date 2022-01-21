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

#ifndef HDI_BATTERY_V1_0_BATTERYCALLBACKSERVICE_H
#define HDI_BATTERY_V1_0_BATTERYCALLBACKSERVICE_H

#include <functional>
#include "battery_callback_stub.h"

namespace hdi {
namespace battery {
namespace v1_0 {
class BatteryCallbackService : public BatteryCallbackStub {
public:
    virtual ~BatteryCallbackService() {}
    using BatteryEventCallback = std::function<int32_t(const CallbackInfo& event)>;
    static int32_t RegisterBatteryEvent(const BatteryEventCallback& eventCb);
    int32_t Update(const CallbackInfo& event) override;
private:
    static BatteryEventCallback eventCb_;
};
} // v1_0
} // battery
} // hdi

#endif // HDI_BATTERY_V1_0_BATTERYCALLBACKSERVICE_H

