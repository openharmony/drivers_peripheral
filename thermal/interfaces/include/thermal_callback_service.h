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

#ifndef HDI_THERMAL_V1_0_THERMALCALLBACKSERVICE_H
#define HDI_THERMAL_V1_0_THERMALCALLBACKSERVICE_H

#include <functional>
#include "thermal_callback_stub.h"

namespace hdi {
namespace thermal {
namespace v1_0 {
class ThermalCallbackService : public ThermalCallbackStub {
public:
    virtual ~ThermalCallbackService() {}
    using ThermalEventCallback = std::function<int32_t(const HdfThermalCallbackInfo& event)>;
    static int32_t RegisterThermalEvent(const ThermalEventCallback &eventCb);
    int32_t OnThermalDataEvent(const HdfThermalCallbackInfo& event) override;
private:
    static ThermalEventCallback eventCb_;
};
} // v1_0
} // thermal
} // hdi

#endif // HDI_THERMAL_V1_0_THERMALCALLBACKSERVICE_H

